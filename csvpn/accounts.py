# -*- coding: utf-8 -*-
#
# This file is part of csvpn, a vpn manager for CivilSphere project.
#
# :authors: Israel Leiva <israel.leiva@usach.cl>
#           see also AUTHORS file
#
# :copyright: (c) 2018, all entities within the AUTHORS file
#
# :license: This is Free Software. See LICENSE for license information.

import os

from ipaddress import ip_network
from datetime import datetime, timedelta
from ConfigParser import ConfigParser

from twisted.python.filepath import FilePath
from twisted.internet import defer, protocol, utils
from twisted.internet.fdesc import writeToFD, setNonBlocking

# local imports
from utils import log, Base, IPError, ExecError


class Accounts(Base):
    """ Accounts. """
    def __init__(self, config_file):
        """ """
        config = ConfigParser()
        config.read(config_file)

        log.debug("ACCOUNTS:: Loading configuration values.")
        self.path = {}
        self.path['client-configs-ips'] = config.get('path', 'client-configs-ips')
        self.path['client-configs'] = config.get('path', 'client-configs')
        self.path['openvpn-ca'] = config.get('path', 'openvpn-ca')
        self.path['pcaps'] = config.get('path', 'pcaps')

        tcpdump_args = config.get('tcpdump', 'args')
        self.tcpdump_args = tcpdump_args.split(',')
        self.tcpdump_interface = config.get('tcpdump', 'interface')

        self.expiration_days = int(config.get('general', 'expiration_days'))
        self.interval = float(config.get('general', 'interval'))

        self.netrange = config.get('network', 'range')
        self.netmask = config.get('network', 'mask')
        subnet_str = "{}/{}".format(self.netrange, self.netmask)
        self.subnet = ip_network(unicode(subnet_str))
        server_ip = config.get('network', 'server_ip')
        self.allocated_ips = []
        self.allocated_ips.append(server_ip)

        self.capture_processes = {}

        Base.__init__(self)

    def _generate_ip(self):
        """ """
        found = False
        for ip_addr in self.subnet.hosts():
            ip_addr_str = str(ip_addr)
            log.debug("ACCOUNTS:: Checking if {} is free.".format(ip_addr_str))

            if ip_addr_str not in self.allocated_ips:
                log.debug("ACCOUNTS:: Found {} available".format(ip_addr_str))
                self.allocated_ips.append(ip_addr_str)
                found = True
                break

        if found:
            return ip_addr_str
        else:
            log.debug("ACCOUNTS:: Could not find a free IP address!")
            raise IPError("IP error")

    def _create_key(self, username):
        """ Create a new account key. """
        log.debug("ACCOUNTS:: Creating key for {}.".format(username))

        return utils.getProcessOutput(
            "./build-key",
            args=[username],
            env=os.environ,
            path=self.path['openvpn-ca']
        ).addCallback(self.cb_cmd).addErrback(self.eb_cmd)

    def _create_profile(self, username, ip_addr):
        """ Create a new OpenVPN profile. """
        log.debug("ACCOUNTS:: Creating profile for {}.".format(username))

        return utils.getProcessOutput(
            "./make-config.sh",
            # args=[username, ip_addr],
            args=[username],
            env=os.environ,
            path=self.path['client-configs']
        ).addCallback(self.cb_cmd).addErrback(self.eb_cmd)

    def _create_ipfile(self, username, ip_addr):
        """ """
        log.info("ACCOUNTS:: Creating IP file for client.")

        ip_filename = os.path.join(self.path['client-configs-ips'], username)
        log.debug("ACCOUNTS: Writing {} with {}.".format(ip_filename, ip_addr))

        data = "ifconfig-push {} {}\n".format(ip_addr, self.netmask)

        with open(ip_filename, 'w+') as f:
            fd = f.fileno()
            setNonBlocking(fd)
            writeToFD(fd, data)

    def _start_traffic_capture(self, username, ip_addr):
        """ Start capturing traffic. """
        log.debug(
            "ACCOUNTS:: Starting capture traffic for {} with IP {}.".format(
                username, ip_addr
            )
        )

        now_str = datetime.now().strftime("%Y-%m-%d")
        pcap_file = "{}_{}_{}.pcap".format(username, ip_addr, now_str)
        pcap_file = os.path.join(self.path['pcaps'], pcap_file)

        cap_args = self.tcpdump_args
        cap_args.append("-i")
        cap_args.append(self.tcpdump_interface)
        cap_args.append("-w")
        cap_args.append(pcap_file)

        print "args: "
        from pprint import pprint
        pprint(cap_args)

        pp = protocol.ProcessProtocol()
        from twisted.internet import reactor
        p = reactor.spawnProcess(
                pp, "/usr/sbin/tcpdump", 
                args=cap_args,
            )

        k = "{}-{}".format(username, ip_addr)
        self.capture_processes[k] = (pp, p.pid)

    def _stop_traffic_capture(self, username, ip_addr):
        """ """
        log.info("ACCOUNTS:: Stopping traffic capture")
        k = "{}-{}".format(username, ip_addr)
        p = self.capture_processes[k]
        log.debug("ACCOUNTS:: Killing process with PID {}".format(str(p[1])))
        p[0].transport.signalProcess("KILL")

    def _revoke_user(self, username):
        """ Revoke OpenVPN user. """
        log.debug("ACCOUNTS:: Revoking user {}.".format(username))

        return utils.getProcessOutput(
            './revoke-full',
            args=[username],
            env=os.environ,
            path=self.path['openvpn-ca']
        ).addCallback(self.cb_cmd).addErrback(self.eb_cmd)

    def _delete_ipfile(self, username):
        """ """
        log.info("ACCOUNTS:: Deleting IP file for {}.".format(username))

        filename = os.path.join(self.path['client-configs-ips'], username)
        log.debug("ACCOUNTS:: Moving file to {}.revoked.".format(filename))

        fp = FilePath(filename)
        revoked_fp = FilePath("{}.revoked".format(filename))
        fp.moveTo(revoked_fp)


    def _get_expired_requests(self):
        """ Get requests with . """
        query = 'select * from requests where status=? and expiration_date<?'

        now_str = datetime.now().strftime("%Y-%m-%d")
        log.debug("ACCOUNTS:: Asking for active accounts that have expired.")

        return self.dbpool.runQuery(query, ("ACTIVE", now_str)).\
            addCallback(self.cb_db_query).\
            addErrback(self.eb_db_query)

    def _set_ip_expiration_date(self, email_addr, ip_addr):
        """ """
        start_date_str = datetime.now().strftime("%Y-%m-%d")
        start_date = datetime.strptime(start_date_str, "%Y-%m-%d")
        exp_date = start_date + timedelta(days=self.expiration_days)
        exp_date_str = exp_date.strftime("%Y-%m-%d")

        query = "update requests set ip_addr=?, start_date=?, \
        expiration_date=? where email_addr=?"

        log.debug(
            "ACCOUNTS:: Setting IP, start and expiration date to {}, {}, {}.\
            ".format(ip_addr, start_date_str, exp_date_str)
        )

        return self.dbpool.runQuery(
            query,
            (ip_addr, start_date_str, exp_date_str, email_addr)
        ).addCallback(self.cb_db_query).addErrback(self.eb_db_query)

    @defer.inlineCallbacks
    def _get_new(self):
        """ """
        new_requests = yield self._get_requests("ONHOLD")

        if new_requests:
            log.info("ACCOUNTS:: Got new requests for accounts.")
            for request in new_requests:
                email_addr = request[0]
                username, domain = email_addr.split('@')
                try:
                    # set to IN_PROCESS
                    log.info(
                        "ACCOUNTS:: Processing request for {}".format(
                            email_addr
                        )
                    )
                    yield self._update_status(email_addr, "IN_PROCESS")
                    # key -> EXEC_ERROR
                    yield self._create_key(username)
                    # assign ip -> NO_IP_AVAILABLE
                    ip = yield self._generate_ip()
                    # create profile (ip, user) -> EXEC_ERROR
                    yield self._create_profile(username, ip)
                    # create file for static ip
                    yield self._create_ipfile(username, ip)
                    # run tcpdump -> CAP_ERROR
                    yield self._start_traffic_capture(username, ip)
                    # calculate exp date
                    yield self._set_ip_expiration_date(email_addr, ip)
                    # set to ACTIVE_READY - profile ready to be sent
                    yield self._update_status(email_addr, "PROFILE_PENDING")
                    log.info(
                        "ACCOUNTS:: Account ready for {} with IP {}. Profile"
                        ".ovpn on queue to be sent to {}.".format(
                            username, ip, email_addr
                        )
                    )
                except IPError as error:
                    log.info(
                        "ACCOUNTS:: Error generating IP address: {}.".format(
                            error
                        )
                    )
                    yield self._update_status(email_addr, "NO_IP_AVAILABLE")
                except ExecError as error:
                    log.info(
                        "ACCOUNTS:: Error executing system command.".format(
                            error
                        )
                    )
                    yield self._update_status(email_addr, "EXEC_ERROR")
        else:
            log.info("ACCOUNTS:: No requests - Keep waiting.")

        expired = yield self._get_expired_requests()
        if expired:
            log.info("ACCOUNTS:: Got expired accounts.")
            for request in expired:
                email_addr, ip = request[0], request[5]
                username, domain = email_addr.split('@')
                # stop traffic capture
                yield self._stop_traffic_capture(username, ip)
                yield self._revoke_user(username)
                yield self._delete_ipfile(username)
                # update status
                yield self._update_status(email_addr, "EXPIRED")
                log.info(
                    "ACCOUNTS:: Account {} revoked and set to expired.".format(
                        username
                    )
                )
        else:
            log.info("ACCOUNTS:: No expired accounts - Keep waiting.")
