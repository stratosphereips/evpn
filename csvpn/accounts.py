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
    """
    Accounts class. Used for:

        - Create VPN accounts: generate internal IP, create client key,
          create client profile, start traffic capture for client-ip.

        - Deactivate VPN accounts: revoke client, stop traffic capture.
    """
    def __init__(self, config_file):
        """
        Constructor. It loads configuration values and call the
        Base constructor.

        :param config_file (str): path for configuration file.
        """
        config = ConfigParser()
        config.read(config_file)

        log.debug("ACCOUNTS:: Loading configuration values.")

        # Common paths used in the creation/revocation of accounts.
        self.path = {}
        self.path['client-configs'] = config.get('path', 'client-configs')
        self.path['client-ips'] = config.get('path', 'client-ips')
        self.path['openvpn-ca'] = config.get('path', 'openvpn-ca')
        self.path['pcaps'] = config.get('path', 'pcaps')

        # More flexible if we change the environment or add capabilities for
        # the traffic capture
        self.tcpdump_bin = config.get('tcpdump', 'bin')
        self.tcpdump_args = config.get('tcpdump', 'args')
        self.tcpdump_args = self.tcpdump_args.split(',')
        self.tcpdump_interface = config.get('tcpdump', 'interface')

        # Network info to allocate ip addresses for new accounts
        self.netrange = config.get('network', 'range')
        self.netmask = config.get('network', 'mask')
        subnet_str = "{}/{}".format(self.netrange, self.netmask)
        self.subnet = ip_network(unicode(subnet_str))
        server_ip = config.get('network', 'server_ip')
        self.allocated_ips = []
        # Keep allocated ips in memory
        self.allocated_ips.append(server_ip)

        # Period of life for an account (in days)
        self.expiration_days = int(config.get('general', 'expiration_days'))
        # Time interval for the service loop (in seconds)
        self.interval = float(config.get('general', 'interval'))

        # Keep process information of running tcpdumps. It makes it easier to
        # kill traffic captures when an account expires
        self.capture_processes = {}
        # TODO: note that if csvpn crashes all running tcpdumps will die
        # We should look for active accounts and start capturing traffic again

        Base.__init__(self)

    def _generate_ip(self):
        """
        Generate an internal IP for a new account.

        :return: string with the IP address.
        :raises: IPError if there is no IP available for the new account.
        """
        found = False
        for ip_addr in self.subnet.hosts():
            ip_addr_str = str(ip_addr)
            log.debug("ACCOUNTS:: Checking if {} is free.".format(ip_addr_str))

            # TODO: if csvpn crashes it should look for active accounts, get
            # their allocated ips and load them into memory
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
        """
        Create VPN key for new account.

        :param username (string): new account username. Note: we should avoid
        duplication of usernames.

        :return: deferred whose callback/errback will log command execution
        details.
        """
        log.debug("ACCOUNTS:: Creating key for {}.".format(username))

        # We avoid doing `source vars` by adding it to the build-key script
        # itself. It should also be possible to add this vars using the env
        # paratemer
        return utils.getProcessOutput(
            "./build-key",
            args=[username],
            env=os.environ,
            path=self.path['openvpn-ca']
        ).addCallback(self.cb_cmd).addErrback(self.eb_cmd)

    def _create_profile(self, username):
        """
        Create a new OpenVPN profile.

        :param username (str): username for the new account.

        :return: deferred whose callback/errback will log command execution
        details.
        """
        log.debug("ACCOUNTS:: Creating profile for {}.".format(username))

        return utils.getProcessOutput(
            "./make-config.sh",
            args=[username],
            env=os.environ,
            path=self.path['client-configs']
        ).addCallback(self.cb_cmd).addErrback(self.eb_cmd)

    def _create_ipfile(self, username, ip_addr):
        """
        Create configuration file for static IP allocation.

        :param username (str): account username
        :param ip_addr (str): IP address allocated for the account.
        """
        log.info("ACCOUNTS:: Creating IP file for client.")

        # OpenVPN will look for files inside this directory. Its filename must
        # be the same as the username
        ip_filename = os.path.join(self.path['client-ips'], username)
        log.debug("ACCOUNTS: Creating {} with {}.".format(
            ip_filename, ip_addr
            )
        )

        data = "ifconfig-push {} {}\n".format(ip_addr, self.netmask)
        with open(ip_filename, 'w+') as f:
            fd = f.fileno()
            setNonBlocking(fd)
            writeToFD(fd, data)

    def _start_traffic_capture(self, username, ip_addr):
        """
        Start traffic capture.

        :param username (str): account username
        :param ip_addr (str): IP address allocated for the account.

        :return: deferred whose callback/errback will log command execution
        details.
        """
        log.debug(
            "ACCOUNTS:: Starting capture traffic for {} with IP {}.".format(
                username, ip_addr
            )
        )

        now_str = datetime.now().strftime("%Y-%m-%d")
        pcap_file = "{}_{}_{}.pcap".format(username, ip_addr, now_str)
        pcap_file = os.path.join(self.path['pcaps'], pcap_file)

        # Always add -i (interface), -w (output file), and host (filter) args
        cap_args = self.tcpdump_args
        cap_args.append("-i")
        cap_args.append(self.tcpdump_interface)
        cap_args.append("-w")
        cap_args.append(pcap_file)
        cap_args.append("host")
        cap_args.append(ip_addr)

        # This process will not appear in `ps`, and it will die together with
        # csvpn if it is not killed before
        pp = protocol.ProcessProtocol()
        from twisted.internet import reactor
        p = reactor.spawnProcess(pp, self.tcpdump_bin, args=cap_args)

        # Keep process info in memory to kill it after
        k = "{}-{}".format(username, ip_addr)
        self.capture_processes[k] = (pp, p.pid)

    def _stop_traffic_capture(self, username, ip_addr):
        """
        Stop traffic capture.

        :param username (str): account username
        :param ip_addr (str): IP address allocated for the account.

        :return: deferred whose callback/errback will log command execution
        details.
        """
        log.info("ACCOUNTS:: Stopping traffic capture")
        k = "{}-{}".format(username, ip_addr)
        p = self.capture_processes[k]

        log.debug("ACCOUNTS:: Killing process with PID {}".format(str(p[1])))
        p[0].transport.signalProcess("KILL")

    def _revoke_user(self, username):
        """ Revoke OpenVPN user (certificate and key). """
        log.debug("ACCOUNTS:: Revoking user {}.".format(username))

        # Same as build-key, we avoid using `source vars` by adding the vars
        # directly to the revoke-full script
        return utils.getProcessOutput(
            './revoke-full',
            args=[username],
            env=os.environ,
            path=self.path['openvpn-ca']
        ).addCallback(self.cb_cmd).addErrback(self.eb_cmd)

    def _delete_ipfile(self, username):
        """
        Create configuration file for static IP allocation.

        :param username (str): account username.
        """
        log.info("ACCOUNTS:: Deleting IP file for {}.".format(username))

        filename = os.path.join(self.path['client-ips'], username)
        log.debug("ACCOUNTS:: Moving file to {}.revoked.".format(filename))

        # do not delete it, just rename it to `revoked`
        fp = FilePath(filename)
        revoked_fp = FilePath("{}.revoked".format(filename))
        fp.moveTo(revoked_fp)

    def _get_expired_requests(self):
        """
        Get requests with status ACTIVE which expiration date is before than
        current date.

        :return: deferred whose callback/errback will log database query
        execution details.
        """
        query = 'select * from requests where status=? and expiration_date<?'

        now_str = datetime.now().strftime("%Y-%m-%d")
        log.debug("ACCOUNTS:: Asking for active accounts that have expired.")

        return self.dbpool.runQuery(query, ("ACTIVE", now_str)).\
            addCallback(self.cb_db_query).\
            addErrback(self.eb_db_query)

    def _set_ip_expiration_date(self, email_addr, ip_addr):
        """
        Set allocated IP and expiration for an account.

        :param email_addr (str): email address (identifier) of the account.
        :param ip_addr (str): IP address allocated for the account.

        :return: deferred whose callback/errback will log database query
        execution details.
        """
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
        """
        Get new requests to process. This will define the `main loop` of
        the Accounts service.
        """

        # check requests to create new accounts
        new_requests = yield self._get_requests("ONHOLD")
        if new_requests:
            log.info("ACCOUNTS:: Got new requests for accounts.")
            for request in new_requests:
                email_addr = request[0]
                username, domain = email_addr.split('@')
                try:
                    log.info(
                        "ACCOUNTS:: Processing request for {}".format(
                            email_addr
                        )
                    )
                    yield self._update_status(email_addr, "IN_PROCESS")
                    # ExecError in case of failure
                    yield self._create_key(username)
                    # IPError in case of failure
                    ip = yield self._generate_ip()
                    # ExecError in case of failure
                    yield self._create_profile(username)
                    yield self._create_ipfile(username, ip)
                    # ExecError in case of failure
                    yield self._start_traffic_capture(username, ip)
                    yield self._set_ip_expiration_date(email_addr, ip)
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

        # Check for expired accounts
        expired = yield self._get_expired_requests()
        if expired:
            log.info("ACCOUNTS:: Got expired accounts.")
            for request in expired:
                try:
                    email_addr, ip = request[0], request[5]
                    username, domain = email_addr.split('@')
                    yield self._stop_traffic_capture(username, ip)
                    # ExecError in case of failure
                    yield self._revoke_user(username)
                    yield self._delete_ipfile(username)
                    yield self._update_status(email_addr, "EXPIRED")
                    log.info(
                        "ACCOUNTS:: Account {} revoked and expired.".format(
                            username
                        )
                    )
                except ExecError as error:
                    log.info(
                        "ACCOUNTS:: Error executing system command.".format(
                            error
                        )
                    )
                    yield self._update_status(email_addr, "EXEC_ERROR")
        else:
            log.info("ACCOUNTS:: No expired accounts - Keep waiting.")
