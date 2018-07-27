# -*- coding: utf-8 -*-
#
# This file is part of evpn, the Emergency VPN manager for CivilSphere project
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
from slack import SlackBot
from utils import log, Base, AddressError, IPError, ExecError


# Keep process information of running tcpdumps. It makes it easier to
# kill traffic captures when an account expires
capture_processes = {}


class CustomProcessProtocol(protocol.ProcessProtocol):
    """
    Custom class to handle Process Protocol behaviour. Right now mostly for
    logging purposes.
    """
    def __init__(self, username, ip_addr):
        self.username = username
        self.ip_addr = ip_addr

    def set_process(self, p):
        self.process = p

    def get_process(self):
        return self.process

    def connectionMade(self):
        log.debug("PROCESS:: process started")

    def outConnectionLost(self):
        log.debug("PROCESS:: Connection lost")

    def processExited(self, status):
        log.debug("PROCESS:: Process exited: {}".format(status))
        k = "{}-{}".format(self.username, self.ip_addr)
        capture_processes[k] = None

    def processEnded(self, status):
        log.debug("PROCESS:: Process ended: {}".format(status))
        k = "{}-{}".format(self.username, self.ip_addr)
        capture_processes[k] = None


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

        # Slack notifications
        slack_config = config.get('slack', 'config')
        self.slack_channel = config.get('slack', 'channel')
        self.slackbot = SlackBot(slack_config)

        # tcpdump binary should be first argument, and -i interface must be
        # present
        self.tcpdump_args = config.get('tcpdump', 'args')
        self.tcpdump_args = self.tcpdump_args.split(',')

        # Network info to allocate ip addresses for new accounts
        self.netrange = config.get('network', 'range')
        self.netmask = config.get('network', 'mask')
        subnet_str = "{}/{}".format(self.netrange, self.netmask)
        self.subnet = ip_network(unicode(subnet_str))
        # Default to OpenVPN IP, but can include others also
        self.reserved_ips = config.get('network', 'reserved_ips')
        # Keep allocated ips in memory
        self.allocated_ips = self.reserved_ips.split(',')

        # Period of life for an account (in days)
        self.expiration_days = int(config.get('general', 'expiration_days'))
        # Time interval for the service loop (in seconds)
        self.interval = float(config.get('general', 'interval'))
        # Limit of account requests per email address
        self.max_account_requests = int(config.get('general', 
                                    'max_account_requests'))

        # TODO: note that if csvpn crashes all running tcpdumps will die
        # We should look for active accounts and start capturing traffic again
        from twisted.internet import reactor
        self.reactor = reactor

        Base.__init__(self)
        

    def _generate_ip(self):
        """
        Generate an internal IP for a new account.

        :return: IPv4Address object.
        :raises: IPError if there is no IP available for the new account.
        """
        found = False
        for ip_addr in self.subnet.hosts():
            ip_addr_str = str(ip_addr)
            ip_addr_list = ip_addr_str.split('.')

            # OpenVPN uses 4k+1 and 4k+2 for static IP allocation
            if ((int(ip_addr_list[3])-1)%4 == 0):
                log.debug("ACCOUNTS:: Checking if {} is free.".format(
                        ip_addr_str
                    )
                )

                # TODO: if csvpn crashes it should look for active accounts,
                # get their allocated ips and load them into memory
                if ip_addr_str not in self.allocated_ips:
                    log.debug("ACCOUNTS:: Found {} available".format(
                            ip_addr_str
                        )
                    )
                    self.allocated_ips.append(ip_addr_str)
                    found = True
                    break

        if found:
            return ip_addr
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
        :param ip_addr (IPv4Address): IP address allocated for the account.
        """
        log.info("ACCOUNTS:: Creating IP file for client.")

        # OpenVPN will look for files inside this directory. Its filename must
        # be the same as the username
        ip_filename = os.path.join(self.path['client-ips'], username)
        log.debug("ACCOUNTS: Creating {} with {}.".format(
                ip_filename, str(ip_addr)
            )
        )

        # From `Configuring client-specific rules and access policies` in
        # https://openvpn.net/index.php/open-source/documentation/howto.html
        virtual_client = ip_addr
        server_endpoint = ip_addr + 1

        log.debug("ACCOUNTS:: ifconfig-push {} {}".format(
                virtual_client, server_endpoint
            )
        )
        data = "ifconfig-push {} {}\n".format(
            str(virtual_client), str(server_endpoint)
        )
        with open(ip_filename, 'w+') as f:
            fd = f.fileno()
            setNonBlocking(fd)
            writeToFD(fd, data)

        fp = FilePath(ip_filename)
        fp.chmod(0644)

    def _backup_pcap(self, username, ip_addr):
        """
        Backup existing pcap file. Used when restarting traffic capture for
        ACTIVE accounts.

        :param username (str): account username
        :param ip_addr (IPv4Address): IP address allocated for the account.

        """
        log.debug(
            "ACCOUNTS:: Backing up pcap for {} with IP {}.".format(
                username, str(ip_addr)
            )
        )

        day_month_str = datetime.now().strftime("%m%d")
        cur_pcap_file = "{}_{}.pcap".format(username, str(ip_addr))
        new_pcap_file = "{}_{}-{}.pcap".format(
            username, str(ip_addr), day_month_str
        )
        cur_pcap_file = os.path.join(self.path['pcaps'], cur_pcap_file)
        new_pcap_file = os.path.join(self.path['pcaps'], new_pcap_file)
        log.debug("ACCOUNTS:: Current pcap file {}".format(cur_pcap_file))
        log.debug("ACCOUNTS:: New pcap file {}".format(new_pcap_file))

        fp = FilePath(cur_pcap_file)
        backup_fp = FilePath(new_pcap_file)
        fp.moveTo(backup_fp)

    def _start_traffic_capture(self, username, ip_addr):
        """
        Start traffic capture.

        :param username (str): account username
        :param ip_addr (IPv4Address): IP address allocated for the account.

        :return: deferred whose callback/errback will log command execution
        details.
        """
        log.debug(
            "ACCOUNTS:: Starting capture traffic for {} with IP {}.".format(
                username, str(ip_addr)
            )
        )

        pcap_file = "{}_{}.pcap".format(username, str(ip_addr))
        pcap_file = os.path.join(self.path['pcaps'], pcap_file)
        log.debug("ACCOUNTS:: pcap file {}".format(pcap_file))

        # Always add -w (output file), and host (filter) args
        # Network interface should be set on config file
        cap_args = []
        cap_args.extend(self.tcpdump_args)
        cap_args.extend(["-w", pcap_file, "host", str(ip_addr)])
        
        # This process will not appear in `ps`, and it will die together with
        # csvpn if it is not killed before
        pp = CustomProcessProtocol(username, str(ip_addr))
        p = self.reactor.spawnProcess(
            pp, cap_args[0], args=cap_args, env=os.environ,
        )
        pp.set_process(p)

        # Keep process info in memory to kill it after
        k = "{}-{}".format(username, str(ip_addr))
        capture_processes[k] = pp

    def _stop_traffic_capture(self, username, ip_addr):
        """
        Stop traffic capture.

        :param username (str): account username
        :param ip_addr (IPv4Address): IP address allocated for the account.

        :return: deferred whose callback/errback will log command execution
        details.
        """
        log.info("ACCOUNTS:: Stopping traffic capture")
        k = "{}-{}".format(username, str(ip_addr))
        pp = capture_processes[k]
        p = pp.get_process()

        log.debug("ACCOUNTS:: Killing process with PID {}".format(str(p.pid)))
        pp.transport.signalProcess("KILL")

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

    def _set_ip_expiration_date(self, username, ip_addr):
        """
        Set allocated IP and expiration for an account.

        :param username (str): username (identifier) of the account.
        :param ip_addr (IPv4Address): IP address allocated for the account.

        :return: deferred whose callback/errback will log database query
        execution details.
        """
        start_date_str = datetime.now().strftime("%Y-%m-%d")
        start_date = datetime.strptime(start_date_str, "%Y-%m-%d")
        exp_date = start_date + timedelta(days=self.expiration_days)
        exp_date_str = exp_date.strftime("%Y-%m-%d")

        query = "update requests set ip_addr=?, start_date=?, \
        expiration_date=? where username=?"

        log.debug(
            "ACCOUNTS:: Setting IP, start and expiration date to {}, {}, {}.\
            ".format(str(ip_addr), start_date_str, exp_date_str)
        )

        return self.dbpool.runQuery(
            query,
            (str(ip_addr), start_date_str, exp_date_str, username)
        ).addCallback(self.cb_db_query).addErrback(self.eb_db_query)


    @defer.inlineCallbacks
    def _get_new(self):
        """
        Get new requests to process. This will define the `main loop` of
        the Accounts service.
        """

        # check for stopped captures that need to be loaded (in case tcpdump
        # died unexpectedly)
        log.info("ACCOUNTS: Checking ACTIVE accounts with no captures.")
        active_accounts = yield self._get_requests("ACTIVE")

        if active_accounts:
            log.debug("ACCOUNTS:: ACTIVE accounts found.")
            for account in active_accounts:
                username = account[0]
                ip_addr = account[6]
                yield self._update_status(username, "ACTIVE_IN_PROCESS")
                k = "{}-{}".format(username, ip_addr)
                if capture_processes.get(k) is None:
                    try:
                        # tcpdump -w truncates the pcap file, so backup first
                        yield self._backup_pcap(username, ip_addr)
                        # ExecError in case of failure
                        yield self._start_traffic_capture(username, ip_addr)
                        self.allocated_ips.append(ip_addr)

                        # Notify
                        yield self.slackbot.post(
                            "Restarting tcpdump for {} with IP {}".format(
                                username, ip_addr
                            ),
                            self.slack_channel
                        )
                    except ExecError as error:
                        log.debug(
                            "ACCOUNTS:: Error executing command.".format(
                                error
                            )
                        )
                        yield self._update_status(username, "EXEC_ERROR")
                    yield self._update_status(username, "ACTIVE")
                else:
                    log.debug("ACCOUNTS:: No inactive captures.")
        else:
            log.debug("ACCOUNTS:: No ACTIVE accounts found.")

        # check requests to create new accounts
        new_requests = yield self._get_requests("ONHOLD")
        if new_requests:
            log.info("ACCOUNTS:: Got new requests for accounts.")
            for request in new_requests:
                username = request[0]
                email_addr = request[1]
                try:
                    log.info(
                        "ACCOUNTS:: Processing request for {}".format(
                            username
                        )
                    )
                    num_requests = yield self._get_num_requests(
                        email_addr, ["IN_PROCESS", "ACTIVE",
                        "PROFILE_PENDING", "EXPIRED", "EXEC_ERROR"]
                    )
                    if num_requests[0][0] > self.max_account_requests:
                        raise AddressError("{}".format(
                                str(num_requests[0][0])
                            )
                        )

                    yield self._update_status(username, "IN_PROCESS")
                    # ExecError in case of failure
                    yield self._create_key(username)
                    # IPError in case of failure
                    ip_addr = yield self._generate_ip()
                    # ExecError in case of failure
                    yield self._create_profile(username)
                    yield self._create_ipfile(username, ip_addr)
                    # ExecError in case of failure
                    yield self._start_traffic_capture(username, ip_addr)
                    yield self._set_ip_expiration_date(username, ip_addr)
                    yield self._update_status(username, "PROFILE_PENDING")

                    msg = "New VPN account {} ready with IP {}. Profile "\
                          ".ovpn on queue to be sent via email.".format(
                        username, ip_addr
                    )
                    log.info("ACCOUNTS:: {}".format(msg))

                    # Notify
                    yield self.slackbot.post(
                        "{} tcpdump is running!".format(msg),
                        self.slack_channel
                    )

                except IPError as error:
                    log.info(
                        "ACCOUNTS:: Error generating IP address: {}.".format(
                            error
                        )
                    )
                    yield self._update_status(username, "NO_IP_AVAILABLE")
                except ExecError as error:
                    log.info(
                        "ACCOUNTS:: Error executing system command.".format(
                            error
                        )
                    )
                    yield self._update_status(username, "EXEC_ERROR")
                except AddressError as error:
                    log.info(
                        "ACCOUNTS:: Too many requests from {}: {}".format(
                            email_addr, error
                        )
                    )
                    # Delete it to avoid database flooding
                    yield self._delete_request(username)
        else:
            log.info("ACCOUNTS:: No requests - Keep waiting.")

        # Check for expired accounts
        expired = yield self._get_expired_requests()
        if expired:
            log.info("ACCOUNTS:: Got expired accounts.")
            for request in expired:
                try:
                    username, ip = request[0], request[6]
                    yield self._update_status(username, "EXPIRED_IN_PROCESS")
                    yield self._stop_traffic_capture(username, ip)
                    # ExecError in case of failure
                    yield self._revoke_user(username)
                    yield self._delete_ipfile(username)
                    yield self._update_status(username, "EXPIRED_PENDING")

                    msg = "VPN account {} revoked and set to expired.".format(
                        username
                    )
                    log.info("ACCOUNTS:: {}".format(msg))

                    # Notify
                    yield self.slackbot.post(msg, self.slack_channel)

                except ExecError as error:
                    log.info(
                        "ACCOUNTS:: Error executing system command.".format(
                            error
                        )
                    )
                    yield self._update_status(username, "EXEC_ERROR")
        else:
            log.debug("ACCOUNTS:: No expired accounts - Keep waiting.")
