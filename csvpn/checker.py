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

from ConfigParser import ConfigParser

from twisted.python.filepath import FilePath
from twisted.internet import defer

# local imports
from utils import log, Base
from slack import SlackBot


class FileChecker(Base):
    """
    FileChecker class. Used for:

        - Check size of traffic captures.

        - Send alert when a limit has been reached.
    """
    def __init__(self, config_file):
        """
        Constructor. It loads configuration values and call the
        Base constructor.

        :param config_file (str): path for configuration file.
        """
        config = ConfigParser()
        config.read(config_file)

        log.debug("FILECHECKER:: Loading configuration values.")

        # Common paths used in the creation/revocation of accounts.
        self.pcaps_path = config.get('path', 'pcaps')

        # Slack notifications
        slack_config = config.get('slack', 'config')
        self.slack_channel = config.get('slack', 'channel')
        self.slackbot = SlackBot(slack_config)

        # Time interval for the service loop (in seconds)
        self.interval = float(config.get('general', 'interval'))

        # Size limit in bytes
        self.size_limit = config.get('general', 'size_limit')
        # Multiple limits
        self.size_limit = self.size_limit.split(',')

        # Store which user-ip has reached the list of size limits
        self.reached_limits = {}

        Base.__init__(self)


    @defer.inlineCallbacks
    def _get_new(self):
        """
        Get new requests to process. This will define the `main loop` of
        the FileChecker service.
        """

        # Check ACTIVE accounts to get files with running traffic captures
        active_requests = yield self._get_requests("ACTIVE")
        if active_requests:
            log.info("FILECHECKER:: Checking pcap files of ACTIVE accounts.")
            for request in active_requests:
                username = request[0]
                ip_addr = request[6]

                # Create path
                k = "{}_{}".format(username, ip_addr)
                pcap_file = "{}.pcap".format(k)
                pcap_file = os.path.join(self.pcaps_path, pcap_file)
                log.debug("FILECHECKER:: Checking {}".format(pcap_file))

                # First limit should be zero
                if self.reached_limits.get(k) is None:
                    self.reached_limits[k] = 0

                try:
                    fp = FilePath(pcap_file)
                    fsize = fp.getsize()
                    # Check each size limit only once
                    if self.reached_limits[k]+1 < len(self.size_limit):
                        if fsize > int(self.size_limit[self.reached_limits[k]+1]):
                            text = "File {} has reached the limit of "\
                                   "{} bytes!".format(
                                pcap_file,
                                self.size_limit[self.reached_limits[k]+1]
                            )

                            log.info("FILECHECKER:: {}".format(text))
                            yield self.slackbot.post(text, self.slack_channel)

                            self.reached_limits[k] = self.reached_limits[k]+1
                    else:
                        log.debug(
                                "FILECHECKER:: File {} has reached the last"
                                " size limit of {} bytes!".format(
                                    pcap_file,
                                    self.size_limit[self.reached_limits[k]]
                                )
                            )

                except Exception as e:
                    log.debug("FILECHECKER:: Could'nt get size: {}".format(e))

        else:
            log.debug("FILECHECKER:: No ACTIVE accounts - Keep waiting.")