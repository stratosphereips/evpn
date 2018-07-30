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

from urllib import urlencode
from ConfigParser import ConfigParser

from twisted.internet import defer
from twisted.web.client import getPage

# local imports
from utils import log


class SlackBot(object):
    """
    Bot class. Used for:

        - Post messages to Slack channels.
    """
    def __init__(self, config_file):
        """
        Constructor. Loads configuration values.

        :param config_file (str): path for configuration file.
        """
        config = ConfigParser()
        config.read(config_file)

        log.debug("SLACKBOT:: Loading configuration values.")

        # Credentials
        self.token = config.get('credentials', 'token')
        self.botname = config.get('credentials', 'botname')

        # General
        # Use this when testing or staging
        self.silent = config.get('general', 'silent')

    def post(self, text, channel):
        """
        Post message to a Slack channel.

        :param text (str): the message to be posted.
        :param channel (str): the destination channel.
        """
        log.debug("SLACKBOT:: Sending message to {}".format(channel))
        # Useful for testing and staging
        if self.silent == "true":
            d = defer.Deferred()
            d.addBoth(lambda: None)
            return d
        else:
            return getPage(
                "https://slack.com/api/chat.postMessage",
                method='POST',
                postdata=urlencode({
                    "token": self.token,
                    "channel": channel,
                    "username": self.botname,
                    "text": text
                }),
                headers={
                    "Content-Type": "application/x-www-form-urlencoded",
                    "charset": "utf-8"
                }
            ).addCallback(self.cb_get_page).addErrback(self.eb_get_page)

    def cb_get_page(self, output):
        """
        Callback with the output of the web request.
        """
        # don't log output
        log.debug("SLACKBOT:: Web request succesful")

    def eb_get_page(self, error):
        """
        Errback if we don't/can't receive make the web request.
        """
        log.debug("SLACKBOT:: Web request failed: {}".format(error))
