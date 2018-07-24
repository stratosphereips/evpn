#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# This file is part of csvpn, a VPN manager for CivilSphere project.
#
# :authors: Israel Leiva <israel.leiva@usach.cl>
#           see also AUTHORS file
#
# :copyright: (c) 2018, all entities within the AUTHORS file
#
# :license: This is Free Software. See LICENSE for license information.

from twisted.application import service

import sys
sys.path.insert(0, '.')

# local imports
from csvpn.smtp import Messages
from csvpn.imap import Fetchmail
from csvpn.slack import SlackBot
from csvpn.accounts import Accounts
from csvpn.utils import BaseService, GreetService, log

log.info("Loading config files.")
fetchmail = Fetchmail('imap.cfg')
accounts = Accounts('accounts.cfg')
messages = Messages('smtp.cfg')
slackbot = SlackBot('slackbot.cfg')

log.info("Starting services.")

# Service for fetching new emails from VPN mail account
fetchmail_service = BaseService(
    "fetchmail", fetchmail.get_interval(), fetchmail
)

# Service for creating and revoking VPN accounts
accounts_service = BaseService(
    "accounts", accounts.get_interval(), accounts
)

# Service for sending emails
messages_service = BaseService(
    "messages", messages.get_interval(), messages
)

# Greeter service for notify on boot and shutdown
greeter_service = GreetService(
	"greeter", 100000, slackbot, "civilsphere"
)

# The heart of the csvpn manager
csvpn = service.MultiService()
csvpn.addService(fetchmail_service)
csvpn.addService(accounts_service)
csvpn.addService(messages_service)
csvpn.addService(greeter_service)

application = service.Application("csvpn")
csvpn.setServiceParent(application)
