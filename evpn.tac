#!/usr/bin/env python
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

from twisted.application import service

import sys
sys.path.insert(0, '.')

# local imports
from evpn.smtp import Messages
from evpn.imap import Fetchmail
from evpn.slack import SlackBot
from evpn.accounts import Accounts
from evpn.utils import BaseService, GreetService, log

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
	"greeter", 100000, slackbot, "alerts"
)

# The heart of the csvpn manager
evpn = service.MultiService()
evpn.addService(fetchmail_service)
evpn.addService(accounts_service)
evpn.addService(messages_service)
evpn.addService(greeter_service)

application = service.Application("evpn")
evpn.setServiceParent(application)
