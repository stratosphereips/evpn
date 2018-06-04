#!/usr/bin/env python
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
import re
import sys
import email
import sqlite3
import logging

from datetime import datetime

from email import Encoders
from email.MIMEBase import MIMEBase
from email.mime.text import MIMEText
from email.MIMEMultipart import MIMEMultipart

from twisted.internet import utils
from twisted.internet.defer import inlineCallbacks, returnValue
from twisted.internet.protocol import ServerFactory, Protocol
from twisted.application import internet, service
from twisted.mail.smtp import sendmail
from twisted.enterprise import adbapi
from twisted.python import log

from pprint import pprint

"""csvpn - Civil Sphere VPN manager."""

###############################################################################
# SETTINGS
###############################################################################


DATABASE_FILE = 'csvpn.db'
OPENVPN_PATH = '/home/user/openvpn-ca'
CLIENT_CONFIGS_PATH = '/home/user/csvpn/client-configs/'
CLIENT_PROFILES_PATH = '/home/user/csvpn/client-configs/files/'

# for G services you must enable 2fa and then create an app password
SMTP_USER = 'email'
SMTP_PASS = 'pass'
SMTP_HOST = 'smtp.gmail.com'
SMTP_PORT = 587

# TODO: improve this
HELP_MSG_CONTENT = 'help content'
HELP_MSG_SUBJECT = 'help subject'

PROFILE_MSG_CONTENT = 'profile content'
PROFILE_MSG_SUBJECT = 'your profile'


class BaseService(internet.TimerService):
    """ Base service that provides connection to the csvpn database. """

    def __init__(self, name, step, callable, *args, **kwargs):
        """Constructor. Overwritten from parent class to add connection to
        the database.

        TODO: add parameters here
        """

        self.name = name
        # asynchronous connection to SQLite database.
        self.dbpool = adbapi.ConnectionPool(
            "sqlite3", DATABASE_FILE, check_same_thread=False
        )

        internet.TimerService.__init__(
            self, step, callable, self.dbpool, **kwargs
        )

    def startService(self):
        """Start the service. Overwritten from parent class to add extra 
        logging information."""

        log.msg("Starting {} service.".format(self.name))
        internet.TimerService.startService(self)
        log.msg("Service started.")

    def stopService(self):
        """Stop the service. Overwritten from parent class to close the
        connection to the database and to add extra logging information."""

        log.msg("Stopping {} service.".format(self.name))
        log.msg("Closing connection to SQLite database.")
        self.dbpool.close()
        log.msg("Connection closed.")
        internet.TimerService.stopService(self)
        log.msg("Service stopped.")



###############################################################################
# methods used by ``accounts`` handler
###############################################################################

# Callback and Errback for command execution. Not much to do here, except log
# what happened or went wrong.
def cmd_success(output):
    """ Callback for successfully executed commands. """
    log.msg("Command executed successfully: {}".format(output))

def cmd_failure(error):
    """ Errback for command execution. """
    log.msg("Command failed: {}".format(error))


# Creation of keys and profiles
def create_key(username):
    """ Create a new account key. """
    log.msg("Creating key for {}".format(username))

    # TODO: replicate source vars
    output = utils.getProcessOutput(
        './build-key',
        args=[username],
        env=os.environ,
        path=OPENVPN_PATH
    )
    output.addCallback(cmd_success).addErrback(cmd_failure)

def create_profile(username):
    """ Create a new OpenVPN profile. """
    log.msg("Creating profile for {}".format(username))

    output = utils.getProcessOutput(
        './make_config.sh', 
        args=[username],
        env=os.environ,
        path=CLIENT_CONFIGS_PATH
    )
    output.addCallback(cmd_success).addErrback(cmd_failure)    

def update_status(status):
    """ Update request status. """
    pass


###############################################################################
# methods used by ``pending_emails`` handler
###############################################################################

# Callback and Errback for emails sent ard not sent.
def email_sent(m):
    log.msg("Email sent.")

def email_not_sent(error):
    log.msg("Email not sent: {}".format(error))

def _send_help(email_addr):
    """ Send help to user.
    
    :param email_addr (string): email address to send help.
    """

    message = MIMEText(HELP_MSG_CONTENT)
    message['Subject'] = HELP_MSG_SUBJECT
    message['From'] = SMTP_USER
    message['To'] = email_addr

    log.msg("Sending help message")
    return sendmail(
        "smtp.gmail.com", SMTP_USER, email_addr, message,
        port=SMTP_PORT, username=SMTP_USER, password=SMTP_PASS,
        requireAuthentication=True, requireTransportSecurity=True
    ).addCallback(email_sent).addErrback(email_not_sent)
        

# the actual methods to send emails

def _send_profile(email_addr, username):
    """ Send OpenVPN profile to user.
    
    :param email_addr (string): email address to send the profile.
    """

    message = MIMEMultipart()
    message.set_charset("utf-8")
    message['Subject'] = PROFILE_MSG_SUBJECT
    message['From'] = SMTP_USER
    message['To'] = email_addr

    content = MIMEText(PROFILE_MSG_CONTENT, 'plain')
    message.attach(content)

    ovpn_file = "{}{}.ovpn".format(CLIENT_PROFILES_PATH, username)
    profile = MIMEBase('application', "octet-stream")
    profile.set_payload(
        open(ovpn_file, "rb").read()
    )
    Encoders.encode_base64(profile)
    profile.add_header(
        "Content-Disposition",
        "attachment; filename={}.ovpn".format(username)
    )
    message.attach(profile)

    log.msg("Sending OpenVPN profile")
    return sendmail(
        "smtp.gmail.com", SMTP_USER, email_addr, message,
        port=SMTP_PORT, username=SMTP_USER, password=SMTP_PASS,
        requireAuthentication=True, requireTransportSecurity=True
    ).addCallback(email_sent).addErrback(email_not_sent)



# inline callbacks for sending emails

@inlineCallbacks
def send_help(email_addr):
    """ Call the inlineCallback for sending help email.
    
    :param email_addr (string): email address to send help.
    """

    response = yield _send_help(email_addr)

@inlineCallbacks
def send_profile(email_addr, username):
    """ Call the inlineCallback for sending profile email.
    
    :param email_addr (string): email address to send the profile.
    """

    response = yield _send_profile(email_addr, username)



###############################################################################
# methods used by ``new_emails`` handler
###############################################################################






###############################################################################
# HANDLERS: methods that define what to do when a service gets new requests
###############################################################################

# accounts
def handle_new_accounts(results):
    """Success callback for runQuery (adbapi).
    
    :param results (dict): database entries.
    """

    if not results:
        log.msg("No requests found.")
        # nothing to do here
        pass

    for request in results:
        log.msg("Request for new account found.")
        if request[1] == 'help':
            log.msg("Handling help request")
            # first element is the email address
            send_help(request[0])
        elif request[1] == 'account':
            username, domain = request[0].split('@')
            create_key(username)
            create_profile(username)
            update_status("SEND_PROFILE")
        else:
            log.msg('Invalid command received: {}'.format(request[1]))

def error_accounts(error):
    """Error callback for runQuery (adbapi).

    :param no_results (string): error message.
    """
    log.msg("Error fetching requests for new accounts ({})".format(error))


# pending emails
def handle_pending_emails(results):
    """ """
    pass

def error_pending_emails(error):
    """ """
    pass


# fetch emails
def handle_new_emails(results):
    """ """
    pass

def error_new_emails(error):
    """ """
    pass


# #############################################################################
# CHECKS: methods called by earch service periodically
# #############################################################################
def check_new_accounts(dbpool):
    """Get new requests from database to create accounts. This method is called
    by the ``accounts`` service every n seconds.

    :param dbpool (DBpool object): asynchronous connection to SQLite database.
    """

    log.msg("Checking requests table for new accounts.")
    query = 'select * from requests where status=?'
    status = 'ONHOLD'

    if dbpool:
        # runQuery returns a deferred, so we can add callback and errback.
        return dbpool.runQuery(query, (status,)).\
            addCallback(handle_new_accounts).\
            addErrback(error_accounts)

def check_pending_email(dbpool):
    """Get new requests from database to send pending emails. This method is
    called by the ``sendmail`` service every n seconds.

    :param dbpool (DBpool object): asynchronous connection to SQLite database.
    """

    log.msg("Checking requests table for pending emails.")
    query = 'select * from requests where status=?'
    status = 'PENDING'

    if dbpool:
        # runQuery returns a deferred, so we can add callback and errback.
        return dbpool.runQuery(query, (status,)).\
            addCallback(handle_new_accounts).\
            addErrback(error_accounts)


def check_new_email(dbpool):
    """Get new requests from database to fetch emails. This method is called
    by the ``getmail`` service every n seconds.

    :param dbpool (DBpool object): asynchronous connection to SQLite database.
    """

    log.msg("Checking requests table for new emails.")
    query = 'select * from requests where status=?'
    status = 'NEW'

    if dbpool:
        # runQuery returns a deferred, so we can add callback and errback.
        return dbpool.runQuery(query, (status,)).\
            addCallback(handle_new_accounts).\
            addErrback(error_accounts)


# one service for each main task
accounts_service = BaseService("accounts", 3, check_new_accounts)
pending_emails_service = BaseService("pending_emails", 5, check_pending_email)
new_emails_service = BaseService("new_emails", 7, check_new_email)

csvpn = service.MultiService()
csvpn.addService(accounts_service)
csvpn.addService(pending_emails_service)
csvpn.addService(new_emails_service)

application = service.Application("csvpn")
csvpn.setServiceParent(application)

