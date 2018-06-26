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

from ConfigParser import ConfigParser

from email import Encoders
from email.MIMEBase import MIMEBase
from email.mime.text import MIMEText
from email.MIMEMultipart import MIMEMultipart
from twisted.internet import defer
from twisted.mail.smtp import sendmail

# local imports
from utils import Base, log


class SMTPError(Exception):
    """ """
    pass


class Messages(Base):
    """ """
    def __init__(self, config_file):
        """ """
        config = ConfigParser()
        config.read(config_file)

        log.debug("SMTP:: Loading configuration values.")
        self.host = config.get('credentials', 'host')
        self.port = int(config.get('credentials', 'port'))
        self.username = config.get('credentials', 'username')
        self.password = config.get('credentials', 'password')

        self.interval = float(config.get('general', 'interval'))

        self.msg = {}
        self.msg['profile_subject'] = config.get('subject', 'profile')
        self.msg['help_subject'] = config.get('subject', 'help')
        self.msg['profile_body'] = config.get('body', 'profile')
        self.msg['help_body'] = config.get('body', 'help')

        self.path = {}
        self.path['profiles'] = config.get('path', 'profiles')

        Base.__init__(self)

    def cb_smtp(self, message):
        """ """
        log.info("SMTP:: Email sent successfully.")
        log.debug("SMTP:: {}".format(message))

    def eb_smtp(self, error):
        """ """
        log.debug("SMTP:: Could not send mail.")
        raise SMTPError("{}".format(error))

    def sendmail(self, email_addr, type, subject, content, file=None):
        """ Send email.

        :param email_addr (string): email address to send help.
        """

        if type == "plain":
            log.debug("SMTP:: Creating plain text email")
            message = MIMEText(content)
        elif type == "mime":
            log.debug("SMTP:: Creating MIME email")
            message = MIMEMultipart()
            message.set_charset("utf-8")

        message['Subject'] = subject
        message['From'] = self.username
        message['To'] = email_addr

        if type == "mime":
            attach_content = MIMEText(content, 'plain')
            message.attach(attach_content)
            attachment = MIMEBase('application', "octet-stream")
            attachment.set_payload(
                open(file, "rb").read()
            )
            Encoders.encode_base64(attachment)
            attachment.add_header(
                "Content-Disposition",
                "attachment; filename={}".format(file)
            )
            message.attach(attachment)

        log.debug("SMTP:: Calling asynchronous sendmail.")
        return sendmail(
            self.host, self.username, email_addr, message,
            port=self.port, username=self.username, password=self.password,
            requireAuthentication=True, requireTransportSecurity=True
        ).addCallback(self.cb_smtp).addErrback(self.eb_smtp)

    @defer.inlineCallbacks
    def _get_new(self):
        """"""
        pending_help = yield self._get_requests("HELP_PENDING")
        pending_profiles = yield self._get_requests('PROFILE_PENDING')

        try:
            if pending_help:
                log.info("SMTP:: Got pending messages for help.")
                for request in pending_help:
                    email_addr = request[0]
                    username, domain = email_addr.split('@')
                    log.info("SMTP:: Sending help message to {}.".format(
                        email_addr
                        )
                    )
                    yield self.sendmail(
                        email_addr, "plain", self.msg['help_subject'],
                        self.msg['help_body']
                    )
                    yield self._update_status(email_addr, "HELP")

            elif pending_profiles:
                log.info("SMTP:: Got pending messages for profiles.")
                for request in pending_profiles:
                    email_addr = request[0]
                    username, domain = email_addr.split('@')

                    ovpn_file = "{}{}.ovpn".format(
                    self.path['profiles'], username
                    )
                    log.info("SMTP:: Sending VPN profile to {}.".format(
                        email_addr
                        )
                    )
                    yield self.sendmail(
                        email_addr, "mime", self.msg['profile_subject'],
                        self.msg['profile_body'], ovpn_file
                    )
                    yield self._update_status(email_addr, "ACTIVE")
            else:
                log.debug("SMTP:: No pending messages - Keep waiting.")

        except SMTPError as error:
            log.info("SMTP:: Error sending email: {}.".format(error))
