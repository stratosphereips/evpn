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

from ConfigParser import ConfigParser

from email import Encoders
from email.MIMEBase import MIMEBase
from email.mime.text import MIMEText
from email.MIMEMultipart import MIMEMultipart
from twisted.internet import defer
from twisted.mail.smtp import sendmail

# local imports
from utils import log, Base, AddressError, SMTPError


class Messages(Base):
    """
    Messages class. Used for:

        - Send mails based on requests status in database.
    """
    def __init__(self, config_file):
        """
        Constructor. It loads configuration values and call the
        Base constructor.

        :param config_file (str): path for configuration file.
        """
        config = ConfigParser()
        config.read(config_file)

        # Credentials and host information
        log.debug("SMTP:: Loading configuration values.")
        self.host = config.get('credentials', 'host')
        self.port = int(config.get('credentials', 'port'))
        self.username = config.get('credentials', 'username')
        self.password = config.get('credentials', 'password')
        # Time interval for the service loop (in seconds)
        self.interval = float(config.get('general', 'interval'))
        # Limit of help requests per email address
        self.max_help_requests = int(config.get('general',
                                 'max_help_requests'))
        # CivilSphere team email address(es) for getting notifications
        self.cs_emails = config.get('general', 'cs_emails')

        # Different message's subject and body fields to be sent.
        self.msg = {}
        self.msg['profile_subject'] = config.get('subject', 'profile')
        self.msg['expired_subject'] = config.get('subject', 'expired')
        self.msg['help_subject'] = config.get('subject', 'help')
        self.msg['profile_cc_subject'] = config.get('subject', 'profile_cc')
        self.msg['expired_cc_subject'] = config.get('subject', 'expired_cc')
        self.msg['profile_body'] = config.get('body', 'profile')
        self.msg['expired_body'] = config.get('body', 'expired')
        self.msg['help_body'] = config.get('body', 'help')
        self.msg['profile_cc_body'] = config.get('body', 'profile_cc')
        self.msg['expired_cc_body'] = config.get('body', 'expired_cc')

        # Make new lines work
        for k in self.msg:
            self.msg[k] = self.msg[k].replace('\\n', '\n')

        # Useful paths
        self.path = {}
        self.path['profiles'] = config.get('path', 'profiles')
        self.path['mobile_tutorial'] = config.get('path', 'mobile_tutorial')

        Base.__init__(self)

    def sendmail(self, email_addr, type, subject, content, file=None,
        filename=None):
        """
        Send an email message. It creates a plain text or mime message
        depending on the request's type, set headers and content and
        finally send it.

        :param email_addr (str): email address of the recipient.
        :param type (str): type of message to create (help or mime).
        :param subject (str): subject of the message.
        :param content (str): content of the message.
        :param file (str): path to file to be attached (optional).
        :param filename (str): attachment's filename (optional).

        :return: deferred whose callback/errback will handle the SMTP
        execution details.
        """

        # Help requests are just text. Accounts requests attach a .ovpn
        # file, so they are MIME
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

            # Attach profile
            profile_attachment = MIMEBase('application', "octet-stream")
            profile_attachment.set_payload(
                open(file, "rb").read()
            )
            Encoders.encode_base64(profile_attachment)
            profile_attachment.add_header(
                "Content-Disposition", "attachment", filename=filename
            )
            message.attach(profile_attachment)

            # Attach mobile tutorial
            mobile_attachment = MIMEBase('application', "octet-stream")
            mobile_attachment.set_payload(
                open(self.path['mobile_tutorial'], "rb").read()
            )
            Encoders.encode_base64(mobile_attachment)
            mobile_attachment.add_header(
                "Content-Disposition", "attachment",
                filename="EVPN_tutorial_mobile_devices.pdf"
            )
            message.attach(mobile_attachment)

        # Create a list of email address so twisted.mail.smtp.sendmail
        # knows how to handle it
        if "," in email_addr:
            log.debug("SMTP:: Sending email to multiple recipients.")
            email_addr = email_addr.split(",")

        log.debug("SMTP:: Calling asynchronous sendmail.")
        return sendmail(
            self.host, self.username, email_addr, message,
            port=self.port, username=self.username, password=self.password,
            requireAuthentication=True, requireTransportSecurity=True
        ).addCallback(self.cb_smtp).addErrback(self.eb_smtp)

    def cb_smtp(self, message):
        """
        Callback invoked after mail has been sent.

        :param message (string): Success details from the server.
        """
        log.info("SMTP:: Email sent successfully.")
        log.debug("SMTP:: {}".format(message))

    def eb_smtp(self, error):
        """
        Errback if we don't/can't send the built message.
        """
        log.debug("SMTP:: Could not send mail.")
        raise SMTPError("{}".format(error))

    @defer.inlineCallbacks
    def _get_new(self):
        """
        Get new requests to process. This will define the `main loop` of
        the Messages service.
        """

        # Manage help, profile and expired messages separately
        pending_help = yield self._get_requests("HELP_PENDING")
        pending_profiles = yield self._get_requests('PROFILE_PENDING')
        expired_accounts = yield self._get_requests('EXPIRED_PENDING')

        if pending_help:
            try:
                log.info("SMTP:: Got pending messages for help.")
                for request in pending_help:
                    username = request[0]
                    email_addr = request[1]

                    num_requests = yield self._get_num_requests(
                        email_addr, ["HELP", "HELP_PENDING"]
                    )
                    if num_requests[0][0] > self.max_help_requests:
                        raise AddressError("{}: {}".format(
                            email_addr, str(num_requests[0][0]))
                        )


                    log.info("SMTP:: Sending help message to {}.".format(
                            email_addr
                        )
                    )
                    yield self.sendmail(
                        email_addr, "plain", self.msg['help_subject'],
                        self.msg['help_body']
                    )
                    yield self._update_status(username, "HELP")

            except AddressError as error:
                log.info("SMTP:: Too many help requests {}: {}".format(
                        email_addr, error
                    )
                )
                # Delete it to avoid database flooding
                yield self._delete_request(username)

            except SMTPError as error:
                log.info("SMTP:: Error sending email: {}.".format(error))

        elif pending_profiles:
            try:
                log.info("SMTP:: Got pending messages for profiles.")
                for request in pending_profiles:
                    username = request[0]
                    email_addr = request[1]
                    ip_addr = request[6]

                    ovpn_filename = "{}.ovpn".format(username)
                    ovpn_file = os.path.join(
                        self.path['profiles'],
                        ovpn_filename
                    )

                    log.info("SMTP:: Sending VPN profile to {}.".format(
                            email_addr
                        )
                    )
                    yield self.sendmail(
                        email_addr, "mime", self.msg['profile_subject'],
                        self.msg['profile_body'], ovpn_file, ovpn_filename
                    )
                    # Notify CivilSphere team
                    yield self.sendmail(
                        self.cs_emails,
                        "plain",
                        self.msg['profile_cc_subject'].format(username),
                        self.msg['profile_cc_body'].format(username, ip_addr)
                    )
                    yield self._update_status(username, "ACTIVE")

            except SMTPError as error:
                log.info("SMTP:: Error sending email: {}.".format(error))
        elif expired_accounts:
            try:
                log.info("SMTP:: Got pending messages for expired accounts.")
                for request in expired_accounts:
                    username = request[0]
                    email_addr = request[1]
                    log.info(
                        "SMTP:: Sending expiration message to {}.".format(
                            email_addr
                        )
                    )
                    yield self.sendmail(
                        email_addr, "plain", self.msg['expired_subject'],
                        self.msg['expired_body']
                    )
                    # Notify CivilSphere team
                    yield self.sendmail(
                        self.cs_emails,
                        "plain",
                        self.msg['expired_cc_subject'].format(username),
                        self.msg['expired_cc_body'].format(username, ip_addr)
                    )
                    yield self._update_status(username, "EXPIRED")

            except SMTPError as error:
                log.info("SMTP:: Error sending email: {}.".format(error))
        else:
            log.debug("SMTP:: No pending messages - Keep waiting.")
