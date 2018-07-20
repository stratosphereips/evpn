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

import re
import dkim
import validate_email

from datetime import datetime
from ConfigParser import ConfigParser

from email import message_from_string
from email.utils import parseaddr

from twisted.mail import imap4
from twisted.protocols import basic
from twisted.enterprise import adbapi
from twisted.internet import ssl, defer, stdio, protocol, endpoints

# local imports
from slack import SlackBot
from utils import log, Base, AddressError, DkimError


"""
Most of this classes and methods were adapted from Twisted examples.
See https://twisted.readthedocs.io/en/twisted-18.4.0/mail/examples/index.html
for reference. Some comments are my own, some from the example.
"""


class TrivialPrompter(basic.LineReceiver):
    """ Prompter to interact with IMAP4 server. """
    from os import linesep as delimiter
    delimiter = delimiter.encode('utf-8')

    promptDeferred = None

    def prompt(self, msg):
        assert self.promptDeferred is None
        self.display(msg)
        self.promptDeferred = defer.Deferred()
        return self.promptDeferred

    def display(self, msg):
        self.transport.write(msg.encode('utf-8'))

    def lineReceived(self, line):
        if self.promptDeferred is None:
            return
        d, self.promptDeferred = self.promptDeferred, None
        d.callback(line.decode('utf-8'))


class SimpleIMAP4Client(imap4.IMAP4Client):
    """ Simple client for greeting the server."""
    greetDeferred = None

    def serverGreeting(self, caps):
        self.serverCapabilities = caps
        if self.greetDeferred is not None:
            d, self.greetDeferred = self.greetDeferred, None
            d.callback(self)


class SimpleIMAP4ClientFactory(protocol.ClientFactory):
    """ Simple client factory extended for IMAP4. """
    usedUp = False
    protocol = SimpleIMAP4Client

    def __init__(self, username, onConn):
        self.username = username
        self.onConn = onConn

    def buildProtocol(self, addr):
        """
        Initiate the protocol instance. Since we are building a simple IMAP
        client, we don't bother checking what capabilities the server has. We
        just add all the authenticators twisted.mail has. Note: Gmail no
        longer uses any of the methods below, it's been using XOAUTH since
        2010.
        """
        assert not self.usedUp
        self.usedUp = True

        p = self.protocol()
        p.factory = self
        p.greetDeferred = self.onConn

        p.registerAuthenticator(imap4.PLAINAuthenticator(self.username))
        p.registerAuthenticator(imap4.LOGINAuthenticator(self.username))
        p.registerAuthenticator(
                imap4.CramMD5ClientAuthenticator(self.username))

        return p

    def clientConnectionFailed(self, connector, reason):
        d, self.onConn = self.onConn, None
        d.errback(reason)


class Fetchmail(Base):
    """
    Class for fetching mails from IMAP4 servers. Used for:

        - Establish communication with IMAP4 server following the ritual:
          greet, auth, select mailbox, search, fetch mails.
        - Process fetched mails: get headers, body, parse contents.
    """

    def __init__(self, config_file):
        """
        Constructor. It loads configuration values and call the
        Base constructor.

        :param config_file (str): path for configuration file.
        """
        config = ConfigParser()
        config.read(config_file)

        log.debug("IMAP:: Loading configuration values.")

        # Credentials and host information
        self.host = config.get('credentials', 'host')
        self.port = int(config.get('credentials', 'port'))

        # For our case, we should use Gmail names for mailboxes
        self.mbox = config.get('credentials', 'mbox')
        self.username = config.get('credentials', 'username')
        self.password = config.get('credentials', 'password')

        # Slack notifications
        slack_config = config.get('slack', 'config')
        self.slack_channel = config.get('slack', 'channel')
        self.slackbot = SlackBot(slack_config)

        # Time interval for the service loop (in seconds)
        self.interval = float(config.get('general', 'interval'))

        Base.__init__(self)

    def cb_server_greeting(self, proto):
        """
        Initial callback - invoked after the server sends us its greet message.

        :param proto (SimpleIMAP4Client): protocol instance.

        :return: deferred whose callback/errback will handle protocol
        authentication result.
        """
        log.debug(
            "IMAP:: Got greeting message from server. Creating prompter."
        )
        # Hook up stdio
        tp = TrivialPrompter()
        stdio.StandardIO(tp)

        # And make it easily accessible
        proto.prompt = tp.prompt
        proto.display = tp.display

        self.proto = proto
        # Try to authenticate securely
        return proto.authenticate(
            self.password
        ).addCallback(self.cb_auth).addErrback(self.eb_auth)

    def eb_server_greeting(error):
        """
        Errback if we don't/can't receive server's greet message.
        """
        log.debug(
            "IMAP:: Could not get greeting message from server: {}.".format(
                error
            )
        )

    def cb_auth(self, capabilities):
        """
        Callback after auth has succeeded. Select the `self.mbox` mailbox.

        :param capabilities (dict): a list of server capabilities and result
        of authentication.

        :return: deferred whose callback/errback will handle mailbox
        selection.
        """
        log.debug(
            "IMAP:: Auth successful. Selecting mailbox {}.".format(
                self.mbox
            )
        )
        return self.proto.select(
            self.mbox
        ).addCallback(self.cb_mbox_select).addErrback(self.eb_mbox_select)

    def eb_auth(self, failure):
        """
        Errback invoked when authentication fails.

        If it failed because no SASL mechanisms match, offer the user the
        choice of logging in insecurely.
        """
        log.debug("IMAP:: Authentication failed.")
        failure.trap(imap4.NoSupportedAuthentication)
        # TODO: change this to exception
        return defer.fail(Exception("Login failed for security reasons."))

    def cb_mbox_select(self, mbox_info):
        """
        Callback invoked when select command completes. Search for unseen
        messages.

        :param mbox_info (dict): Mailbox information. See
        twisted.mail.imap4.IMAP4Client.html#select for details.

        :return: deferred whose callback will be invoked with a list of all
        the message sequence numbers return by the search, or whose errback
        will be invoked if there is an error.
        """

        new = imap4.Query(unseen=True, sorted=True)
        log.debug(
            "IMAP:: Examining mailbox {}. "
            "Trying to fetch unseen messages.".format(self.mbox)
        )
        return self.proto.search(
            new
        ).addCallback(self.cb_fetchmail).addErrback(self.eb_fetchmail)

    def eb_mbox_select(self, error):
        """
        Errback if we don't/can't select mailbox.
        """
        log.debug(
            "IMAP:: Could not select mailbox {}: {}.".format(
                self.mbox, error
            )
        )

    @defer.inlineCallbacks
    def cb_fetchmail(self, mids):
        """
        Finally, retrieve messages. Get headers, body, and parse it. After
        that just finish communication with the IMAP server.

        :param mids (list): list of mail IDs for unseen messages.
        """
        for mid in mids:
            log.info("IMAP:: Fetching message with MID {}".format(mid))
            log.debug("IMAP:: Fetching headers")
            headers = yield self.proto.fetchHeaders(mid)
            log.debug("IMAP:: Fetching body")
            body = yield self.proto.fetchBody(mid)
            if headers and body:
                log.info("IMAP:: Got new mail!")
                try:
                    # We don't do asynchronous parse of message content
                    yield defer.maybeDeferred(
                        self.parse_message, mid, headers, body
                    ).addCallback(
                        self.cb_parse_message
                    ).addErrback(
                        self.eb_parse_message
                    )
                # Fail if the email address is malformed, does not have valid
                # DKIM signature
                except AddressError as e:
                    log.info("IMAP:: Invalid email address: {}.".format(e))
                except DkimError as e:
                    log.info("IMAP:: DKIM error: {}.".format(e))

                yield self.slackbot.post("Got new mail!", self.slack_channel)
                log.info("IMAP:: Mail processed.")

        # Finish communication. Connect and disconnect rather than keep a
        # persistent connection
        yield self.proto.logout()

    def eb_fetchmail(self, error):
        """
        Errback if we don't/can't fetch the mails (search query failed).
        """
        log.debug("IMAP:: Could not fetch message: {}.".format(error))

    def parse_message(self, mid, headers, body):
        """
        Parse message content. Check if email address is well formed, if DKIM
        signature is valid, and prevent service flooding. Finally, look for
        commands to process the request. Current commands are:

            - vpn account: request a new VPN account.
            - anything else is processed as a help request.

        :param mid (int): mail identifier.
        :param headers (dict): message headers.
        :param body (dict): message body.

        :return dict with email address and command (`account` or `help`).
        """
        log.info("IMAP:: Parsing email content.")

        headers_str = headers[mid]['RFC822.HEADER']
        body_str = body[mid]['RFC822.TEXT']
        # Create an email.message.Message object
        msg_str = headers_str + body_str
        msg = message_from_string(msg_str)

        # Normalization will convert <Alice Wonderland> alice@wonderland.net
        # to alice@wonderland.net
        name, norm_addr = parseaddr(msg['From'])
        log.debug("IMAP:: Normalizing and validating {}.".format(msg['From']))

        # Validate_email will do a bunch of regexp to see if the email address
        # is well address. Additional options for validate_email are check_mx
        # and verify, which check if the SMTP host and email address exist.
        # See validate_email package for more info.
        if norm_addr and validate_email.validate_email(norm_addr):
            log.debug("IMAP:: Normalized email address: {}.".format(norm_addr))
            log.info("IMAP:: Email address looks good: {}.".format(norm_addr))
        else:
            log.debug("IMAP:: Error normalizing/validating email address.")
            raise AddressError("Invalid email address {}".format(from_header))

        whitelist = ['vpn@aic.fel.cvut.cz', 'mailer-daemon@googlemail.com']
        if norm_addr in whitelist:
            log.debug("IMAP:: Ignoring message from {}".format(norm_addr))
            raise AddressError("Email address in whitelist")

        # DKIM verification. Simply check that the server has verified the
        # message's signature
        log.info("IMAP:: Checking DKIM signature.")
        # Note: msg.as_string() changes the message to conver it to string, so
        # DKIM will fail. Use the original string istead
        if dkim.verify(msg_str):
            log.info("IMAP:: Valid DKIM signature.")
        else:
            log.info("IMAP:: Invalid DKIM headers.")
            raise DkimError("DKIM verification failed")

        # For parsing we just search for `vpn account` keywords.
        command = "help"
        words = re.split(r"\s+", body_str.strip())
        for word in words:
            if word.lower() == "vpn":
                command = "account"
                break

        log.debug("IMAP:: Email body content parsed.")
        if command == 'account':
            log.info("IMAP:: Got request for new account.")
        elif command == "help":
            log.info("IMAP:: Got request for help.")

        return {'email_addr': norm_addr, 'command': command}

    def cb_parse_message(self, request):
        """
        Callback invoked when the message has been parsed. It stores the
        obtained information in the database for further processing by the
        Accounts or Messages services.

        :param (dict) request: the built request based on message's content.
        It contains the `email_addr` and command `fields`.

        :return: deferred whose callback/errback will log database query
        execution details.
        """
        log.info("IMAP:: Request parsed successfully: {} ({}).".format(
            request['email_addr'], request['command'])
        )

        query = "insert into requests values(?, ?, ?, '', '', ?, '')"

        # Generate username based on email prefix and current date.
        username, domain = request['email_addr'].split('@')
        now_str = datetime.now().strftime("%Y%m%d%H%M%S")
        username = "{}-{}".format(username, now_str)

        # Account requests are set to ONHOLD to be processed by the Accounts
        # serice. Help requests are set to HELP_PENDING to be processed by the
        # Messages service.
        if request['command'] == "account":
            log.debug("IMAP:: Inserting new request with status ONHOLD.")
            return self.dbpool.runQuery(
                query, (
                    username,
                    request['email_addr'],
                    request['command'],
                    "ONHOLD"
                )
            ).addCallback(self.cb_db_query).addErrback(self.eb_db_query)
        else:
            log.debug("IMAP:: Inserting new request with status HELP_PENDING.")
            return self.dbpool.runQuery(
                query, (
                    username,
                    request['email_addr'],
                    request['command'],
                    "HELP_PENDING"
                )
            ).addCallback(self.cb_db_query).addErrback(self.eb_db_query)

    def eb_parse_message(self, error):
        """
        Errback if we don't/can't parse the message's content.
        """
        log.info("IMAP:: Error parsing email content: {}.".format(error))

    def _get_new(self):
        """
        Get new mails from IMAP server. This will define the `main loop` of
        the IMAP service.
        """
        onConn = defer.Deferred().addCallback(
            self.cb_server_greeting
        ).addErrback(
            self.eb_server_greeting
        )

        # Connect with endpoints. Connect and disconnect from time to time
        # (defined by the service's interval) instead of establishing a
        # persistent connection
        factory = SimpleIMAP4ClientFactory(self.username, onConn)

        from twisted.internet import reactor
        endpoint = endpoints.HostnameEndpoint(reactor, self.host, self.port)

        contextFactory = ssl.optionsForClientTLS(
            hostname=self.host.decode('utf-8')
        )
        endpoint = endpoints.wrapClientTLS(contextFactory, endpoint)

        log.debug("IMAP:: Connecting to Google's IMAP servers.")
        endpoint.connect(factory)
