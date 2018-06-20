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

from ConfigParser import ConfigParser

from email import message_from_string
from email.utils import parseaddr

from twisted.mail import imap4
from twisted.protocols import basic
from twisted.enterprise import adbapi
from twisted.internet import ssl, defer, stdio, protocol, endpoints

from pprint import pprint

# local imports
from utils import Base, log


class AddressError(Exception):
    pass


class DkimError(Exception):
    pass


class TrivialPrompter(basic.LineReceiver):
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
    """
    A client with callbacks for greeting messages from an IMAP server.
    """
    greetDeferred = None

    def serverGreeting(self, caps):
        self.serverCapabilities = caps
        if self.greetDeferred is not None:
            d, self.greetDeferred = self.greetDeferred, None
            d.callback(self)


class SimpleIMAP4ClientFactory(protocol.ClientFactory):
    usedUp = False
    protocol = SimpleIMAP4Client

    def __init__(self, username, onConn):
        self.username = username
        self.onConn = onConn

    def buildProtocol(self, addr):
        """
        Initiate the protocol instance. Since we are building a simple IMAP
        client, we don't bother checking what capabilities the server has. We
        just add all the authenticators twisted.mail has.  Note: Gmail no
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
    """ """
    def __init__(self, config_file):
        """ """
        config = ConfigParser()
        config.read(config_file)

        log.debug("IMAP:: Loading configuration values.")
        self.host = config.get('credentials', 'host')
        self.port = int(config.get('credentials', 'port'))
        self.mbox = config.get('credentials', 'mbox')
        self.username = config.get('credentials', 'username')
        self.password = config.get('credentials', 'password')

        self.interval = float(config.get('general', 'interval'))

        Base.__init__(self)

    def cb_server_greeting(self, proto):
        """
        Initial callback - invoked after the server sends us its greet message.
        """
        # Hook up stdio
        log.debug(
            "IMAP:: Got greeting message from server. Creating prompter."
        )
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
        """ """
        log.debug(
            "IMAP:: Could not get greeting message from server: {}.".format(
                error
            )
        )

    def cb_auth(self, result):
        """
        Callback after authentication has succeeded.

        Lists a bunch of mailboxes.
        """
        log.debug("IMAP:: Authentication successful. Selecting mailbox.")
        return self.proto.list(
            "", "*"
        ).addCallback(self.cb_mbox_select).addErrback(self.eb_mbox_select)

    def eb_auth(self, failure):
        """
        Errback invoked when authentication fails.

        If it failed because no SASL mechanisms match, offer the user the
        choice of logging in insecurely.

        If you are trying to connect to your Gmail account, you will be here!
        """
        log.debug("IMAP:: Authentication failed.")
        failure.trap(imap4.NoSupportedAuthentication)
        # change this to exception
        return defer.fail(Exception("Login failed for security reasons."))

    def cb_mbox_select(self, result):
        """
        Callback invoked when a list of mailboxes has been retrieved.
        """
        # result = [e[2] for e in result]
        # s = '\n'.join(['%d. %s' % (n + 1, m) \
        # for (n, m) in zip(range(len(result)), result)])
        # if not s:
        #    return defer.fail(Exception("No mailboxes exist on server!"))

        # result[N], with number of mailbox - 1
        # mbox = result[1]
        log.debug("IMAP:: Selected {}. Examining mailbox.".format(self.mbox))
        # select allows read and write
        return self.proto.select(
            self.mbox
        ).addCallback(self.cb_mbox_examine).addErrback(self.eb_mbox_examine)

    def eb_mbox_select(self, error):
        """ """
        log.debug(
            "IMAP:: Could not select mailbox {}: {}.".format(
                self.mailbox, error
            )
        )

    def cb_mbox_examine(self, result):
        """
        Callback invoked when examine command completes.

        Retrieve the subject header of every message in the mailbox.
        """
        new = imap4.Query(unseen=True, sorted=True)
        log.debug(
            "IMAP:: Examining mailbox {}. \
            Trying to fetch unseen mails.".format(self.mbox)
        )
        return self.proto.search(
            new
        ).addCallback(self.cb_fetchmail).addErrback(self.eb_fetchmail)

    def eb_mbox_examine(self, error):
        """ """
        log.debug(
            "IMAP:: Could not examine mailbox {}: {}.".format(
                self.mbox, error
            )
        )

    @defer.inlineCallbacks
    def cb_fetchmail(self, result):
        """
        Finally, display headers.
        """
        for mid in result:
            headers = yield self.get_email_headers(mid)
            body = yield self.get_email_body(mid)
            if headers and body:
                log.info("IMAP:: Got new mail!")
                try:
                    yield defer.maybeDeferred(
                        self.parse_email, mid, headers, body
                    ).addCallback(
                        self.cb_parse_email
                    ).addErrback(
                        self.eb_parse_email
                    )

                except AddressError as e:
                    log.info("IMAP:: Invalid email address: {}.".format(e))
                except DkimError as e:
                    log.info("IMAP:: DKIM error: {}.".format(e))
                except ExistingAccount as e:
                    log.info("IMAP:: Duplicated request: {}.".format(e))

                log.info("IMAP:: Mail processed.")

        yield self.proto.logout()

    def eb_fetchmail(self, error):
        """ """
        log.debug("IMAP:: Could not fetch mail: {}.".format(error))

    def get_email_headers(self, num):
        """ """
        log.debug(
            "IMAP:: Fetching headers for mail with MID {}".format(num)
        )
        return self.proto.fetchHeaders(num)

    def get_email_body(self, num):
        """ """
        log.debug("IMAP:: Fetching body for mail with MID {}".format(num))
        return self.proto.fetchBody(num)

    def parse_email(self, num, headers, body):
        """ """
        log.info("IMAP:: Parsing email content.")

        headers_str = headers[num]['RFC822.HEADER']
        body_str = body[num]['RFC822.TEXT']
        msg = message_from_string(headers_str + body_str)

        name, norm_addr = parseaddr(msg['From'])
        log.debug("IMAP:: Normalizing and validating {}.".format(msg['From']))
        if norm_addr and validate_email.validate_email(norm_addr):
            log.debug("IMAP:: Normalized email address: {}.".format(norm_addr))
            log.info("IMAP:: Email address looks good: {}.".format(norm_addr))
        else:
            log.debug("IMAP:: Error normalizing/validating email address.")
            raise AddressError("Invalid email address {}".format(from_header))

        log.info("IMAP:: Checking DKIM signature.")
        if dkim.verify(msg.as_string()):
            log.info("IMAP:: Valid DKIM signature.")
            command = "help"

            body_content = self.get_body_content(msg)
            words = re.split("\s+", body_content.strip())

            prev_word = ""
            for word in words:
                if prev_word == "vpn" and word.lower() == "account":
                    command = "account"
                    break
                else:
                    prev_word = word.lower()

            log.debug("IMAP:: Email body content parsed.")
            if command == 'account':
                log.info("IMAP:: Got request for new account.")
            elif command == "help":
                log.info("IMAP:: Got request for help.")
        else:
            log.info("IMAP:: Invalid DKIM headers.")
            # log.debug(headers_str)
            raise DkimError("DKIM verification failed")

        return {'email_addr': norm_addr, 'command': command}

    def get_body_content(self, msg):
        """ """
        maintype = msg.get_content_maintype()

        if maintype == 'multipart':
            log.debug("IMAP:: Received a multipart message.")
            for part in msg.get_payload():
                if part.get_content_maintype() == 'text':
                    return part.get_payload()

        elif maintype == 'text':
            log.debug("IMAP:: Received a plain text message.")
            return msg.get_payload()

    def cb_parse_email(self, request):
        """ """
        log.info("IMAP:: Request parsed successfully: {} ({}).".format(
            request['email_addr'], request['command'])
        )

        query = "insert into requests values(?, ?, '', '', ?, '')"

        if request['command'] == "account":
        	log.debug("IMAP:: Inserting new request with status ONHOLD.")
        	return self.dbpool.runQuery(
        		query, (request['email_addr'], request['command'], "ONHOLD")
        	).addCallback(self.cb_db_query).addErrback(self.eb_db_query)
        else:
        	log.debug("IMAP:: Inserting new request with status HELP_PENDING.")
        	return self.dbpool.runQuery(
        		query, (request['email_addr'], request['command'], "HELP_PENDING")
        	).addCallback(self.cb_db_query).addErrback(self.eb_db_query)
        	

    def eb_parse_email(self, error):
        """ """
        log.info("IMAP:: Error parsing email content: {}.".format(error))

    def _get_new(self):
        """  """
        onConn = defer.Deferred().addCallback(
            self.cb_server_greeting
        ).addErrback(
            self.eb_server_greeting
        )

        factory = SimpleIMAP4ClientFactory(self.username, onConn)

        from twisted.internet import reactor
        endpoint = endpoints.HostnameEndpoint(reactor, self.host, self.port)

        contextFactory = ssl.optionsForClientTLS(
            hostname=self.host.decode('utf-8')
        )
        endpoint = endpoints.wrapClientTLS(contextFactory, endpoint)

        log.info("IMAP:: Connecting to Google's IMAP servers.")
        endpoint.connect(factory)
