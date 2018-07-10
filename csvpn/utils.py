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

from twisted.logger import Logger
from twisted.enterprise import adbapi
from twisted.application import internet

# SQLite database for handling requests.
DATABASE = 'csvpn.db'

# Define an application logger
log = Logger('csvpn')

"""
Exception classes for different errors raised in services.
"""


class IPError(Exception):
    """
    Error if we can't allocate an IP for a new account.
    """
    pass


class ExecError(Exception):
    """
    Error when executing system commands.
    """
    pass


class AddressError(Exception):
    """
    Error if email address is not valid, it can't be normalized or it has
    reached the limit of requests.
    """
    pass


class DkimError(Exception):
    """
    Error if DKIM signature verification fails.
    """
    pass


class SMTPError(Exception):
    """
    Error if we can't send emails.
    """
    pass


class Base(object):
    """
    Base class for common behaviour. Including:

        - Initiate and close connection to database.
        - Get time interval.
        - Get requests from database with a given status
        - Update status for a given request.
        - Define callbacks/errbacks for command and query execution details.
    """
    def __init__(self):
        """
        Constructor. For now just asynchronous connection to database.
        """
        self.dbpool = adbapi.ConnectionPool(
            "sqlite3", DATABASE, check_same_thread=False
        )

    def shutdown(self):
        """
        Called on service shutdown. Close connection to database.
        """
        log.debug("DATABASE:: Closing connection to SQLite database.")
        self.dbpool.close()
        log.debug("DATABASE:: Connection closed.")

    def _get_new(self):
        """
        Empty method for override. Accounts, Messages and Fetchmail classes
        should override this to implement its main logic.
        """
        pass

    def get_interval(self):
        """
        Get the time interval. Used by services.

        :return: time interval (float) in seconds.
        """
        if self.interval:
            return self.interval

    def _get_requests(self, status):
        """
        Get requests with a given status.

        :param status (str): request's status.

        :return: deferred whose callback/errback will log database query
        execution details.
        """
        query = "select * from requests where status=?"

        log.debug(
            "DATABASE:: Asking for requests with status {}.".format(
                status
            )
        )
        return self.dbpool.runQuery(query, (status,)).\
            addCallback(self.cb_db_query).\
            addErrback(self.eb_db_query)

    def _update_status(self, username, status):

        """
        Update request status.

        :param username (str): account's username (identifier).
        :param status (str): new request's status.

        :return: deferred whose callback/errback will log database query
        execution details.
        """
        query = "update requests set status=? where username=?"

        log.debug("DATABASE:: Updating request to status {}.".format(status))
        return self.dbpool.runQuery(query, (status, username)).\
            addCallback(self.cb_db_query).\
            addErrback(self.eb_db_query)

    def _delete_request(self, username):
        """
        Delete request. This is to avoid database flooding.

        :param username (str): account's username (identifier).

        :return: deferred whose callback/errback will log database query
        execution details.
        """
        query = "delete from requests where username=?"

        log.debug("DATABASE:: Deleting request with id {}.".format(username))
        return self.dbpool.runQuery(query, (username,)).\
            addCallback(self.cb_db_query).\
            addErrback(self.eb_db_query)

    def _get_num_requests(self, email_addr, statuses):
        """
        Get the number of requests associated to an email address. This
        is to prevent abuse of the service and email flooding.

        :param email_addr (str): the email address of the sender.
        :param statuses (list): statuses for filtering requests.

        :return: deferred whose callback/errback will log database query
        execution details.
        """
        questionmarks = '?' * len(statuses)
        questionmarks = ','.join(questionmarks)
        query = "select count(rowid) from requests where email_addr=? and" \
                " status in ({})".format(questionmarks)

        log.debug("DATABASE:: Getting number of requests from {}.".format(
                email_addr
            )
        )

        params = [email_addr]
        params.extend(statuses)
        return self.dbpool.runQuery(query, params).\
            addCallback(self.cb_db_query).\
            addErrback(self.eb_db_query)

    def cb_db_query(self, results=None):
        """
        Callback for successful query. Return the results, if any.

        :param results (list): list with query's results.
        """
        log.debug("DATABASE:: Query executed successfully.")
        return results

    def eb_db_query(self, error):
        """
        Errback if we don't/can't execute database query, or if we receive
        empty results.
        """
        log.debug("DATABASE:: Empty query or error.")
        if error:
            log.debug("DATABASE:: {}".format(error))
        return None

    def cb_cmd(self, output):
        """
        Callback for successful execution of system command.

        :param output (str): system command's output.
        """
        log.debug("CMD:: Command execution successful.")
        log.debug("{}".format(output))

    def eb_cmd(self, error):
        """
        Errback if we don't/can't execute the system command.
        """
        log.debug("CMD:: Command execution failed.")
        log.debug("{}".format(error))
        raise ExecError("{}".format(error))

    def get_new(self):
        """
        Call to internal method. Called by TimerService parent class.
        """
        self._get_new()


class BaseService(internet.TimerService):
    """
    Base service for Accounts, Messages and Fetchmail. It extends the
    TimerService providing asynchronous connection to database by default.
    """

    def __init__(self, name, step, instance, *args, **kwargs):
        """
        Constructor. Initiate connection to database and link one of Accounts,
        Messages or Fetchmail instances to TimerService behavour.

        :param name (str): name of the service being initiated (just for log
                           purposes).
        :param step (float): time interval for TimerService, in seconds.
        :param instance (object): instance of Accounts, Messages, or
                                  Fetchmail classes.
        """

        log.info("SERVICE:: Initializing {} service.".format(name))
        self.name = name
        self.instance = instance
        log.debug("SERVICE:: Initializing TimerService.")
        internet.TimerService.__init__(
            self, step, self.instance.get_new, **kwargs
        )

    def startService(self):
        """
        Starts the service. Overridden from parent class to add extra logging
        information.
        """
        log.info("SERVICE:: Starting {} service.".format(self.name))
        internet.TimerService.startService(self)
        log.info("SERVICE:: Service started.")

    def stopService(self):
        """
        Stop the service. Overridden from parent class to close connection to
        database, shutdown the service and add extra logging information.
        """
        log.info("SERVICE:: Stopping {} service.".format(self.name))
        log.debug("SERVICE:: Calling shutdown on {}".format(self.name))
        self.instance.shutdown()
        log.debug("SERVICE:: Shutdown for {} done".format(self.name))
        internet.TimerService.stopService(self)
        log.info("SERVICE:: Service stopped.")
