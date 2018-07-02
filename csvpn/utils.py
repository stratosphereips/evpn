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
    Error if email address is not valid or we can't normalize it.
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
        query = 'select * from requests where status=?'

        log.debug(
            "DATABASE:: Asking for requests with status {}.".format(
                status
            )
        )
        return self.dbpool.runQuery(query, (status,)).\
            addCallback(self.cb_db_query).\
            addErrback(self.eb_db_query)

    def _update_status(self, email_addr, status):

        """
        Update request status.

        :param email_addr (str): account's email address (identifier).
        :param status (str): new request's status.

        :return: deferred whose callback/errback will log database query
        execution details.
        """
        query = "update requests set status=? where email_addr=?"

        log.debug("DATABASE:: Updating request to status {}.".format(status))
        return self.dbpool.runQuery(query, (status, email_addr)).\
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
