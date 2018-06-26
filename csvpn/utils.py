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

DATABASE = 'csvpn.db'
log = Logger('csvpn')


class IPError(Exception):
    """ """
    pass


class ExecError(Exception):
    """ """
    pass


class Base(object):
    """ Base class for common behaviour """
    def __init__(self):
        """ Constructor. For now just asynchronous connection to database. """
        self.dbpool = adbapi.ConnectionPool(
            "sqlite3", DATABASE, check_same_thread=False
        )

    def shutdown(self):
        """ """
        log.debug("DATABASE:: Closing connection to SQLite database.")
        self.dbpool.close()
        log.debug("DATABASE:: Connection closed.")

    def _get_new(self):
        """ """
        pass

    def get_interval(self):
        """ """
        if self.interval:
            return self.interval

    def _get_requests(self, status):
        """ Get requests with a given status. """
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

        """ Update request status on database. """
        query = "update requests set status=? where email_addr=?"

        log.debug("DATABASE:: Updating request to status {}.".format(status))
        return self.dbpool.runQuery(query, (status, email_addr)).\
            addCallback(self.cb_db_query).\
            addErrback(self.eb_db_query)

    # Callback and Errback for database query. Return results or None.
    def cb_db_query(self, results):
        """ Callback for sucessful queries. """
        log.debug("DATABASE:: Query executed successfully.")
        return results

    def eb_db_query(self, error):
        """ Errback for failed queries. This is called on empty results. """
        log.debug("DATABASE:: Empty query or error.")
        return None

    # Callback and Errback for command execution. Log output or die.
    def cb_cmd(self, output):
        """ Callback for successfully executed commands. """
        log.debug("CMD:: Command execution successful.")
        log.debug("{}".format(output))

    def eb_cmd(self, error):
        """ Errback for command execution. """
        log.debug("CMD:: Command execution failed.")
        log.debug("{}".format(error))
        raise ExecError("{}".format(error))

    def get_new(self):
        """  """
        self._get_new()


class BaseService(internet.TimerService):
    """ Base service that provides connection to the csvpn database. """

    def __init__(self, name, step, instance, *args, **kwargs):
        """Constructor. Overwritten from parent class to add connection to
        the database.

        TODO: add parameters here
        """

        log.info("SERVICE:: Initializing {} service.".format(name))
        self.name = name
        self.instance = instance
        log.debug("SERVICE:: Initializing TimerService.")
        internet.TimerService.__init__(
            self, step, self.instance.get_new, **kwargs
        )

    def startService(self):
        """Start the service. Overwritten from parent class to add extra
        logging information."""

        log.info("SERVICE:: Starting {} service.".format(self.name))
        internet.TimerService.startService(self)
        log.info("SERVICE:: Service started.")

    def stopService(self):
        """Stop the service. Overwritten from parent class to close the
        connection to the database and to add extra logging information."""

        log.info("SERVICE:: Stopping {} service.".format(self.name))
        log.debug("SERVICE:: Calling shutdown on {}".format(self.name))
        self.instance.shutdown()
        log.debug("SERVICE:: Shutdown for {} done".format(self.name))
        internet.TimerService.stopService(self)
        log.info("SERVICE:: Service stopped.")
