#!/usr/bin/env python2
import os.path as path
import logging

# subclassing threading.local based on https://github.com/ickerwx/tcpproxy/pull/26 ?
class BaseModule:
    def __init__(self, incoming=False, args=None, options=None):
        # extract the file name from __file__. __file__ is proxymodules/name.py
        self.name = path.splitext(path.basename(__file__))[0]

        self.description = "Base Module"
        self.incoming = incoming  # incoming means module is on -im chain
        self.direction = ('OUT','IN')[self.incoming]
        self.protocol = 'TCP'
        self.conn = None
        self.prematch = None

        self.verbose = False
        if args != None:
            self.verbose = args.log_level in ["DEBUG"]

        self.dependencies = []

    def getInfos(self):
        mname = self.name
        mdesc = self.description
        mhelp = self.help()
        if len(self.dependencies) > 0:
            mname += "-MISSING DEPENDENCY"
            mdesc = "Missing dependencies for module: %s\n\t" % ",".join(list(set(self.dependencies))) + mdesc
        return mname, mdesc, mhelp

    def missing(self, name):
        self.dependencies.append(name)
        self.log_warning("Cannot load %s. %s module will be disabled." % (name, self.name))

    def help(self):
        return ''

    def set_connection(self, conn_obj):
        self.conn = conn_obj

    def set_prematch_re(self, prematch_re):
        self.prematch = prematch_re

    def wrap(self, sock):
        return {}

    def peek(self, data):
        return {}

    def _log_extra(self):
        return {'conn':self.conn, 'direction':self.direction,  'self':self}

    def log_error(self, msg):
        logger.error(msg, extra=self._log_extra())

    def log_warning(self, msg):
        logger.warning(msg, extra=self._log_extra())

    def log_info(self, msg):
        logger.info(msg, extra=self._log_extra())

    def log_debug(self, msg):
        logger.debug(msg, extra=self._log_extra())

    def log_trace(self, msg):
        logger.log(2,  msg,  extra=self._log_extra())

    def is_inhibited(self):
        if len(self.dependencies) > 0:
            self.log_trace("inhibited because module is missing some dependencies (%s)" % ",".join(list(set(self.dependencies))))
            return True
        if self.prematch != None and self.conn.hostname != None:
            if not self.conn or not self.conn.hostname or not self.prematch.match(self.conn.hostname):
                self.log_trace("inhibited because hostname does not match rule")
                return True
        return False

    def _execute(self, data):
        if not self.is_inhibited():
            return data

    def execute(self, data):
        return data

if __name__ == '__main__':
    print ('This module is not supposed to be executed alone!')

