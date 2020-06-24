#!/usr/bin/env python2
import os.path as path

class BaseModule:
    def __init__(self, incoming=False, verbose=False, options=None):
        # extract the file name from __file__. __file__ is proxymodules/name.py
        self.name = path.splitext(path.basename(__file__))[0]
        self.description = "Base Module"
        self.incoming = incoming  # incoming means module is on -im chain
        self.conn = None
        self.prematch = None
        self.verbose = verbose
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

    def log(self, level, msg):
        if self.verbose:
            print( ("> > > > in: " if self.incoming else "< < < < out: ") + self.name + " " + level + ": " + msg)

    def log_error(self, msg):
        self.log("ERROR", msg)

    def log_warning(self, msg):
        self.log("WARNING", msg)

    def log_info(self, msg):
        self.log("INFO", msg)

    def log_debug(self, msg):
        self.log("DEBUG", msg)

    def log_trace(self, msg):
        self.log("TRACE", msg)

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

