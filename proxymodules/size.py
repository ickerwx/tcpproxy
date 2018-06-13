#!/usr/bin/env python2
import os.path as path
from distutils.util import strtobool


class Module:
    def __init__(self, incoming=False, verbose=False, options=None):
        # extract the file name from __file__. __file__ is proxymodules/name.py
        self.name = path.splitext(path.basename(__file__))[0]
        self.description = 'Print the size of the data passed to the module'
        self.verbose = verbose
        self.source = None
        self.destination = None
        self.incoming = incoming
        if options is not None:
            if 'verbose' in options.keys():
                self.verbose = bool(strtobool(options['verbose']))

    def execute(self, data):
        size = len(data)
        msg = "Received %d bytes" % size
        if self.verbose:
            msg += " from %s:%d" % self.source
            msg += " for %s:%d" % self.destination
        print msg
        return data

    def help(self):
        h = '\tverbose: override the global verbosity setting'
        return h


if __name__ == '__main__':
    print 'This module is not supposed to be executed alone!'
