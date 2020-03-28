#!/usr/bin/env python3
import ipaddress
import os.path as path
from distutils.util import strtobool


class Module:
    def __init__(self, incoming=False, verbose=False, options=None):
        # extract the file name from __file__. __file__ is proxymodules/name.py
        self.name = path.splitext(path.basename(__file__))[0]
        self.description = 'Filter Source IP passed to the module'
        self.verbose = verbose
        self.source = None
        self.destination = None
        self.incoming = incoming
        self.filename = None
        if options is not None:
            if 'verbose' in options.keys():
                self.verbose = bool(strtobool(options['verbose']))
            if 'file' in options.keys():
                self.filename = options['file']
                try:
                    open(self.filename)
                except IOError as ioe:
                    print ("Error opening %s: %s" % (self.filename, ioe.strerror))
                    self.filename = None


    def execute(self, data):
        source = "%s:%d" % self.source
        destination = "%s:%d" % self.destination
        if self.verbose:
            print (source)
            print (destination)
        if self.filename is not None:
            for line in open(self.filename).readlines():
                if "#" not in line:
                    if "/" in line:
                        for addr in ipaddress.IPv4Network(line.strip("\n")):
                            print(addr)
                            if ipaddress.ip_address(source.split(":")[0]) == addr:
                                #print("HIT!!")
                                return ''
                            #else:
                                #print("NO "+source.split(":")[0])
                    elif source.split(":")[0] == line.strip("\n"):
                        #print("HIT!!")
                        return ''

        return data

    def help(self):
        h = '\tverbose: override the global verbosity setting'
        return h


if __name__ == '__main__':
    print ('This module is not supposed to be executed alone!')
