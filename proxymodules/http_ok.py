#!/usr/bin/env python2
import os.path as path


class Module:
    def __init__(self, incoming=False, verbose=False, options=None):
        # extract the file name from __file__. __file__ is proxymodules/name.py
        self.name = path.splitext(path.basename(__file__))[0]
        self.description = 'Prepend HTTP response header'
        self.server = None
        if options is not None:
            if 'server' in options.keys():
                self.server = options['server']

        # source will be set by the proxy thread later on
        self.source = None

    def execute(self, data):
        if self.server is None:
            self.server = self.source[0]

        http = "HTTP/1.1 200 OK\r\n"
        http += "Server: %s\r\n" % self.server
        http += "Connection: keep-alive\r\n"
        http += "Content-Length: %d\r\n" % len(data)

        return http + "\r\n" + data

    def help(self):
        h = '\tserver: remote source, used in response Server header\n'
        return h


if __name__ == '__main__':
    print 'This module is not supposed to be executed alone!'
