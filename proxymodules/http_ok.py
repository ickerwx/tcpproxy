#!/usr/bin/env python3
import os.path as path


class Module:
    def __init__(self, incoming=False, args=None, options=None):
        # extract the file name from __file__. __file__ is proxymodules/name.py
        self.name = path.splitext(path.basename(__file__))[0]
        self.description = 'Prepend HTTP response header'
        self.server = None
        if options is not None:
            if 'server' in options.keys():
                self.server = bytes(options['server'], 'ascii')

        # source will be set by the proxy thread later on
        self.source = None

    def execute(self, data):
        if self.server is None:
            self.server = bytes(self.source[0], 'ascii')

        http = b"HTTP/1.1 200 OK\r\n"
        http += b"Server: %s\r\n" % self.server
        http += b"Connection: keep-alive\r\n"
        http += b"Content-Length: %d\r\n" % len(data)

        return http + b"\r\n" + data

    def help(self):
        h = '\tserver: remote source, used in response Server header\n'
        return h


if __name__ == '__main__':
    print('This module is not supposed to be executed alone!')
