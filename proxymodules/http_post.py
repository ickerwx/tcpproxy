#!/usr/bin/env python3
import os.path as path


class Module:
    def __init__(self, incoming=False, verbose=False, options=None):
        # extract the file name from __file__. __file__ is proxymodules/name.py
        self.name = path.splitext(path.basename(__file__))[0]
        self.description = 'Prepend HTTP header'
        self.incoming = incoming  # incoming means module is on -im chain
        self.targethost = None
        self.targetport = None
        if options is not None:
            if 'host' in options.keys():
                self.targethost = bytes(options['host'], 'ascii')
            if 'port' in options.keys():
                self.targetport = bytes(options['port'], 'ascii')

        # destination will be set by the proxy thread later on
        self.destination = None

    def execute(self, data):
        if self.targethost is None:
            self.targethost = bytes(self.destination[0], 'ascii')
        if self.targetport is None:
            self.targetport = bytes(str(self.destination[1]), 'ascii')
        http = b"POST /to/%s/%s HTTP/1.1\r\n" % (self.targethost, self.targetport)
        http += b"Host: %s\r\n" % self.targethost

        http += b"Connection: keep-alive\r\n"
        http += b"Content-Length: %d\r\n" % len(data)
        return http + b"\r\n" + str(data)

    def help(self):
        h = '\thost: remote target, used in request URL and Host header\n'
        h += '\tport: remote target port, used in request URL\n'
        return h


if __name__ == '__main__':
    print('This module is not supposed to be executed alone!')
