#!/usr/bin/env python2


class Module:
    def __init__(self, incoming=False, options=None):
        # extract the file name from __file__. __file__ is proxymodules/name.py
        self.name = __file__.rsplit('/', 1)[1].split('.')[0]
        self.description = 'Prepend HTTP header'
        self.incoming = incoming  # incoming means module is on -im chain

    def execute(self, data):
        http = "POST / HTTP/1.1\nHost: tcpproxy\n"
        http += "Content-Length: " + str(len(data))
        return http + "\n\n" + data


if __name__ == '__main__':
    print 'This module is not supposed to be executed alone!'
