#!/usr/bin/env python2


class Module:
    def __init__(self):
        self.name = 'fake HTTP GET Header'
        self.description = 'Simply adds a fake HTTP GET header. This is quite usefull if you want to inspect the payload in tools like BurpSuite'

    def execute(self, data):
        http = "GET / HTTP/1.1\nHost: tcpproxy\n\n"

        return http + data

if __name__ == '__main__':
    print 'This module is not supposed to be executed alone!'
