#!/usr/bin/env python2


class Module:
    def __init__(self):
        self.name = 'fake HTTP OK Header'
        self.description = 'Simply adds a fake HTTP header. This is quite usefull if you want to inspect the payload in tools like BurpSuite'

    def execute(self, data):
        http = "HTTP/1.1 200 OK\nServer: tcpproxy\n\n"

        return http + data

if __name__ == '__main__':
    print 'This module is not supposed to be executed alone!'
