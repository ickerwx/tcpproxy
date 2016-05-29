#!/usr/bin/env python2


class Module:
    def __init__(self, incoming=False):
        self.name = 'http_ok'
        self.description = 'Prepend HTTP response header'
        self.incoming = incoming  # incoming means module is on -im chain

    def execute(self, data):
        http = "HTTP/1.1 200 OK\nServer: tcpproxy\n"
        http += "Content-Length: " + str(len(data))
        return http + "\n\n" + data

if __name__ == '__main__':
    print 'This module is not supposed to be executed alone!'
