#!/usr/bin/env python2


class Module:
    def __init__(self, incoming=False):
        self.name = 'http_strip'
        self.description = 'Remove HTTP header from data'
        self.incoming = incoming  # incoming means module is on -im chain

    def detect_linebreak(self, data):
        line = data.split('\n', 1)[0]
        if line.endswith('\r'):
            return '\r\n' * 2
        else:
            return '\n' * 2

    def execute(self, data):
        if data.startswith('HTTP/1.'):
            delimiter = self.detect_linebreak(data)
            data = data.split(delimiter, 1)[1]
        return data


if __name__ == '__main__':
    print 'This module is not supposed to be executed alone!'
