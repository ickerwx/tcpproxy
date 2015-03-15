#!/usr/bin/env python2


class Module:
    def __init__(self):
        self.name = 'Text display'
        self.description = 'Simply print the received data as text'

    def execute(self, data):
        print data
        return data

if __name__ == '__main__':
    print 'This module is not supposed to be executed alone!'
