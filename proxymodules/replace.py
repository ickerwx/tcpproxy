#!/usr/bin/env python2

import re


class Module:
    def __init__(self, incoming=False, verbose=False, options=None):
        # extract the file name from __file__. __file__ is proxymodules/name.py
        self.name = __file__.rsplit('/', 1)[1].split('.')[0]
        self.description = 'Replace text by using regular expressions'
        self.incoming = incoming  # incoming means module is on -im chain
        if options is not None:
            self.search = options['search']
            self.replace = options['replace']

    def execute(self, data):
        new_data = re.sub(self.search, self.replace, data)
        if not new_data == data:
            print("Replacing '%s' with '%s'" % (self.search, self.replace))
        return new_data

    def help(self):
        h = '\tsearch: string that should be replaced\n'
        h += ('\treplace: value that it should be replaced with')
        return h


if __name__ == '__main__':
    print 'This module is not supposed to be executed alone!'
