#!/usr/bin/env python3
import os
import re


class Module:
    def __init__(self, incoming=False, verbose=False, options=None):
        # extract the file name from __file__. __file__ is proxymodules/name.py
        self.name = os.path.splitext(os.path.basename(__file__))[0]
        self.description = 'Find HTTP Digest Authentication and replace it with a Basic Auth'
        self.verbose = verbose
        self.realm = 'tcpproxy'

        if options is not None:
            if 'realm' in options.keys():
                self.realm = options['realm']

    def detect_linebreak(self, data):
        line = str(data).split('\n', 1)[0]
        if line.endswith('\r'):
            return '\r\n'
        else:
            return '\n'

    def execute(self, data):
        delimiter = self.detect_linebreak(data)
        lines = str(data).split(delimiter)
        for index, line in enumerate(lines):
            if line.lower().startswith('www-authenticate: digest'):
                lines[index] = 'WWW-Authenticate: Basic realm="%s"%s' % (self.realm, delimiter)

        return delimiter.join(lines)

    def help(self):
        h = '\trealm: use this instead of the default "tcpproxy"\n'
        return h


if __name__ == '__main__':
    print ('This module is not supposed to be executed alone!')
