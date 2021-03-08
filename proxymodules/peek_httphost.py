#!/usr/bin/env python3
import os.path as path
import re

class Module:
    def __init__(self, incoming=False, args=None, options=None):
        # extract the file name from __file__. __file__ is proxymodules/name.py
        self.name = path.splitext(path.basename(__file__))[0]
        self.description = 'Retrieve hostname from HTTP Host'
        self.incoming = incoming  # incoming means module is on -im chain
        self.re = re.compile(b"^[Hh]ost:\s+([^\r\n]+)", re.MULTILINE)

    def help(self):
        return ''

    def set_connection(self, conn_obj):
        self.conn = conn_obj

    def peek(self, data):
        # Only peek on outgoing data
        if self.incoming:
            return {}

        match = self.re.search(data)
        if match:
            hostname = match.group(1)
            self.conn.set_hostname(hostname)
            return { "hostnames": [hostname] }

        return {}

    def execute(self, data):
        return data

if __name__ == '__main__':
    print ('This module is not supposed to be executed alone!')

