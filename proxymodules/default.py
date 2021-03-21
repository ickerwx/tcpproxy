#!/usr/bin/env python3
import os.path as path
import struct
import builtins
import logging
import threading
from proxymodules.basemodule import BaseModule

class Module(BaseModule):
    def __init__(self, incoming=False, args=None, options=None):
        BaseModule.__init__(self, incoming, args, options)

        self.name = '*'
        self.description = 'Default module (for L7 filtering ala Snort/Suricata "content")'
        self.source = None
        self.destination = None
        self.protocol = 'TCP'
        self.incoming = incoming
        self.audit = ''
        self.filters = None

    def execute(self, data, source, destination):
        sample = data[:20].hex()
        if len(data) > 20:
            sample += '...'
        self.audit = '%s %s SRC=%s:%d DST=%s:%d LEN=%d %s' % (self.direction, self.protocol, source[0], source[1], destination[0], destination[1], len(data), sample) 
        logger.info(self.audit)

        if self.incoming == False and self.filters:
            params = [
            (self.protocol, PType.IP_PROTO), 
            (source[0], PType.IP_ADDR), 
            (source[1], PType.NUMERIC),
            (destination[0], PType.IP_ADDR),
            (destination[1], PType.NUMERIC),
            (data, PType.CONTENT)]
            self.filters.source = source
            self.filters.destination = destination
            self.filters.protocol = self.protocol
            self.filters.direction = self.direction
            self.filters.audit = self.audit
            self.filters.filter(self.name, params)
        return data

    def help(self):
        h = ''
        return h

if __name__ == '__main__':
    print('This module is not supposed to be executed alone!')
