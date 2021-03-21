#!/usr/bin/env python3
import os.path as path
from distutils.util import strtobool
import codecs
import collections
import textwrap
import struct
import logging
import builtins
import threading
from proxymodules.basemodule import BaseModule

class Module(BaseModule):
    def __init__(self, incoming=False, args=None, options=None):
        BaseModule.__init__(self, incoming, args, options)

        # extract the file name from __file__. __file__ is proxymodules/name.py
        self.name = path.splitext(path.basename(__file__))[0]

        self.description = 'Siemens Logo! module'
        self.source = None
        self.destination = None
        self.incoming = incoming
        self.direction = ('OUT','IN')[self.incoming] 
        self.protocol = 'TCP'
        self.port = 10005
        self.header = 0x4b
        self.request = None
        self.audit = ''
        self.detection = False
        self.filters = None

    def execute(self, data):
        source = self.conn.src
        destination = self.conn.dst
        
        # Protocol detection
        self.detection = False
        if self.incoming:
            addr, port = source
        else:
            addr, port = destination
        if (port != self.port):
            return data
        self.detection = True
        if not self.incoming:
            try:
                addr, port = destination
                (signature, version, flags, _, request, _) = struct.unpack('!BBxBQ12sL', data[:28])
                if port == self.port and signature == self.header:
                    self.audit = '%s %s' % (request.rstrip(b'\x00').decode(),data[28:].hex())
                    logger.info(self.audit)
                    self.request = request.rstrip(b'\x00').decode()
            except struct.error:
                return data
        if self.incoming and len(data) > 16:
            addr, port = source
            (signature, version, flags) = struct.unpack('!BBxB', data[:4])
            if port == self.port and signature == self.header:
                self.audit = data[16:].hex()
                logger.info(self.audit)

        if self.incoming == False and self.filters:
            params = [
            (self.protocol, PType.IP_PROTO), 
            (source[0], PType.IP_ADDR), 
            (source[1], PType.NUMERIC),
            (destination[0], PType.IP_ADDR),
            (destination[1], PType.NUMERIC),
            (self.request, PType.STRING)]
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
