#!/usr/bin/env python3
import os.path as path

class Module:
    def __init__(self, incoming=False, args=None, options=None):
        # extract the file name from __file__. __file__ is proxymodules/name.py
        self.name = path.splitext(path.basename(__file__))[0]
        self.description = 'Find if connection is based on SSL by seaching for SSL/TLS Client Hello'
        self.incoming = incoming  # incoming means module is on -im chain

    def help(self):
        return ''

    def is_client_hello(self, firstbytes):
        return (len(firstbytes) >= 3 and
                firstbytes[0] in [0x16, 0x17] and
                firstbytes[1:3] in [b"\x03\x00",
                                b"\x03\x01",
                                b"\x03\x02",
                                b"\x03\x03",
                                b"\x02\x00"]
                )

    def set_connection(self, conn_obj):
        self.conn = conn_obj

    def peek(self, data):
        # Only peek on outgoing data
        if self.incoming:
            return {}

        client_hello = self.is_client_hello(data)
        if client_hello:
            self.conn.add_tag("ssl")
            return { "ssl": True }
        return {}

if __name__ == '__main__':
    print ('This module is not supposed to be executed alone!')

