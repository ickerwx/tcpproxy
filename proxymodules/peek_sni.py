#!/usr/bin/env python3
import sys
import os.path as path

from proxymodules.basemodule import BaseModule
try:
	from scapy.layers.tls.all import *
except Exception:
    print("WARNING: cannot load scapy. peek_sni module wont work")


class Module(BaseModule):
    def __init__(self, incoming=False, verbose=False, options=None):
        BaseModule.__init__(self, incoming, verbose, options)

        # extract the file name from __file__. __file__ is proxymodules/name.py
        self.name = path.splitext(path.basename(__file__))[0]
        self.description = 'Retrieve hostname from TLS/SSL ClientHello SNI'
        if 'scapy' not in sys.modules:
            self.missing("scapy")

    def is_client_hello(self, firstbytes):
        return (len(firstbytes) >= 3 and
                firstbytes[0] in [0x16, 0x17] and
                firstbytes[1:3] in [b"\x03\x00",
                                b"\x03\x01",
                                b"\x03\x02",
                                b"\x03\x03",
                                b"\x02\x00"]
                )

    def extract_sni(self, data):
        #print ("Dissected TLS Hello data:")
        #TLS(data).show()

        hostnames = []
        tls = TLS(data)

        for msg in tls.msg:
            if 'msgtype' in msg.fields and (msg.msgtype == 1 or msg.msgtype == 2) and 'ext' in msg.fields: # TLSClientHello / TLS13ClientHello / 2: TLS13HelloRetryRequest / SSLv2ClientHello
                for ext in msg.ext:
                    if 'servernames' in ext.fields:
                        for server_name in ext.servernames:
                            self.log_trace("SNI: %s" % str(server_name.servername))
                            hostnames.append(server_name.servername)

        return hostnames

    def peek(self, data):
        # Only peek on outgoing data
        if self.incoming:
            return {}

        client_hello = self.is_client_hello(data)
        self.log_trace("Looking if packet is a TLS Hello: %s" % str(client_hello))
        if client_hello:
            hostnames = self.extract_sni(data)
            if len(hostnames) > 0:
                # Only first hostname will be considered as the current one. Is it possible to get multiple hostnames anyway ?
                self.conn.set_hostname(hostnames[0])
                return { "hostnames": hostnames }

        return {}

    def execute(self, data):
        return data

if __name__ == '__main__':
    print ('This module is not supposed to be executed alone!')

