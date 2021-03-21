#!/usr/bin/env python3
import socket, struct
import os.path as path
from proxymodules.basemodule import BaseModule

class Drop(BaseModule):

    def __init__(self, incoming=False, args=None, options=None):
        BaseModule.__init__(self, incoming, args, options)

        # extract the file name from __file__. __file__ is proxymodules/name.py
        self.name = path.splitext(path.basename(__file__))[0]

        self.description = 'Drop trafic (optionally with a TCP Reset)'
        
        self.dropped = False
        
        self.reset = False
        if options is not None:
            if 'reset' in options.keys():
                self.reset = options['reset'] == "True"

    def help(self):
        return ''

    def wrap(self, sock):
        local_socket = sock[0]
        remote_socket = sock[1]
        if not self.incoming and not self.dropped:
            self.log_trace("Dropping trafic going to %s:%d" % (self.conn.dst, self.conn.dstport))
            if self.reset == True:
                tag = "Reset"
                text= "reset"
                l_onoff = 1
                l_linger = 0
                local_socket.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack('ii', l_onoff, l_linger))
                remote_socket.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack('ii', l_onoff, l_linger))
            else:
                tag = "Drop"
                text = "dropped"

            # Remote socket may not be open (server unreachable ...) and will be closed by tcpproxy.py anyway
            local_socket.shutdown(socket.SHUT_RDWR)
            local_socket.close()

            self.dropped = True
            self.conn.add_tag(tag)
            self.log_warning("Client connection %s" % text)

        return {}

class Module(Drop):
    pass

if __name__ == '__main__':
    print ('This module is not supposed to be executed alone!')
