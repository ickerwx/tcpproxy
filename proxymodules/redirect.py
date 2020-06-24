#!/usr/bin/env python3
import os.path as path
from proxymodules.basemodule import BaseModule
import socket
import ssl

class Module(BaseModule):
    def __init__(self, incoming=False, verbose=False, options=None):
        BaseModule.__init__(self, incoming, verbose, options)
        self.name = path.splitext(path.basename(__file__))[0]
        self.description = 'Redirect trafic to another server through a new TCP socket'
 
        self.host = None
        self.port = None
        self.ssl = False
        self.redirected = False
        self.data = None
        if options is not None:
            if "host" in options.keys():
                self.host = options["host"]
            if "port" in options.keys():
                self.port = int(options["port"])
            if "ssl" in options.keys():
                self.ssl = options["ssl"] == "True"
 
    def help(self):
        return '\thost: the host to redirect trafic to (default to same host than connection)\n' + '\tport: the port to redirect trafic to (default to same port than connection)\n' + '\tssl: connect to server using SSL\n'

    def wrap(self, sock):
        if not self.incoming and not self.redirected:
            return self.wrap_tcp(sock)
        return {}

    def wrap_tcp(self, sock):
        if self.host == None:
            self.host = self.conn.dst
        if self.port == None:
            self.port = self.conn.dstport
        remote_socket,local_socket,sock = sock
 
        self.log_trace("Redirecting trafic to %s:%s" % (self.host, self.port))
        try:
            new_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            new_sock.connect((self.host, self.port))
        except Exception as ex:
            self.log_error("TCP Connection failed when establishing redirection to %s:%s" % (self.host, self.port))
            return { "error": "TCP Connection failed when establishing redirection to %s:%s" % (self.host, self.port) }
 
        if self.ssl:
            self.log_trace("Wrapping %s:%s using SSL" % (self.host, self.port))
            new_sock, msg = self.wrap_ssl(new_sock)
            if not new_sock:
                return { "error" : "SSL Connection failed when establishing redirection to %s:%s: %s" % (self.host, self.port, msg) }
 
        self.redirected = True
        self.conn.add_tag("redirected")    
        return { "remote_socket": new_sock }

    def wrap_ssl(self, sock):
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT) # PROTOCOL_TLS_CLIENT for Python3
        # Disable all SSL security as we don't care in the context of the debugger
        # We want to inspect at any price
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        try:
            if self.host:
                # Wrap with SNI
                ssl_socket = context.wrap_socket(sock, server_hostname=self.host)
            else:
                # Legacy wrap
                ssl_socket = context.wrap_socket(sock)

        except ssl.SSLError as e:
            self.log_error("SSL handshake failed for remote socket"+str(e))
            return None, str(e)
        except Exception as e2:
            self.log_error("SSL handshake failed for remote socket on a non ssl related Exception "+str(e2))
            return None, str(e2)
 
if __name__ == '__main__':
    print ('This module is not supposed to be executed alone!')
