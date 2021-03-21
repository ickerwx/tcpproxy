#!/usr/bin/env python3
import sys
import os.path as path
from proxymodules.basemodule import BaseModule
try:
    import socks
except Exception:
    print("WARNING: cannot load pysocks. proxy module will be inefective")

class Module(BaseModule):
    def __init__(self, incoming=False, args=None, options=None):
        BaseModule.__init__(self, incoming, args, options)
        self.name = path.splitext(path.basename(__file__))[0]
        self.description = 'Redirect trafic using a HTTP or SOCKS proxy'
 
        self.mode = "HTTP"
        self.host = None
        self.port = None
        self.redirected = False
        if options is not None:
            if "type" in options.keys():
                self.mode = options["type"]
                if self.mode not in ['HTTP', 'SOCKS4', 'SOCKS5']:
                    self.missing("valid mode")
            if "host" in options.keys():
                self.host = options["host"]
            if "port" in options.keys():
                self.port = int(options["port"])

        if 'socks' not in sys.modules:
            self.missing("socks")
        if not self.host:
            self.missing("proxy host")
        if not self.port:
            self.missing("proxy port")

    def help(self):
        return '\thost: the host to proxy trafic through\n' + '\tport: the proxy listening port\n' + '\ttype: the proxy type: HTTP (default), SOCKS4, SOCKS5\n'

    def wrap(self, sock):
        if not self.incoming and not self.redirected:
            return self.wrap_tcp(sock)
        return {}

    def wrap_tcp(self, sock):
        proxy_type = getattr(socks, self.mode)

        remote_socket,local_socket,sock = sock

        new_sock = socks.socksocket()
        new_sock.set_proxy(proxy_type, self.host, self.port)
        try:
            # A second connection will be initiated there because the engine run connect on the server
            # side socket before wrapping sockets
            if self.conn.hostname:
                new_sock.connect((self.conn.hostname, self.conn.dstport))
            else:
                new_sock.connect((self.conn.dst, self.conn.dstport))
            self.redirected = True
            self.conn.add_tag("proxy")
            return {"remote_socket":new_sock}
        except socks.ProxyConnectionError as ex:
            self.log_error(str(ex))

        return {}


