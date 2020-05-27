import socket
import struct
import base64
import json

"""
ConnData is an object that contains basic information about the connection.

Plugins can also use this object to exchange connection or status information using tags

This class is also in charge of retrieving the real source IP and real destination in case

tcproxy is used as a transparent mitm proxy by using IPTables redirects.
"""

class ConnData:

    src = None
    dst = None
    srcport = 0
    dstport = 0
    hostname = None
    data = None

    # Retrieve the destination address and port of the connection
    def setrealdest(self, csock):
        # SO_ORIGINAL_DST option is set when iptable REDIRECT target are used
        # and allows retrieving the original socket destination IP and port (if supported)
        try:
            socket.SO_ORIGINAL_DST
        except AttributeError:
            # This is often not defined as valid socket option. Lets force it
            socket.SO_ORIGINAL_DST = 80

        # Use the Linux specific socket option to query NetFilter
        try:
            odestdata = csock.getsockopt(socket.SOL_IP, socket.SO_ORIGINAL_DST, 16)
        except FileNotFoundError:
            raise Exception("Cannot initiate connection in transparent proxy mode (get socket destination from Netfilter failed).")

        # Unpack the first 6 bytes, which hold the destination data needed
        _, port, a1, a2, a3, a4 = struct.unpack("!HHBBBBxxxxxxxx", odestdata)
        address = "%d.%d.%d.%d" % (a1, a2, a3, a4)

        self.dst = address
        self.dstport = port

    def __init__(self, source=None, destination=None,  dest_socket=None, hostname=None):
        if source:
            self.src, self.srcport = source
        if destination:
            self.dst, self.dstport = destination
        if not self.dst:
            if dest_socket:
                self.setrealdest(dest_socket)

        self.hostname = hostname
        self.tags = set()

    def get_dict(self, data=None, **kwargs):
        res = {
            "src": self.src,
            "dst": self.dst,
            "srcport": self.srcport,
            "dstport": self.dstport,
            "hostname": self.hostname,
            "tags": ",".join(self.tags),
        }
        res.update(**kwargs)
        if data:
            res["data"] = base64.b64encode(data)

        return res

    def set_hostname(self, hostname):
        self.hostname = hostname

    def add_tag(self, tag):
        self.tags |= set([tag])

    def get_hostname(self):
        return self.hostname

    def get_tags(self):
        return self.tags

    def get_json(self, data=None, **kwargs):
        return json.dumps(self.get_dict(data, **kwargs))

    def get_channel(self):
        return ":".join([self.src,str(self.srcport),self.dst,str(self.dstport),self.hostname if self.hostname else "undefined", ','.join(self.tags)])
