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

    def __init__(self, source=None, destination=None, hostname=None):
        if source:
            self.src, self.srcport = source
        if destination:
            self.dst, self.dstport = destination

        self.hostname = hostname
        self.tags = set()

    def set_destination(self,  destination):
        self.dst, self.dstport = destination

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
            if isinstance(data,bytes):
                res["data"] = base64.b64encode(data).decode("utf-8")
            else:
                res["data"] = base64.b64encode(data.encode("utf-8")).decode("utf-8")

        return res

    def __str__(self):
        return "Connection %s:%d > %s:%d(%s) tags:%s" % (self.src,self.srcport,self.dst,self.dstport,self.hostname if self.hostname else "unknown", ",".join(self.tags) if self.tags else "None")

    def set_hostname(self, hostname):
        if isinstance(hostname, bytes):
            self.hostname = hostname.decode("utf-8")
        else:
            self.hostname = hostname

        # In case of HTTP Proxy usage (CONNECT), hostname is composed of hostname:targetport. We normalize things there
        self.hostname = self.hostname.split(":")[0]

    def add_tag(self, tag):
        self.tags |= set([tag])

    def get_hostname(self):
        return self.hostname

    def get_tags(self):
        return self.tags

    def get_json(self, data=None, **kwargs):
        return json.dumps(self.get_dict(data, **kwargs))

    def get_string(self):
        return "%s:%s %s:%s" % (self.src,  self.srcport,  self.dst,  self.dstport)

    def get_raw_channel(self):
        return ":".join([self.src,str(self.srcport),self.dst,str(self.dstport)])

    def get_channel(self):
        return ":".join([self.src,str(self.srcport),self.dst,str(self.dstport),self.hostname if self.hostname else "undefined", ','.join(self.tags)])

    def get_short_hash(self):
        return ":".join([self.src,self.dst,str(self.dstport),self.hostname if self.hostname else "undefined", ','.join(self.tags)])
