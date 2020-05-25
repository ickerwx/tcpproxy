import socket
import struct
import base64

# ConnData is an object that contains basic information about the connection.
# Plugins can also use this object to exchange connection or status information
# using tags

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
