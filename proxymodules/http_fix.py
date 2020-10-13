#!/usr/bin/env python2
import os.path as path
import re

from proxymodules.basemoduleredis import BaseModuleRedis

class Module(BaseModuleRedis):
    def __init__(self, incoming=False, verbose=False, options=None):
        BaseModuleRedis.__init__(self, incoming, verbose, options)
        # extract the file name from __file__. __file__ is proxymodules/name.py
        self.name = path.splitext(path.basename(__file__))[0]
        self.description = 'Fix Content-Length HTTP response header'

    def execute(self, data):
        separator = b"\r\n\r\n"
        print(type(data))
        split = data.split(separator,2)
        
        if len(split) <= 1:
            separator = b"\n\n"
            split = data.split(separator,2)

        if len(split) <= 1:
            self.log_warning("Malformed HTTP header. Cannot fix Content-Length size")
            return data 
        else:
            comp = re.compile(b"\n[Cc]ontent-[Ll]ength:\s*[0-9]+")
            body = split[1]
            body_size = len(body)
            headers = comp.sub(b"\nContent-Length: %d" % body_size, split[0], re.MULTILINE)
            self.conn.add_tag("fixed")

            return headers + separator + body

    def help(self):
        h = ''
        return h


if __name__ == '__main__':
    print ('This module is not supposed to be executed alone!')
