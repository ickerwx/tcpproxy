#!/usr/bin/env python2
import os.path as path
from proxymodules.basemoduleredis import BaseModuleRedis
from tempfile import TemporaryFile
import socket

class Module(BaseModuleRedis):

    def __init__(self, incoming=False, verbose=False, options=None):
        BaseModuleRedis.__init__(self, incoming, verbose, options)

        self.tempfile = TemporaryFile()

        # extract the file name from __file__. __file__ is proxymodules/name.py
        self.name = path.splitext(path.basename(__file__))[0]

        self.description = 'Wrap the server with data from a file instead of a proper connection'

        self.fileread = False

        self.filename = ""
        self.filetype = "redis"
        self.seekstate = 0
        if options is not None:
            if 'redis' in options.keys():
                self.filetype = "redis"
                self.filename = options['redis']
            if 'esc' in options.keys():
                self.filename = self.filename.replace(options['esc'], ":")
            else:
                self.filename = self.filename.replace("_",":")

    def help(self):
        return "\tredis: the redis key where the data is stored\n" + "\tesc: an escape string to replace ':' characters (default:_)"

    def wrap(self, sock):
        if not self.incoming and not self.fileread and filename:
            if self.filetype == "redis":
                self.log_trace("Reading file from redis (%s) in behalf of connection %s:%d" % (self.filename,self.conn.dst, self.conn.dstport))

                key = self.filename.split(":")
                if len(key) > 1:
                    self.encoding = key[1]
                else:
                    self.encoding = "text"
                if self.encoding in ["base64"]:
                    self.tempfile.write(base64.b64decode(self.redis_db.get(self.filename)))
                else:
                    self.tempfile.write(self.redis_db.get(self.filename))

                self.tempfile.seek(0)
            
                return { "remote_socket": self }
                self.fileread = True
                self.conn.add_tag("redisopendropped")

        return {}

    def recv(self, size, flags=None):
        if flags is not None and flags & socket.MSG_PEEK:
            seekstate = self.tempfile.tell()
            self.tempfile.seek(0)
            data = self.tempfile.read(size)
            self.tempfile.seek(seekstate)
        else:
            data = self.tempfile.read(size)
        return data
        
    def fileno(self):
        return self.tempfile.fileno()

    def getpeername(self):
        return self.filename, 0

    def send(self, data):
        return True

if __name__ == '__main__':
    print ('This module is not supposed to be executed alone!')
