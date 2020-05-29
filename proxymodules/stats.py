#!/usr/bin/env python3
import sys
import os.path as path
from proxymodules.basemoduleredis import BaseModuleRedis

class Module(BaseModuleRedis):
    def __init__(self, incoming=False, verbose=False, options=None):
        BaseModuleRedis.__init__(self, incoming, verbose, options)

        # extract the file name from __file__. __file__ is proxymodules/name.py
        self.name = path.splitext(path.basename(__file__))[0]
        self.description = 'Send statistics to redis db'

        if 'redis' not in sys.modules:
            self.missing('redis')

    def set_connection(self, conn_obj):
        BaseModuleRedis.set_connection(self, conn_obj)
        self.channel = self.conn.get_channel()
        self.hash = self.conn.get_short_hash()

        # Initialize statistics in redis if it does not exists
        if not self.redis_db.hexists("stats:summary:bytes",self.hash):
            self.redis_db.hset("stats:summary:bytes", self.hash, 0)
            self.redis_db.hset("stats:summary:packets", self.hash, 0)
        if not self.redis_db.hexists("stats:connections:bytes",self.channel):
            self.redis_db.hset("stats:connections:bytes", self.channel, 0)
            self.redis_db.hset("stats:connections:packets", self.channel, 0)
            self.redis_db.hset("stats:connections:status", self.channel, "O")

    def execute(self, data):
        # Need to refresh connection each time as property may change
        self.channel = self.conn.get_channel()
        self.hash = self.conn.get_short_hash()

        # Increment statistics in redis
        self.redis_db.hincrby("stats:summary:packets", self.hash, 1)
        self.redis_db.hincrby("stats:summary:bytes", self.hash, len(data))
        self.redis_db.hincrby("stats:connections:packets", self.channel, 1)
        self.redis_db.hincrby("stats:connections:bytes", self.channel, len(data))

        return data

    def help(self):
        return ""

if __name__ == '__main__':
    print ('This module is not supposed to be executed alone!')
