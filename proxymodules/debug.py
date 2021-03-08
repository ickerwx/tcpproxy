#!/usr/bin/env python3
import sys
import os.path as path
from proxymodules.basemoduleredis import BaseModuleRedis

class Module(BaseModuleRedis):
    def __init__(self, incoming=False, args=None, options=None):
        BaseModuleRedis.__init__(self, incoming, args, options)

        # extract the file name from __file__. __file__ is proxymodules/name.py
        self.name = path.splitext(path.basename(__file__))[0]

        self.description = 'Send received data in redis debug PubSub'

        if 'redis' not in sys.modules:
            self.missing("redis")

    def set_connection(self, conn_obj):
        BaseModuleRedis.set_connection(self, conn_obj)

        # Will publish to redis debug channel
        self.channel_name = "debug:"+self.channel_name

    def execute(self, data):
        self.redis_db.publish(self.channel_name, self.conn.get_json(data, c2s=self.incoming, s2c=not self.incoming))
        return data

    def help(self):
        return ""

if __name__ == '__main__':
    print ('This module is not supposed to be executed alone!')
