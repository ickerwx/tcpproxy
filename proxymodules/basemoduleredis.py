#!/usr/bin/env python2
import sys
import os.path as path
from proxymodules.basemodule import BaseModule
try:
    import redis
except Exception:
    print("WARNING: cannot load pyredis. modules depending on redis wont work")

class BaseModuleRedis(BaseModule):
    channel_name = None

    def __init__(self, incoming=False, args=None, options=None):
        BaseModule.__init__(self, incoming, args, options)

        self.name = path.splitext(path.basename(__file__))[0]

        if 'redis' not in sys.modules:
            self.redis_db = None
            return

        self.redis_db = redis.StrictRedis()

    def set_connection(self, conn_obj):
        BaseModule.set_connection(self, conn_obj)

        # Will publish to redis debug channel
        self.channel_name = self.conn.get_channel()

    def log(self, level, msg):
        BaseModule.log(self, level, msg)

        if self.channel_name:
            channel = "debug:"+level+":"+self.channel_name
            if self.redis_db:
                self.redis_db.publish(channel, self.conn.get_json(self.name+": "+msg, level=level))

if __name__ == '__main__':
    print ('This module is not supposed to be executed alone!')

