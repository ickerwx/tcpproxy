#!/usr/bin/env python3
import os.path as path
import redis
import json
import base64
import os.path as path
from proxymodules.basemoduleredis import BaseModuleRedis

class Module(BaseModuleRedis):
    def __init__(self, incoming=False, args=None, options=None):
        BaseModuleRedis.__init__(self, incoming, args, options)

        # extract the file name from __file__. __file__ is proxymodules/name.py
        self.name = path.splitext(path.basename(__file__))[0]

        self.description = 'Inspect received data using redis PubSub'
        self.seq = 0
        
        # TODO
        # Implement parameter timeout / fail_policy (pass/drop: default pass)

    def set_connection(self, conn_obj):
        BaseModuleRedis.set_connection(self, conn_obj)

        self.channel_name = self.conn.get_raw_channel()

        # Will publish to redis inspect channel
        self.log_trace("Will send packets on channel %s"%"inspect:"+self.channel_name)

        # Will receive debugged messages to the inspected channel
        self.log_trace("Will received inspected packets on channel %s"%"inspected:"+self.channel_name)
        self.return_sub = self.redis_db.pubsub()
        self.return_sub.subscribe("inspected:"+self.channel_name)
        ret = self.return_sub.get_message(timeout=20)
        self.log_trace("Subscription status: %s"%ret.__str__())

        self.conn.add_tag("inspect")

    def execute(self, data):
        # Increment Sequence number to make more uniq the data channel
        self.seq += 1
        self.log_trace("Sending message to channel %s"%"inspect:"+self.channel_name)

        self.redis_db.publish("inspect:"+self.channel_name, self.conn.get_json(data, seq=self.seq, s2c=self.incoming, c2s=not self.incoming,  module="inspect"))
        self.log_trace("Waiting for debugged message (timeout 60 sec)")
        stop = False
        while not stop:
            msg = self.return_sub.get_message(timeout=60)
            self.log_trace("Received message from channel inspected: %s" % msg.__str__())
            if msg:
                obj = json.loads(msg["data"])
                if obj["s2c"] == self.incoming and obj["c2s"] == (not self.incoming) and obj["seq"] == self.seq:
                    stop = True
                    data = base64.b64decode(obj["data"])
            else:
                stop = True

        return data

    def help(self):
        return ""

if __name__ == '__main__':
    print ('This module is not supposed to be executed alone!')
