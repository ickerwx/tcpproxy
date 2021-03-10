#!/usr/bin/env  python3
import redis
import json
import logging
from conndata import ConnData

class RedisLogHandler(logging.Handler):
    def __init__(self, uri):
        logging.Handler.__init__(self)
        self.uri = uri
        logging.info("Starting logger %s through redis %s" % (self,self.uri))
        # Create a redis connection pool and client
        self.redis_pool = redis.ConnectionPool.from_url(self.uri.geturl())
        self.redis = redis.Redis(connection_pool=self.redis_pool)
        self.conn_none =  ConnData(("0.0.0.0", 0), ("0.0.0.0", 0))

    def emit(self,  record):
        # Will publish to redis debug channel
        channel = "debug:"+record.levelname+":"+record.conn.get_channel()
        self.redis.publish(channel, record.conn.get_json(record.threadName+": "+record.msg, level=record.levelname))

class API():

    def __init__(self,  args, infos,  uri):
        # Create a redis connection pool and client
        self.redis_pool = redis.ConnectionPool.from_url(uri.geturl())
        self.redis = redis.Redis(connection_pool=self.redis_pool)
        
        # Add Redis handler to default logger
        logging.getLogger("__main__").addHandler(RedisLogHandler(uri))

        # Store module documentation on redis
        self.redis.set('modules', " ".join(infos.keys()))
        self.redis.set('default_modules', "peek_sni,peek_httphost,peek_ssl")
        for key, value in infos.items():
            self.redis.set("module:%s:help"%key, value)

    def rules(self):

        try:
            rules = self.redis.get('rules')
        except Exception as ex:
            logger.error("Failed to connect to redis to retrieve rules: %s" % str(ex))
            return {}

        if not rules:
            return {}

        try:
            rules = json.loads(rules)
            return rules
        except Exception as ex:
            logger.error("Failed to decode rules json: %s" % str(ex))
