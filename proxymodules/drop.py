#!/usr/bin/env python2
import os.path as path
from proxymodules.basemoduleredis import BaseModuleRedis

class Module(BaseModuleRedis):

    def __init__(self, incoming=False, verbose=False, options=None):
        BaseModuleRedis.__init__(self, incoming, verbose, options)

        # extract the file name from __file__. __file__ is proxymodules/name.py
        self.name = path.splitext(path.basename(__file__))[0]

        self.description = 'Drop trafic with a TCP Reset'
        
        self.dropped = False
                
    def help(self):
        return ''

    def wrap(self, sock):
        if not self.incoming and not self.dropped:
            self.log_trace("Dropping trafic going to %s:%d" % (self.conn.dst, self.conn.dstport))
            sock[0].close()
            self.dropped = True
            self.conn.add_tag("dropped")
        return {}

if __name__ == '__main__':
    print ('This module is not supposed to be executed alone!')
 
