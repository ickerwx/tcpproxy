#!/usr/bin/env python3
from proxymodules.drop import Drop
import os.path as path

class Module(Drop):
    def __init__(self, incoming=False, args=None, options=None):
        Drop.__init__(self, incoming, args, options)

        # extract the file name from __file__. __file__ is proxymodules/name.py
        self.name = path.splitext(path.basename(__file__))[0]

        self.description = 'Drop trafic with a TCP Reset'
        self.reset = True

if __name__ == '__main__':
    print ('This module is not supposed to be executed alone!')
