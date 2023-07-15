#!/usr/bin/env python3
import os.path as path
import time


class Module:
    def __init__(self, incoming=False, verbose=False, options=None):
        # extract the file name from __file__. __file__ is proxymodules/name.py
        self.name = path.splitext(path.basename(__file__))[0]
        self.description = 'Set delay in passing through the packet, used for simulating various network conditions'
        self.incoming = incoming  # incoming means module is on -im chain
        self.seconds = None
        if options is not None:
            if 'seconds' in options.keys():
                self.seconds = float(options['seconds'])

    def execute(self, data):
        if self.seconds:
            time.sleep(self.seconds)

        return data

    def help(self):
        h = '\tseconds: number of seconds you want the packet to be delayed'
        return h


if __name__ == '__main__':
    print('This module is not supposed to be executed alone!')
