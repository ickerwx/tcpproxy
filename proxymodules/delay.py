#!/usr/bin/env python3
import os.path as path
import time
import random


class Module:
    def __init__(self, incoming=False, verbose=False, options=None):
        # extract the file name from __file__. __file__ is proxymodules/name.py
        self.name = path.splitext(path.basename(__file__))[0]
        self.description = 'Set delay in passing through the packet, used for simulating various network conditions'
        self.incoming = incoming  # incoming means module is on -im chain
        self.random = False
        self.seconds = None
        self.verbose = verbose
        if options is not None:
            if 'seconds' in options.keys():
                try:
                    self.seconds = abs(float(options['seconds']))
                except ValueError:
                    print(f"Can't parse {options['seconds']} as float")
                    pass  # leave it set to None
            if 'random' in options.keys():
                # set random=true to enable delay randomization
                self.random = (options['random'].lower() == 'true')
                if self.random and self.seconds is None:
                    # set a upper bound of 1s if seconds is not being used, otherwise keep the seconds value
                    self.seconds = 1.0

    def execute(self, data):
        delay = None
        if self.random:
            delay = round(random.uniform(0, self.seconds), 3)  # round to milliseconds
        else:
            delay = self.seconds
        # here delay is either None or a positive float
        # if the module was instantiated w/o either seconds or random, effectively nothing happens
        if delay is not None:
            if self.verbose:
                print(f"Waiting {delay}s.")
            time.sleep(delay)
        return data

    def help(self):
        h = '\tseconds: number of seconds you want the packet to be delayed\n'
        h += ('\trandom: optional; set to true to randomize the delay between 0 and seconds (default: 1.0s)\n')
        return h


if __name__ == '__main__':
    print('This module is not supposed to be executed alone!')
