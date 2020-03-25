#!/usr/bin/env python3
import os.path as path
import time


class Module:
    def __init__(self, incoming=False, verbose=False, options=None):
        # extract the file name from __file__. __file__ is proxymodules/name.py
        self.name = path.splitext(path.basename(__file__))[0]
        self.description = 'Change HTTP responses of a certain size to 404.'
        self.incoming = incoming  # incoming means module is on -im chain
        self.size = 2392  # if a response has this value as content-length, it will become a 404
        self.verbose = False
        self.custom = False
        self.rewriteall = False  # will we block the first occurence?
        self.firstfound = False  # have we found the first occurence yet?
        self.resetinterval = None # if we haven't found a fitting response in this many seconds, reset the state and set first to False again
        self.timer = time.time()
        if options is not None:
            if 'size' in options.keys():
                try:
                    self.size = int(options['size'])
                except ValueError:
                    pass  # use the default if you can't parse the parameter
            if 'verbose' in options.keys():
                self.verbose=True
            if 'custom' in options.keys():
                try:
                    with open(options['custom'], 'r') as handle:
                        self.custom = handle.read()
                except Exception as e:
                    print 'Can\'t open custom error file, not using it.'
                    self.custom = False
            if 'rewriteall' in options.keys():
                self.rewriteall=True
            if 'reset' in options.keys():
                try:
                    self.resetinterval = float(options['reset'])
                except ValueError:
                    pass  # use the default if you can't parse the parameter


    def execute(self, data):
        contentlength = 'content-length: ' + str(self.size)
        if self.resetinterval is not None:
            t = time.time()
            if t - self.timer >= self.resetinterval:
                if self.verbose:
                    print 'Timer elapsed'
                self.firstfound = False
            self.timer = t
        if data.startswith('HTTP/1.1 200 OK') and contentlength in data.lower():
            if self.rewriteall is False and self.firstfound is False:
                # we have seen this response size for the first time and are not blocking the first one
                self.firstfound = True
                if self.verbose:
                    print 'Letting this response through'
                return data
            if self.custom is not False:
                data = self.custom
                if self.verbose:
                    print 'Replaced response with custom response'
            else:
                data = data.replace('200 OK', '404 Not Found', 1)
                if self.verbose:
                    print 'Edited return code'
        return data

    def help(self):
        h = '\tsize: if a response has this value as content-length, it will become a 404\n'
        h += ('\tverbose: print a message if a string is replaced\n'
              '\tcustom: path to a file containing a custom response, will replace the received response\n'
              '\trewriteall: if set, it will rewrite all responses. Default is to let the first on through'
              '\treset: number of seconds after which we will reset the state and will let the next response through.')
        return h


if __name__ == '__main__':
    print 'This module is not supposed to be executed alone!'