#!/usr/bin/env python3
import os.path as path


class Module:
    def __init__(self, incoming=False, verbose=False, options=None):
        # extract the file name from __file__. __file__ is proxymodules/name.py
        self.name = path.splitext(path.basename(__file__))[0]
        self.description = 'Change HTTP responses of a certain size to 404.'
        self.incoming = incoming  # incoming means module is on -im chain
        self.size = 2392  # if a response has this value as content-length, it will become a 404
        self.verbose = False
        if options is not None:
            if 'size' in options.keys():
                try:
                    self.size = int(options['size'])
                except ValueError:
                    pass  # use the default if you can't parse the parameter
            if 'verbose' in options.keys():
                self.verbose=True


    def execute(self, data):
        contentlength = 'content-length: ' + str(self.size)
        if data.startswith('HTTP/1.1 200 OK') and contentlength in data.lower():
            data = data.replace('200 OK', '404 Not Found', 1)
            print 'Edited return code'
        return data

    def help(self):
        return '\tsize: if a response has this value as content-length, it will become a 404\n\tverbose: print a message if a string is replaced'


if __name__ == '__main__':
    print 'This module is not supposed to be executed alone!'
