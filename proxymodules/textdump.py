#!/usr/bin/env python3
import os.path as path
from codecs import decode


class Module:
    def __init__(self, incoming=False, verbose=False, options=None):
        # extract the file name from __file__. __file__ is proxymodules/name.py
        self.name = path.splitext(path.basename(__file__))[0]
        self.description = 'Simply print the received data as text'
        self.incoming = incoming  # incoming means module is on -im chain
        self.find = None  # if find is not None, this text will be highlighted
        if options is not None:
            if 'find' in options.keys():
                self.find = bytes(options['find'], 'ascii')  # text to highlight
            if 'color' in options.keys():
                self.color = bytes('\033[' + options['color'] + 'm', 'ascii')  # highlight color
            else:
                self.color = b'\033[31;1m'

    def execute(self, data):
        if self.find is None:
            print(repr(decode(data, 'raw_unicode_escape')))
        else:
            pdata = data.replace(self.find, self.color + self.find + b'\033[0m')
            print(repr(decode(pdata, 'raw_unicode_escape')))
        return data

    def help(self):
        h = '\tfind: string that should be highlighted\n'
        h += ('\tcolor: ANSI color code. Will be wrapped with \\033[ and m, so'
              ' passing 32;1 will result in \\033[32;1m (bright green)')
        return h


if __name__ == '__main__':
    print('This module is not supposed to be executed alone!')
