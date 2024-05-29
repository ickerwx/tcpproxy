#!/usr/bin/env python3
import os
import re


class Module:
    def __init__(self, incoming=False, verbose=False, options=None):
        # extract the file name from __file__. __file__ is proxymodules/name.py
        self.name = os.path.splitext(os.path.basename(__file__))[0]
        self.description = 'Replace hex data on the fly defining search and replace-pairs in a file or as module parameters'
        self.verbose = verbose
        self.search = None
        self.replace = None
        self.filename = None
        self.separator = ':'
        self.len = 16

        if options is not None:
            if 'search' in options.keys():
                search = bytes.fromhex(options['search'])
            if 'replace' in options.keys():
                replace = bytes.fromhex(options['replace'])
            if 'file' in options.keys():
                self.filename = options['file']
                try:
                    open(self.filename)
                except IOError as ioe:
                    print("Error opening %s: %s" % (self.filename, ioe.strerror))
                    self.filename = None
            if 'separator' in options.keys():
                self.separator = options['separator']

        self.pairs = []  # list of (search, replace) tuples
        if search is not None and replace is not None:
            self.pairs.append((search, replace))

        if self.filename is not None:
            for line in open(self.filename).readlines():
                try:
                    search, replace = line.split(self.separator, 1)
                    self.pairs.append((bytes.fromhex(search.strip()), bytes.fromhex(replace.strip())))
                except ValueError:
                    # line does not contain separator and will be ignored
                    pass

    def hexdump(self, data):
        result = []
        digits = 2
        for i in range(0, len(data), self.len):
            s = data[i:i + self.len]
            hexa = ' '.join(['%0*X' % (digits, x) for x in s])
            text = ''.join([chr(x) if 0x20 <= x < 0x7F else '.' for x in s])
            result.append("%04X   %-*s   %s" % (i, self.len * (digits + 1), hexa, text))
        print("\n".join(result))

    def execute(self, data):
        #self.hexdump(data)
        print(f"Incoming packet with size {len(data)}:")
        for search, replace in self.pairs:
            #print(f"{search} -> {replace}")
            if search in data:
                print("########## data found ###########")
                print("[Before:]")
                self.hexdump(data)
                data = data.replace(search, replace)
                print("[After:]")
                self.hexdump(data)
        return data

    def help(self):
        h = '\tsearch: hex string (i.e. "deadbeef") to search for\n'
        h += ('\treplace: hex string the search string should be replaced with\n')
        h += ('\tfile: file containing search:replace pairs, one per line\n')
        h += ('\tseparator: define a custom search:replace separator in the file, e.g. search#replace\n')
        h += ('\n\tUse at least file or search and replace (or both).\n')
        return h


if __name__ == '__main__':
    print('This module is not supposed to be executed alone!')
