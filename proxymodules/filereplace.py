#!/usr/bin/env python2

import os
import re


class Module:
    def __init__(self, incoming=False, verbose=False, options=None):
        # extract the file name from __file__. __file__ is proxymodules/name.py
        self.name = __file__.rsplit('/', 1)[1].split('.')[0]
        self.description = 'Replace text on the fly by using regular expressions in files'
        self.incoming = incoming  # incoming means module is on -im chain
        self.find = None  # if find is not None, this text will be highlighted
        if options is not None:
            self.search = options['search']
            self.replace = options['replace']
            try:
                f = open(self.search)
            except IOError:
                print("Search file not found. Use string '%s' for search string." % (self.search))
            try:
                open(self.replace)
            except IOError:
                print("Replace file not found. Use string '%s' for replace string." % (self.replace))

    def execute(self, data):
        '''
        If the argument is a text file in the current directory, then the content
        of the file will be used as search_string / replace_string.
        Otherwise the argument itself is the search_string / replace_string.
        This works also during a running tcpproxy process.
        '''
        listdir = os.listdir(".")

        try:
            f = open(self.replace,"r")
            replace_string = f.read()[:-1]
            f.close()
        except IOError:
            replace_string = self.replace

        try:
            f = open(self.search,"r")
            search_string = f.read()[:-1]
            f.close()
        except IOError:
            search_string = self.search
            
        results = re.findall(search_string, data)
        new_data = re.sub(search_string, replace_string, data)
        if not new_data == data:
            for finding in results:
                print("Replacing '%s' with '%s'" % (finding, replace_string))
        return new_data

    def help(self):
        h = '\tsearch: file which contains string that should be replaced\n'
        h += ('\treplace: file which contains value that it should be replaced with\n')
        h += ('\tExample: filereplace:search=searchstring.txt,replace=replacestring.txt')
        return h


if __name__ == '__main__':
    print 'This module is not supposed to be executed alone!'

