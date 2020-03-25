#!/usr/bin/env python2
import os.path as path


class Module:
    def __init__(self, incoming=False, verbose=False, options=None):
        # extract the file name from __file__. __file__ is proxymodules/name.py
        self.name = path.splitext(path.basename(__file__))[0]
        self.description = 'Replace gzip in the list of accepted encodings ' \
                           'in a HTTP request with booo.'
        self.incoming = incoming  # incoming means module is on -im chain
        # I chose to replace gzip instead of removing it to keep the parsing
        # logic as simple as possible.

    def execute(self, data):
        try:
            # split at \r\n\r\n to split the request into header and body
            header, body = data.split('\r\n\r\n', 1)
        except ValueError:
            # no \r\n\r\n, so probably not HTTP, we can go now
            return data
        # now split the header string into its lines
        headers = header.split('\r\n')

        for h in headers:
            if h.lower().startswith('accept-encoding:') and 'gzip' in h:
                headers[headers.index(h)] = h.replace('gzip', 'booo')
                break

        return '\r\n'.join(headers) + '\r\n\r\n' + body


if __name__ == '__main__':
    print ('This module is not supposed to be executed alone!')
