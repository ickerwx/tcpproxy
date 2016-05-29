#!/usr/bin/env python2


class Module:
    def __init__(self, incoming=False):
        self.name = 'Hexdump display'
        self.description = 'Print a hexdump of the received data'
        self.incoming = incoming  # incoming means module is on -im chain

    def execute(self, data):
        # this is a pretty hex dumping function directly taken from
        # http://code.activestate.com/recipes/142812-hex-dumper/
        result = []
        length = 16
        digits = 4 if isinstance(data, unicode) else 2

        for i in xrange(0, len(data), length):
            s = data[i:i + length]
            hexa = b' '.join(["%0*X" % (digits, ord(x)) for x in s])
            text = b''.join([x if 0x20 <= ord(x) < 0x7F else b'.' for x in s])
            result.append(b"%04X   %-*s   %s" % (i, length * (digits + 1),
                          hexa, text))

        print b'\n'.join(result)
        return data

if __name__ == '__main__':
    print 'This module is not supposed to be executed alone!'
