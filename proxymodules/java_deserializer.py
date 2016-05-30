#!/usr/bin/env python2
# -*- coding: utf-8 -*-
import platform
if 'java' in platform.system().lower():
    import java.io as io
    from com.thoughtworks.xstream import XStream


class Module:
    def __init__(self, incoming=False, options=None):
        self.is_jython = 'java' in platform.system().lower()
        # extract the file name from __file__. __file__ is proxymodules/name.py
        self.name = __file__.rsplit('/', 1)[1].split('.')[0]
        self.description = 'Deserialization of Java objects' if self.is_jython else \
                           'Deserialization of Java objects (needs jython)'
        self.incoming = incoming  # incoming means module is on -im chain

    def execute(self, data):
        if not self.is_jython:
            print '[!] This module can only be used in jython!'
            return data

        # turn data into a Java object
        bis = io.ByteArrayInputStream(data)
        ois = io.ObjectInputStream(bis)
        obj = ois.readObject()

        # converting Java object to XML structure
        xs = XStream()
        xml = xs.toXML(obj)
        return xml

if __name__ == '__main__':
    print 'This module is not supposed to be executed alone!'
