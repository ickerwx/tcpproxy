#!/usr/bin/env python2
# -*- coding: utf-8 -*-
import platform
if 'java' in platform.system().lower():
    import java.io as io
    import java.lang.reflect.Modifier as Modifier

    from com.thoughtworks.xstream import XStream
    
class Module:
    """
    This is a quick PoC and definitely needs to be modified to be useful.
    """
    def __init__(self):
        self.is_jython = 'java' in platform.system().lower()
        self.name = 'Java Deserialization'
        self.description = 'Deserialization' if self.is_jython else \
                           'Deserialization (needs jython)'
        

    def execute(self, data):
        # this is a quick and dirty PoC to show that jython can be used to
        # deserialize Java objects on the fly, manipulate them and send them
        # on their way.
        
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
