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
        self.name = 'java serialization'
        self.description = 'serialization' if self.is_jython else \
                           'serialization (needs jython)'
        

    def execute(self, data):
        # this is a quick and dirty PoC to show that jython can be used to
        # deserialize Java objects on the fly, manipulate them and send them
        # on their way.
        
        if not self.is_jython:
            print '[!] This module can only be used in jython!'
            return data

        # Creating XStream object and creating Java object from XML structure
        xs = XStream()
        serial = xs.fromXML(data)        
        
        # writing created Java object to and serializing it with ObjectOutputStream
        bos = io.ByteArrayOutputStream()
        oos = io.ObjectOutputStream(bos)
        oos.writeObject(serial)

        # I had a problem with signed vs. unsigned bytes, hence the & 0xff
        return "".join([chr(x & 0xff) for x in bos.toByteArray().tolist()])


if __name__ == '__main__':
    print 'This module is not supposed to be executed alone!'

