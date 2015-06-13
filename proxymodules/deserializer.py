#!/usr/bin/env python2
# -*- coding: utf-8 -*-
import platform
if 'java' in platform.system().lower():
    import java.io as io
    import java.lang.reflect.Modifier as Modifier


class Module:
    """
    This is a quick PoC and definitely needs to be modified to be useful.
    """
    def __init__(self):
        self.is_jython = 'java' in platform.system().lower()
        self.name = 'Number Changer'
        self.description = 'Deserialize Java objects' if self.is_jython else \
                           'Deserialize Java objects (needs jython)'

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
        # at this point you have the deserialized object in obj, do what you
        # want. Set the jython classpath to include custom classes and cast obj

        mod = Modifier()
        # get all methods of the object
        print type(obj)
        methods = obj.getClass().getDeclaredMethods()
        print "Object is of class " + obj.getClass().getName()
        print "Methods:"
        for m in methods:
            print "\t%s %s %s(%s)" % (mod.toString(m.getModifiers()),
                                      m.getGenericReturnType(),
                                      m.getName(),
                                      m.getGenericParameterTypes().tolist())

        declared_fields = obj.getClass().getDeclaredFields()
        print "Fields:"
        for f in declared_fields:
            if not f.isAccessible():
                f.setAccessible(True)
            print "\t%s %s %s => %s" % (mod.toString(f.getModifiers()),
                                        f.getType(), f.getName(), f.get(obj))

        # serialize the object again and turn it into a string again
        bos = io.ByteArrayOutputStream()
        oos = io.ObjectOutputStream(bos)
        oos.writeObject(obj)

        # I had a problem with signed vs. unsigned bytes, hence the & 0xff
        return "".join([chr(x & 0xff) for x in bos.toByteArray().tolist()])

if __name__ == '__main__':
    print 'This module is not supposed to be executed alone!'
