#!/usr/bin/env python2


class Module:
    def __init__(self):
        self.name = 'stripping fake HTTP Header'
        self.description = 'Simply adds a fake HTTP header. This is quite usefull if you want to inspect the payload in tools like BurpSuite'

    def execute(self, data):

    	print data
        if 'HTTP' in data:
	        data = data.split('\x0d\x0a\x0d\x0a')[1]

	        return data
	    
    	print 'no HTTP!!!'
    	return data

if __name__ == '__main__':
    print 'This module is not supposed to be executed alone!'
