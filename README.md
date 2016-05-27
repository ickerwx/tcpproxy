# tcpproxy.py - An intercepting proxy for TCP data
This tool opens a listening socket, receives data and then runs this data through a chain of proxy modules. After the modules are done, the resulting data is sent to the target server. The response is received and again run through a chain of modules before sending the final data back to the client.
To intercept the data, you will either have to be the gateway or do some kind of man-in-the-middle attack. Set up iptables so that the PREROUTING chain will modify the destination and send it to the proxy process. The proxy will then send the data on to whatever target was specified.

This tool is inspired and partially based on the TCP proxy example used in Justin Seitz' book "Black Hat Python" by no starch press.

## Usage

```
$ python2 tcpproxy.py -h
usage: tcpproxy.py [-h] [-li LISTEN_IP] [-ti TARGET_IP] [-lp LISTEN_PORT]
                   [-tp TARGET_PORT] [-om OUT_MODULES] [-im IN_MODULES]
                   [-t TIMEOUT] [-v] [-r] [-n] [-l] [-s]

Simple TCP proxy for data interception and modification. Select modules to
handle the intercepted traffic.

optional arguments:
  -h, --help            show this help message and exit
  -li LISTEN_IP, --listenip LISTEN_IP
                        IP address to listen for incoming data
  -ti TARGET_IP, --targetip TARGET_IP
                        remote target IP
  -lp LISTEN_PORT, --listenport LISTEN_PORT
                        port to listen on
  -tp TARGET_PORT, --targetport TARGET_PORT
                        remote target port
  -om OUT_MODULES, --outmodules OUT_MODULES
                        comma-separated list of modules to modify data before
                        sending to remote target.
  -im IN_MODULES, --inmodules IN_MODULES
                        comma-separated list of modules to modify data
                        received from the remote target.
  -t TIMEOUT, --timeout TIMEOUT
                        Socket timeout to wait for incoming data
  -v, --verbose         More verbose output of status information
  -r, --receivefirst    Receive data from remote first, e.g. a banner
  -n, --no-chain        Don't send output from one module to the next one
  -l, --list            list available modules
  -s, --ssl             use SSL, certificate is mitm.pem
```

You will have to  provide TARGET_IP and TARGET_PORT, the default listening settings are 0.0.0.0:8080. To make the program actually useful, you will have to decide which modules you want to use on outgoing (client to server) and incoming (server to client) traffic. You can use different modules for each direction. Pass the list of modules as comma-separated list, e.g. -im mod1,mod4,mod2. The data will be passed to the first module, the returned data will be passed to the second module and so on, unless you use the -n/--no/chain switch. In that case, every module will receive the original data.

### Modules

```
$ python2 tcpproxy.py -l
deserializer - Deserialize Java objects (needs jython)
hexdump - Print a hexdump of the received data
httpparser - Check if data is HTTP and try to parse it
removegzip - Replace gzip in the list of accepted encodings in a HTTP request with booo.
textdump - Simply print the received data as text
all - use all available modules
```
Tcpproxy.py uses modules to view or modify the intercepted data. To see the possibly easiest implementation of a module, have a look at the textdump.py module in the proxymodules directory:

```
#!/usr/bin/env python2


class Module:
    def __init__(self):
        self.name = 'Text display'
        self.description = 'Simply print the received data as text'

    def execute(self, data):
        print data
        return data

if __name__ == '__main__':
    print 'This module is not supposed to be executed alone!'
```

Every module file contains a class named Module. Every module MUST set self.description and MUST implement an execute method that accepts one paramter, the input data. The execute method MUST return something, this something is then either passed to the next module or sent on. Other than that, you are free to do whatever you want inside a module.

### Playing with Java objects
The deserializer module implements a way to alter serialized java objects on the fly. To use it, change the CLASSPATH env variable to make sure the custom classes are available to your code.
```
CLASSPATH=$CLASSPATH:/home/user/test/Someclass.jar jython27 tcpproxy.py -ti 127.0.0.1 -tp 12346 -lp 12345 -om hexdump,deserializer,hexdump
```
Note that when using jython, the SSL mitm does not seem to work. It looks like a jython bug to me, but I haven't yet done extensive debugging so I can't say for sure.

### Deserializing and Serializing Java Objects to XML
Using the Java xstream libary, it is possible to deserialize intercepted serialised objects if the .jar with class definitions is known by tcpproxy.
```
CLASSPATH=/pathTo/xstream/libary/*:/pathTo/jarFiles/* jython 27 tcpproxy.py -ti 127.0.0.1 -tp 12346 -lp 12345 -om java_deserial,textdump
```
If you would like to use a 3rd tool like BurpSuite to manipulate the XStream XML structure use this setup:
```

                                            +---------+
                                  +-------> |BurpSuite+-----+
                                  |         +---------+     v
                                  |
+------------------+        +--------+--+                   +-----------+              +-----------+
| Java ThickClient +------> |1. tcpproxy|                   |2. tcpproxy+------------> |Java Server|
+------------------+        +-----------+                   +-----------+              +-----------+
```
Example for the tcpproxy parameters:
```
1.tcpproxy$ CLASSPATH=/pathTo/xstream/libary/*:/pathTo/jarFiles/* jython 27 tcpproxy.py -ti 127.0.0.1 -tp <burpPort> -lp <ThickClientTargetPort> -om java_deserial,http_get -im http_strip,java_serial -t 0.1
2.tcpproxy$ CLASSPATH=/pathTo/xstream/libary/*:/pathTo/jarFiles/* jython 27 tcpproxy.py -ti 127.0.0.1 -tp <JavaServerPort> -lp <BurpSuiteTargetPort> -om http_strip,java_serial -im java_deserial,http_ok -t 0.1

```




## TODO
- implement a way to pass parameters to modules
- implement logging (pre-/post modification)
- make the process interactive by implementing some kind of editor module (will probably complicate matters with regard to timeouts)
