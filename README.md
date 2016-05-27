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

## Modules
```
$ python2 tcpproxy.py -l
hexdump - Print a hexdump of the received data
http_get - Prepend HTTP header
http_ok - Prepend HTTP response header
http_strip - Remove HTTP header from data
java_deserializer - Deserialization of Java objects (needs jython)
java_serializer - serialization of XStream XML data (needs jython)
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
Every module file contains a class named Module. Every module MUST set self.description and MUST implement an execute method that accepts one parameter, the input data. The execute method MUST return something, this something is then either passed to the next module or sent on. Other than that, you are free to do whatever you want inside a module. Note that self.name will be removed in the near future since I am not using it.
## Deserializing and Serializing Java Objects to XML
Using the Java xstream libary, it is possible to deserialize intercepted serialised objects if the .jar with class definitions is known to tcpproxy.
```
CLASSPATH=./lib/* jython tcpproxy.py -ti 127.0.0.1 -tp 12346 -lp 12345 -om java_deserializer,textdump
```
If you would like to use a 3rd tool like BurpSuite to manipulate the XStream XML structure use this setup:
```

                                            +---------+
                                  +-------> |BurpSuite+-----+
                                  |         +---------+     |
                                  |                         V
+------------------+        +--------+--+                   +-----------+              +-----------+
| Java ThickClient +------> |1. tcpproxy|                   |2. tcpproxy+------------> |Java Server|
+------------------+        +-----------+                   +-----------+              +-----------+
```
The setup works like this: Let's say you want to intercept an manipulate serialized objects between the thick client and the Java server. The idea is to intercept serialized objects, turn them into XML (deserialize them), pipe them into another tool (BurpSuite in this example) where you manipulate the data, then take that data and send it to the server. The server replies with another object which is again deserialized into XML, fed to the tool and then serialized before sending the response to the client.
```
$ CLASSPATH=./lib/*:/pathTo/jarFiles/* jython27 tcpproxy.py -ti <burpIP> -tp <burpPort> -lp <ThickClientTargetPort> -om java_deserializer,http_post -im http_strip,java_serializer -t 0.1
```
The call above is for the first tcpproxy instance between the client and Burp (or whatever tool you want to use). The target IP is the IP Burp is using, target port tp is Burp's listening port. For listening IP li and listening port lp you either configure the client or do some ARP spoofing/iptables magic. With -om you prepare the data for burp. Since Burp only consumes HTTP, use the http_post module after the deserializer to prepend an HTTP header. Then manipulate the data within burp. Take care to configure Burp to redirect the data to the second tcpproxy instance's listen IP/listen port and enable invisible proxying.
Burp's response will be HTTP with an XML body, so in the incoming chain (-im) first strip the header (http_strip), then serialize the XML before the data is sent to the client.
```
$ CLASSPATH=./lib/*:/pathTo/jarFiles/* jython27 tcpproxy.py -ti <JavaServerIP> -tp <JavaServerPort> -lp <BurpSuiteTargetPort> -im java_deserializer,http_post -om http_strip,java_serializer -t 3
```
This is the second tcpproxy instance. Burp will send the data there if you correctly configured the request handling in Burp's proxy listener options. Before sending the data to the server in the outgoing chain (-om), first strip the HTTP header, then serialize the XML. The server's response will be handled by the incoming chain (-im), so deserialize it, prepend the HTTP header, then send the data to burp.

Using this setup, you are able to take advantage of Burp's capabilities, like the repeater or intruder or simply use it for logging purposes. This was originally the idea of @jbarg.

If you are doing automated modifications and have no need for interactivity, you can simply take advantage of the (de-)serialization modules by writing a module to work on the deserialized XML structure. Then plug your module into the chain by doing -im java_deserializer,your_module,java_serializer (or -om of course). This way you also only need one tcpproxy instance, of course.

Note that when using jython, the SSL mitm does not seem to work. It looks like a jython bug to me, but I haven't yet done extensive debugging so I can't say for sure.
## TODO
- implement a way to pass parameters to modules
- implement logging (pre-/post modification)
- make the process interactive by implementing some kind of editor module (will probably complicate matters with regard to timeouts)
