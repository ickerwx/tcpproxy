# tcpproxy.py - An intercepting proxy for TCP data
This tool opens a listening socket, receives data and then runs this data through a chain of proxy modules. After the modules are done, the resulting data is sent to the target server. The response is received and again run through a chain of modules before sending the final data back to the client.
To intercept the data, you will either have to be the gateway or do some kind of man-in-the-middle attack. Set up iptables so that the PREROUTING chain will modify the destination and send it to the proxy process. The proxy will then send the data on to whatever target was specified.

This tool is inspired by and partially based on the TCP proxy example used in Justin Seitz' book "Black Hat Python" by no starch press.

## Usage
```
$ ./tcpproxy.py -h
usage: tcpproxy.py [-h] -ti TARGET_IP -tp TARGET_PORT [-li LISTEN_IP]
                   [-lp LISTEN_PORT] [-om OUT_MODULES] [-im IN_MODULES] [-v]
                   [-n] [-l LOGFILE] [--list] [-lo HELP_MODULES] [-s]

Simple TCP proxy for data interception and modification. Select modules to
handle the intercepted traffic.

optional arguments:
  -h, --help            show this help message and exit
  -ti TARGET_IP, --targetip TARGET_IP
                        remote target IP
  -tp TARGET_PORT, --targetport TARGET_PORT
                        remote target port
  -li LISTEN_IP, --listenip LISTEN_IP
                        IP address to listen for incoming data
  -lp LISTEN_PORT, --listenport LISTEN_PORT
                        port to listen on
  -om OUT_MODULES, --outmodules OUT_MODULES
                        comma-separated list of modules to modify data before
                        sending to remote target.
  -im IN_MODULES, --inmodules IN_MODULES
                        comma-separated list of modules to modify data
                        received from the remote target.
  -v, --verbose         More verbose output of status information
  -n, --no-chain        Don't send output from one module to the next one
  -l LOGFILE, --log LOGFILE
                        Log all data to a file before modules are run.
  --list                list available modules
  -lo HELP_MODULES, --list-options HELP_MODULES
                        Print help of selected module
  -s, --ssl             detect SSL/TLS as well as STARTTLS, certificate is
                        mitm.pem
```

You will have to  provide TARGET_IP and TARGET_PORT, the default listening settings are 0.0.0.0:8080. To make the program actually useful, you will have to decide which modules you want to use on outgoing (client to server) and incoming (server to client) traffic. You can use different modules for each direction. Pass the list of modules as comma-separated list, e.g. -im mod1,mod4,mod2. The data will be passed to the first module, the returned data will be passed to the second module and so on, unless you use the -n/--no/chain switch. In that case, every module will receive the original data.
You can also pass options to each module: -im mod1:key1=val1,mod4,mod2:key1=val1:key2=val2. To learn which options you can pass to a module use -lo/--list-options like this: -lo mod1,mod2,mod4
## Modules
```
$ ./tcpproxy.py --list
hexdump - Print a hexdump of the received data
http_ok - Prepend HTTP response header
http_post - Prepend HTTP header
http_strip - Remove HTTP header from data
java_deserializer - Deserialization of Java objects (needs jython)
java_serializer - serialization of XStream XML data (needs jython)
log - Log data in the module chain. Use in addition to general logging (-l/--log).
removegzip - Replace gzip in the list of accepted encodings in a HTTP request with booo.
replace - Replace text by using regular expressions
textdump - Simply print the received data as text
```
Tcpproxy.py uses modules to view or modify the intercepted data. To see the possibly easiest implementation of a module, have a look at the textdump.py module in the proxymodules directory:
```python
#!/usr/bin/env python2


class Module:
    def __init__(self, incoming=False, options=None):
        # extract the file name from __file__. __file__ is proxymodules/name.py
        self.name = __file__.rsplit('/', 1)[1].split('.')[0]
        self.description = 'Simply print the received data as text'
        self.incoming = incoming  # incoming means module is on -im chain
        self.find = None  # if find is not None, this text will be highlighted
        if options is not None:
            if 'find' in options.keys():
                self.find = options['find']  # text to highlight
            if 'color' in options.keys():
                self.color = '\033[' + options['color'] + 'm'  # highlight color
            else:
                self.color = '\033[31;1m'

    def execute(self, data):
        if self.find is None:
            print data
        else:
            pdata = data.replace(self.find, self.color + self.find + '\033[0m')
            print pdata
        return data

    def help(self):
        h = '\tfind: string that should be highlighted\n'
        h += ('\tcolor: ANSI color code. Will be wrapped with \\033[ and m, so'
              ' passing 32;1 will result in \\033[32;1m (bright green)')
        return h


if __name__ == '__main__':
    print 'This module is not supposed to be executed alone!'
```
Every module file contains a class named Module. Every module MUST set self.description and MUST implement an execute method that accepts one parameter, the input data. The execute method MUST return something, this something is then either passed to the next module or sent on. Other than that, you are free to do whatever you want inside a module.
The incoming parameter in the constructor is set to True when the module is in the incoming chain (-im), otherwise it's False. This way, a module knows in which direction the data is flowing (credits to jbarg for this idea).
The options parameter is a dictionary with the keys and values passed to the module on the command line. Note that if you use the options dictionary in your module, you should also implement a help() method. This method must return a string. Use one line per option, make sure each line starts with a \t character for proper indentation.

See the hexdump module for an additional options example:
```python
#!/usr/bin/env python2


class Module:
    def __init__(self, incoming=False, options=None):
        # -- 8< --- snip
        self.len = 16
        if options is not None:
            if 'length' in options.keys():
                self.len = int(options['length'])

    def help(self):
        return '\tlength: bytes per line (int)'

    def execute(self, data):
        # -- 8< --- snip
        for i in xrange(0, len(data), self.len):
            s = data[i:i + self.len]
        # # -- 8< --- snip

if __name__ == '__main__':
    print 'This module is not supposed to be executed alone!'
```
The above example should give you an idea how to make use of module parameters. A calling example would be:
```
python2 tcpproxy.py -om hexdump:length=8,http_post,hexdump:length=12 -ti 127.0.0.1 -tp 12345
< < < < out: hexdump
0000   77 6C 6B 66 6A 6C 77 71    wlkfjlwq
0008   6B 66 6A 68 6C 6B 77 71    kfjhlkwq
0010   6A 65 68 66 6C 6B 65 77    jehflkew
0018   71 6A 66 68 6C 6B 65 77    qjfhlkew
0020   71 6A 66 68 6C 6B 65 77    qjfhlkew
0028   71 6A 66 6C 68 77 71 6B    qjflhwqk
0030   65 6A 66 68 77 71 6C 6B    ejfhwqlk
0038   65 6A 66 68 0A             ejfh.
< < < < out: http_post
< < < < out: hexdump
0000   50 4F 53 54 20 2F 20 48 54 54 50 2F    POST / HTTP/
000C   31 2E 31 0A 48 6F 73 74 3A 20 74 63    1.1.Host: tc
0018   70 70 72 6F 78 79 0A 43 6F 6E 74 65    pproxy.Conte
0024   6E 74 2D 4C 65 6E 67 74 68 3A 20 36    nt-Length: 6
0030   31 0A 0A 77 6C 6B 66 6A 6C 77 71 6B    1..wlkfjlwqk
003C   66 6A 68 6C 6B 77 71 6A 65 68 66 6C    fjhlkwqjehfl
0048   6B 65 77 71 6A 66 68 6C 6B 65 77 71    kewqjfhlkewq
0054   6A 66 68 6C 6B 65 77 71 6A 66 6C 68    jfhlkewqjflh
0060   77 71 6B 65 6A 66 68 77 71 6C 6B 65    wqkejfhwqlke
006C   6A 66 68 0A                            jfh.
```
You can see how the first hexdump instance gets a length of 8 bytes per row and the second instance gets a length of 12 bytes. To pass more than one option to a single module, seperate the options with a : character, modname:key1=val1:key2=val2...
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

Using this setup, you are able to take advantage of Burp's capabilities, like the repeater or intruder or simply use it for logging purposes. This was originally the idea of jbarg.

If you are doing automated modifications and have no need for interactivity, you can simply take advantage of the (de-)serialization modules by writing a module to work on the deserialized XML structure. Then plug your module into the chain by doing -im java_deserializer,your_module,java_serializer (or -om of course). This way you also only need one tcpproxy instance, of course.

Note that when using jython, the SSL mitm does not seem to work. It looks like a jython bug to me, but I haven't yet done extensive debugging so I can't say for sure.
##Logging
You can write all data that is sent or received by the proxy to a file using the -l/--log <filename> parameter. Data (and some housekeeping info) is written to the log before passing it to the module chains. If you want to log the state of the data during or after the modules are run, you can use the log proxymodule. Using the chain -im http_post,log:file=log.1,http_strip,log would first log the data after the http_post module to the logfile with the name log.1. The second use of the log module at the end of the chain would write the final state of the data to a logfile with the default name in-<timestamp> right before passing it on .
## TODO
- [X] implement a way to pass parameters to modules
- [X] implement logging (pre-/post modification)
- [ ] make the process interactive by implementing some kind of editor module (will probably complicate matters with regard to timeouts)
