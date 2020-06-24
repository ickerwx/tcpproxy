# tcpproxy.py - An intercepting proxy for TCP data

This tool opens a listening socket, receives data and then runs this data through a chain of proxy modules. After the modules are done, the resulting data is sent to the target server. The response is received and again run through a chain of modules before sending the final data back to the client.
To intercept the data, you will either have to be the gateway or do some kind of man-in-the-middle attack. Set up iptables so that the PREROUTING chain will modify the destination and send it to the proxy process. The proxy will then send the data on to whatever target was specified.

This tool is inspired by and partially based on the TCP proxy example used in Justin Seitz' book "Black Hat Python" by no starch press.

## Usage

```
$ ./tcpproxy.py -h
usage: tcpproxy.py [-h] [-ti TARGET_IP] [-tp TARGET_PORT] [-li LISTEN_IP] [-lp LISTEN_PORT] [-om OUT_MODULES]
                   [-im IN_MODULES] [-v] [-n] [-l LOGFILE] [--list] [-lo HELP_MODULES] [-r RULES]

Simple TCP proxy for data interception and modification. Select modules to handle the intercepted traffic.

optional arguments:
  -h, --help            show this help message and exit
  -ti TARGET_IP, --targetip TARGET_IP
                        remote target IP or host name (none for transparent proxying based on iptable)
  -tp TARGET_PORT, --targetport TARGET_PORT
                        remote target port
  -li LISTEN_IP, --listenip LISTEN_IP
                        IP address/host name to listen for incoming data
  -lp LISTEN_PORT, --listenport LISTEN_PORT
                        port to listen on
  -om OUT_MODULES, --outmodules OUT_MODULES
                        comma-separated list of modules to modify data before sending to remote target.
  -im IN_MODULES, --inmodules IN_MODULES
                        comma-separated list of modules to modify data received from the remote target.
  -v, --verbose         More verbose output of status information
  -n, --no-chain        Don't send output from one module to the next one
  -l LOGFILE, --log LOGFILE
                        Log all data to a file before modules are run.
  --list                list available modules
  -lo HELP_MODULES, --list-options HELP_MODULES
                        Print help of selected module
  -r RULES, --rules RULES
                        Use a json module ruleset loaded from an URL instead of -im or -om
```

You will have to  provide TARGET_IP and TARGET_PORT, the default listening settings are 0.0.0.0:8080. To make the program actually useful, you will have to decide which modules you want to use on outgoing (client to server) and incoming (server to client) traffic. You can use different modules for each direction. Pass the list of modules as comma-separated list, e.g. -im mod1,mod4,mod2. The data will be passed to the first module, the returned data will be passed to the second module and so on, unless you use the -n/--no/chain switch. In that case, every module will receive the original data.
You can also pass options to each module: -im mod1:key1=val1,mod4,mod2:key1=val1:key2=val2. To learn which options you can pass to a module use -lo/--list-options like this: -lo mod1,mod2,mod4

### Transparent proxy

Transparent proxying will be enabled if no targetip / targetport option is provided. In transparent proxying, TCPProxy will lookup the NAT table to identify the actual target IP.

Of course transparent proxying only works if you are using linux NAT features such as (IPTables/NFT...):

`iptables -t nat -A PREROUTING [-d TARGET_IP] -p tcp [--dport TARGET_PORT] --to-port TCPProxy_LISTEN_PORT -j REDIRECT`

You are also responsible of doing a proper setup for NAT Forwarding. For instance if you which to forward all traffic coming from a given IP range to your system:

`iptables -t nat -A POSTROUTING -s 10.0.0.0/24 -j MASQUERADE`

`sysctl net.ipv4.ip_forward=1`

The mitmproxy project provide a great documentation on different possible network setup:

[https://docs.mitmproxy.org/stable/concepts-modes/]

### Client/Server mode

Client Server mode can be achieved by using the different redis based plugins such as `stats`, `debug`, `intercept`.

For example we recommend using `peek_sni` `peek_host` `stats` to get some feedback on traffic going through TCPProxy.

Redis needs to be installed on the TCPProxy system in order for this to work. Just install a redis package and start the redis service.

Eventually, you need to ensure that redis listen to 0.0.0.0 if you want to use the client from a different system.

When you are ready, run TCPProxy with the ruleset URL pointing to your redis instance:

`tcpproxy.py -v --rules redis://localhost`

You can now run the TCPProxy client CLI (CLI has dependencies requirements on python-redis and python-hexdump) or GUI (GUI have additionnal dependencies requirements on PyQT5 and python-difflib)

`tcpproxy_cli.py YourRedisInstanceIP --rules`

`tcpproxy_gui.py YourRedisInstanceIP`

## Modules

```
$ ./tcpproxy.py --list
debug - Send received data in redis debug PubSub
digestdowngrade - Find HTTP Digest Authentication and replace it with a Basic Auth
	realm: use this instead of the default "tcpproxy"

hexdump - Print a hexdump of the received data
	length: bytes per line (int)
http_ok - Prepend HTTP response header
	server: remote source, used in response Server header

http_post - Prepend HTTP header
	host: remote target, used in request URL and Host header
	port: remote target port, used in request URL

http_strip - Remove HTTP header from data
javaxml - Serialization or deserialization of Java objects (needs jython)
	mode: [serial|deserial] select deserialization (to XML) or serialization (to Java object)
log - Log data in the module chain. Use in addition to general logging (-l/--log).
	file: name of logfile
peek_httphost - Retrieve hostname from HTTP Host
peek_sni-MISSING DEPENDENCY - Missing dependencies for module: scapy
	Retrieve hostname from TLS/SSL ClientHello SNI
peek_ssl - Find if connection is based on SSL by seaching for SSL/TLS Client Hello
proxy-MISSING DEPENDENCY - Missing dependencies for module: proxy host,proxy port,socks
	Redirect trafic using a HTTP or SOCKS proxy
	host: the host to proxy trafic through
	port: the proxy listening port
	type: the proxy type: HTTP (default), SOCKS4, SOCKS5

redirect - Redirect trafic to another server through a new TCP socket
	host: the host to redirect trafic to (default to same host than connection)
	port: the port to redirect trafic to (default to same port than connection)
	ssl: connect to server using SSL

removegzip - Replace gzip in the list of accepted encodings in a HTTP request with booo.
replace - Replace text on the fly by using regular expressions in a file or as module parameters
	search: string or regular expression to search for
	replace: string the search string should be replaced with
	file: file containing search:replace pairs, one per line
	separator: define a custom search:replace separator in the file, e.g. search#replace

	Use at least file or search and replace (or both).

size - Print the size of the data passed to the module
	verbose: override the global verbosity setting
size404 - Change HTTP responses of a certain size to 404.
	size: if a response has this value as content-length, it will become a 404
	verbose: print a message if a string is replaced
	custom: path to a file containing a custom response, will replace the received response
	rewriteall: if set, it will rewrite all responses. Default is to let the first on through	reset: number of seconds after which we will reset the state and will let the next response through.
sslupgrade - Upgrade connection to SSL automatically if requested by the client (ClientHello)
	mode: certificate generation mode (newly generated certificates will be cached into redis) : file(default),fake,spoof,cafake,caspoof,ca
	file: where to load the certificate and key from in static mode (default:mitm.pem)
	cn: force certificate CN
	version: use TLS version (PROTOCOL_SSLv2, PROTOCOL_SSLv3, PROTOCOL_TLSv1, PROTOCOL_TLSv1_1, PROTOCOL_TLSv1_2)
	show: show selected ciphers and client certificate requests
	server_version: use TLS version for server (PROTOCOL_SSLv23, PROTOCOL_SSLv2 ...)
	ignore_servfail: ignore server connection failure
	nocache: disable caching on redis

stats - Send statistics to redis db
textdump - Simply print the received data as text
	find: string that should be highlighted
	color: ANSI color code. Will be wrapped with \033[ and m, so passing 32;1 will result in \033[32;1m (bright green)
```

Tcpproxy.py uses modules to view or modify the intercepted data. To see the more documentation about implementation of a module, have a look at [API.md]:

```python
#!/usr/bin/env python3
import os.path as path


class Module:
    def __init__(self, incoming=False, verbose=False, options=None):
        # extract the file name from __file__. __file__ is proxymodules/name.py
        self.name = path.splitext(path.basename(__file__))[0]
        self.description = 'Simply print the received data as text'
        self.incoming = incoming  # incoming means module is on -im chain
        self.find = None  # if find is not None, this text will be highlighted
        if options is not None:
            if 'find' in options.keys():
                self.find = bytes(options['find'], 'ascii')  # text to highlight
            if 'color' in options.keys():
                self.color = bytes('\033[' + options['color'] + 'm', 'ascii')  # highlight color
            else:
                self.color = b'\033[31;1m'

    def execute(self, data):
        if self.find is None:
            print(data)
        else:
            pdata = data.replace(self.find, self.color + self.find + b'\033[0m')
            print(pdata.decode('ascii'))
        return data

    def help(self):
        h = '\tfind: string that should be highlighted\n'
        h += ('\tcolor: ANSI color code. Will be wrapped with \\033[ and m, so'
              ' passing 32;1 will result in \\033[32;1m (bright green)')
        return h


if __name__ == '__main__':
    print('This module is not supposed to be executed alone!')
```

Every module file contains a class named Module. Every module MUST set self.description and MUST implement an execute method that accepts one parameter, the input data. The execute method MUST return something, this something is then either passed to the next module or sent on. Other than that, you are free to do whatever you want inside a module.
The incoming parameter in the constructor is set to True when the module is in the incoming chain (-im), otherwise it's False. This way, a module knows in which direction the data is flowing (credits to jbarg for this idea).
The verbose parameter is set to True if the proxy is started with -v/--verbose.
The options parameter is a dictionary with the keys and values passed to the module on the command line. Note that if you use the options dictionary in your module, you should also implement a help() method. This method must return a string. Use one line per option, make sure each line starts with a \t character for proper indentation.

See the hexdump module for an additional options example:

```python
#!/usr/bin/env python3
import os.path as path


class Module:
    def __init__(self, incoming=False, verbose=False, options=None):
        # extract the file name from __file__. __file__ is proxymodules/name.py
        self.name = path.splitext(path.basename(__file__))[0]
        self.description = 'Print a hexdump of the received data'
        self.incoming = incoming  # incoming means module is on -im chain
        self.len = 16
        if options is not None:
            if 'length' in options.keys():
                self.len = int(options['length'])

    def help(self):
        return '\tlength: bytes per line (int)'

    def execute(self, data):
        # -- 8< --- snip
        for i in range(0, len(data), self.len):
            s = data[i:i + self.len]
        # # -- 8< --- snip

if __name__ == '__main__':
    print 'This module is not supposed to be executed alone!'
```

The above example should give you an idea how to make use of module parameters. A calling example would be:

```
./tcpproxy.py -om hexdump:length=8,http_post,hexdump:length=12 -ti 127.0.0.1 -tp 12345
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

**Note: at present this does not work due to changes that made the code not compatible with Jython's `socket` implementation. If Java deserialization is what you are looking for: the last compatible commit is e3290261.**

Using the Java xstream libary, it is possible to deserialize intercepted serialised objects if the .jar with class definitions is known to tcpproxy.

```
CLASSPATH=./lib/* jython tcpproxy.py -ti 127.0.0.1 -tp 12346 -lp 12345 -om javaxml:mode=deserial,textdump
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
$ CLASSPATH=./lib/*:/pathTo/jarFiles/* jython27 tcpproxy.py -ti <burpIP> -tp <burpPort> -lp <ThickClientTargetPort> -om javaxml:mode=deserial,http_post -im http_strip,javaxml:mode=serial
```
The call above is for the first tcpproxy instance between the client and Burp (or whatever tool you want to use). The target IP is the IP Burp is using, target port tp is Burp's listening port. For listening IP li and listening port lp you either configure the client or do some ARP spoofing/iptables magic. With -om you prepare the data for burp. Since Burp only consumes HTTP, use the http_post module after the deserializer to prepend an HTTP header. Then manipulate the data within burp. Take care to configure Burp to redirect the data to the second tcpproxy instance's listen IP/listen port and enable invisible proxying.
Burp's response will be HTTP with an XML body, so in the incoming chain (-im) first strip the header (http_strip), then serialize the XML before the data is sent to the client.
```
$ CLASSPATH=./lib/*:/pathTo/jarFiles/* jython27 tcpproxy.py -ti <JavaServerIP> -tp <JavaServerPort> -lp <BurpSuiteTargetPort> -im javaxml:mode=deserial,http_ok -om http_strip,javaxml:mode=serial
```
This is the second tcpproxy instance. Burp will send the data there if you correctly configured the request handling in Burp's proxy listener options. Before sending the data to the server in the outgoing chain (-om), first strip the HTTP header, then serialize the XML. The server's response will be handled by the incoming chain (-im), so deserialize it, prepend the HTTP response header, then send the data to burp.

Using this setup, you are able to take advantage of Burp's capabilities, like the repeater or intruder or simply use it for logging purposes. This was originally the idea of jbarg.

If you are doing automated modifications and have no need for interactivity, you can simply take advantage of the (de-)serialization modules by writing a module to work on the deserialized XML structure. Then plug your module into the chain by doing -im java_deserializer,your_module,java_serializer (or -om of course). This way you also only need one tcpproxy instance, of course.

Note that when using jython, the SSL mitm does not seem to work. It looks like a jython bug to me, but I haven't yet done extensive debugging so I can't say for sure.

## Logging

You can write all data that is sent or received by the proxy to a file using the -l/--log <filename> parameter. Data (and some housekeeping info) is written to the log before passing it to the module chains. If you want to log the state of the data during or after the modules are run, you can use the log proxymodule. Using the chain -im http_post,log:file=log.1,http_strip,log would first log the data after the http_post module to the logfile with the name log.1. The second use of the log module at the end of the chain would write the final state of the data to a logfile with the default name in-<timestamp> right before passing it on .

## TODO

- [ ] make the process interactive by implementing some kind of editor module (will probably complicate matters with regard to timeouts, can be done for now by using the burp solution detailed above and modifying data inside burp)
- [ ] Create and maintain a parallel branch that is compatible with jython but also has most of the new stuff introduced after e3290261

## Contributions

I want to thank the following people for spending their valuable time and energy on improving this little tool:

- [Adrian Vollmer](https://github.com/AdrianVollmer)
- [Michael Füllbier](https://github.com/mfuellbier)
- [Stefan Grönke](https://github.com/gronke)
- [Mattia](https://github.com/sowdust)
- [bjorns163](https://github.com/bjorns163)
