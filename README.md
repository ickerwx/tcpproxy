# tcpproxy.py - An intercepting proxy for TCP data

This tool opens a listening socket, receives data and then runs this data through a chain of proxy modules. After the modules are done, the resulting data is sent to the target server. The response is received and again run through a chain of modules before sending the final data back to the client.

To intercept the data, you have several options:

* Your tcpproxy system have to be the gateway or do some kind of man-in-the-middle attack;
* Set up iptables so that the PREROUTING chain will modify the destination and send it to the proxy process;
* Configure tcpproxy listener as SOCKS and forward traffic through a SOCKS enabled client (experimental).

The data will be forwarded to the server depending on your configuration:

* If you setup a destination ip/port in command line arguments, it will send traffic to the selected IP;
* If you did not setup a destination ip, it will try to retrieve destinable from linux NAT tables (transparent proxying);
* If the listener is configured as SOCKS it will retrieve the proper destination from the SOCKS initialisation packets;
* As an option, several plugins are actively redirecting selected traffic. Check the documentation for these plugins.

This tool is inspired by and partially based on the TCP proxy example used in Justin Seitz' book "Black Hat Python" by no starch press.

The client/server, GUI, and rule based mechanism (all EXPERIMENTAL) are inspired by Mallory - MiTM TCP and UDP Proxy (https://github.com/intrepidusgroup/mallory).

## Usage

```
$ ./tcpproxy.py -h
usage: tcpproxy.py [-h] [-ti TARGET_IP] [-tp TARGET_PORT] [-li LISTEN_IP]
                   [-lp LISTEN_PORT] [-om OUT_MODULES] [-im IN_MODULES] [-n]
                   [-l {DEBUG,INFO,WARNING,ERROR,CRITICAL,TRACE}]
                   [-lc LOG_CONFIG] [--list] [-lo HELP_MODULES] [-r RULES]
                   [-t TIMEOUT] [--protocol {TCP,SOCKS}]

Simple TCP proxy for data interception and modification. Select modules to
handle the intercepted traffic.

optional arguments:
  -h, --help            show this help message and exit
  -ti TARGET_IP, --targetip TARGET_IP
                        remote target IP or host name (none for transparent
                        proxying based on iptable)
  -tp TARGET_PORT, --targetport TARGET_PORT
                        remote target port
  -li LISTEN_IP, --listenip LISTEN_IP
                        IP address/host name to listen for incoming data
  -lp LISTEN_PORT, --listenport LISTEN_PORT
                        port to listen on
  -om OUT_MODULES, --outmodules OUT_MODULES
                        comma-separated list of modules to modify data before
                        sending to remote target.
  -im IN_MODULES, --inmodules IN_MODULES
                        comma-separated list of modules to modify data
                        received from the remote target.
  -n, --no-chain        Don't send output from one module to the next one
  -l {DEBUG,INFO,WARNING,ERROR,CRITICAL,TRACE}, --log-level {DEBUG,INFO,WARNING,ERROR,CRITICAL,TRACE}
                        Logging level (verbosity)
  -lc LOG_CONFIG, --log-config LOG_CONFIG
                        Logging configuration file (mutually exclusive with
                        -l --loglevel)
  --list                list available modules
  -lo HELP_MODULES, --list-options HELP_MODULES
                        Print help of selected module
  -r RULES, --rules RULES
                        Use a json module ruleset loaded from an URL instead
                        of -im or -om
  -t TIMEOUT, --timeout TIMEOUT
                        Specify server side timeout to get fast failure
                        feedback (seconds)
  --protocol {TCP,SOCKS}
                        Specify protocol for listening thread (default TCP)
```

To make the program actually useful, you will have to decide which modules you want to use on outgoing (client to server) and incoming (server to client) traffic. You can use different modules for each direction. Pass the list of modules as comma-separated list, e.g. -im mod1,mod4,mod2. The data will be passed to the first module, the returned data will be passed to the second module and so on, unless you use the -n/--no/chain switch. In that case, every module will receive the original data.
You can also pass options to each module: -im mod1:key1=val1,mod4,mod2:key1=val1:key2=val2. To learn which options you can pass to a module use -lo/--list-options like this: -lo mod1,mod2,mod4
You can also choose to use the rules mechanism to specify modules depending on different criteria.

## Transparent proxy

Transparent proxying will be enabled if no targetip / targetport option is provided. In transparent proxying, TCPProxy will lookup the NAT table to identify the actual target IP.

Of course transparent proxying only works if you are using linux NAT features such as (IPTables/NFT...):

`iptables -t nat -A PREROUTING [-d TARGET_IP] -p tcp [--dport TARGET_PORT] --to-port TCPProxy_LISTEN_PORT -j REDIRECT`

You are also responsible of doing a proper setup for NAT Forwarding. For instance if you which to forward all traffic coming from a given IP range to your system:

`iptables -t nat -A POSTROUTING -s 10.0.0.0/24 -j MASQUERADE`

`sysctl net.ipv4.ip_forward=1`

The mitmproxy project provide a great documentation on different possible network setup:

[https://docs.mitmproxy.org/stable/concepts-modes/]

## Modules

The following command allow listing all available modules.

Modules are running in order. The only exception is when `--no-chain` is specified in command line, in which case only the first module will be executed.

Some module can require parameters, in such case, the parameters are passed along with the module name using the following syntax: `mod1:key1=val1:key2=val2`

Modules can be separated by `,` or using the space character.

Some modules have optional or mandatory python dependencies. If the dependencie is not satistied, the module will not be run and a WARNING will be printed out for each connection that tries to use this module.

```
$ ./tcpproxy.py --list
debug - Send received data in redis debug PubSub
* - Default module (for L7 filtering ala Snort/Suricata "content")
digestdowngrade - Find HTTP Digest Authentication and replace it with a Basic Auth
	realm: use this instead of the default "tcpproxy"

drop - Drop trafic (optionally with a TCP Reset)
fileopen - Wrap the server with data from a file instead of a proper connection
	redis: the redis key where the data is stored
	esc: an escape string to replace ':' characters (default:_)
hexdump - Print a hexdump of the received data
	length: bytes per line (int)
http_fix - Fix Content-Length HTTP response header
http_ok - Prepend HTTP response header
	server: remote source, used in response Server header

http_post - Prepend HTTP header
	host: remote target, used in request URL and Host header
	port: remote target port, used in request URL

http_strip - Remove HTTP header from data
inspect - Inspect received data using redis PubSub
javaxml - Serialization or deserialization of Java objects (needs jython)
	mode: [serial|deserial] select deserialization (to XML) or serialization (to Java object)
log - Log data in the module chain. Use in addition to general logging (-l/--log).
	file: name of logfile
logo - Siemens Logo! module
modbus-MISSING DEPENDENCY - Missing dependencies for module: pymodbus
	Modbus TCP module
	ports: override default TCP port (502), multiple ports comma separated
mqtt-MISSING DEPENDENCY - Missing dependencies for module: mqtt_codec
	MQTT module
peek_httphost - Retrieve hostname from HTTP Host
peek_sni-MISSING DEPENDENCY - Missing dependencies for module: scapy
	Retrieve hostname from TLS/SSL ClientHello SNI
peek_ssl - Find if connection is based on SSL by seaching for SSL/TLS Client Hello
proxy-MISSING DEPENDENCY - Missing dependencies for module: socks,proxy host,proxy port
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

reset - Drop trafic with a TCP Reset
s7comm - Siemens S7 (0x32) module
	ports: override default TCP port (102), multiple ports comma separated
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

## Logging (DOCUMENTATION IN PROGRESS)

You can enable logging  all data that is sent or received by the proxy to a file using the -l/--log <filename> parameter. Data (and some housekeeping info) is written to the log before passing it to the module chains. If you want to log the state of the data during or after the modules are run, you can use the log proxymodule. Using the chain -im http_post,log:file=log.1,http_strip,log would first log the data after the http_post module to the logfile with the name log.1. The second use of the log module at the end of the chain would write the final state of the data to a logfile with the default name in-<timestamp> right before passing it on .

## Rule mechanism (EXPERIMENTAL)

You can run TCPProxy with a ruleset URL.

The supported URI schemes are `file://` and `redis://`

Currently rules can only be provided as json (CSV support is in progress)

`tcpproxy.py -v --rules redis://localhost` (rules will be retrieved from the key 'rules')

`tcpproxy.py -v --rules file:///tmp/tcpproxy-rules.json`

The json ruleset need to be an ordered array of rules dictionnaries that can have the following fields:
```
[
{
  "src": ".*",
  "srcport": "0-65535",
  "dst": ".*",
  "dstport: "443",
  "c2s": True,
  "s2c": True,
  "hostname": None,
  "rules": "peek_sni peek_httphost sslupgrade"
}
]
```

Most fields support python regular expressions.

In order to filter based on hostname, you need to put in first modules allowing to discover the hostname such as `peek_sni` or `peek_httphost`.
  
## Client/Server mode (EXPERIMENTAL)

Client Server mode can be achieved by using the different redis based plugins such as `stats`, `debug`, `intercept`.

Redis needs to be installed on the TCPProxy system in order for this to work. Just install a redis package and start the redis service.

Eventually, you need to ensure first that redis listen to 0.0.0.0 if you want to use the client from a different system.

Starts tcpproxy with the rules parameter:
`$ tcpproxy.py --rules redis://localhost`

As example we recommend using `peek_sni` `peek_host` `stats` first to get some feedback on traffic going through TCPProxy.

You can now run the TCPProxy client CLI (CLI has dependencies requirements on python-redis and python-hexdump) to edit rules or check ongoing traffic:

`$ ./tcpproxy_cli.py 127.0.0.1 -h
usage: tcpproxy_cli.py [-h] [-c] [-a [ADD]] [-r REPLACE [REPLACE ...]]
                       [-d DELETE] [-l LEVEL]
                       host [topic]

positional arguments:
  host                  The target host running redis
  topic                 List or do action on topic
                        [certs,rules,convs,conns,all]

optional arguments:
  -h, --help            show this help message and exit
  -c, --clear           Clear the topic
  -a [ADD], --add [ADD]
                        Add an item
  -r REPLACE [REPLACE ...], --replace REPLACE [REPLACE ...]
                        Edit an item (id key value)
  -d DELETE, --delete DELETE
                        Delete an item
  -l LEVEL, --level LEVEL
                        Debug level
`

Add a rule interactively using `tcpproxy_cli.py YourRedisInstanceIP rules -a`

The TCPProxy GUI client can also be used (the GUI has additionnal python dependencies requirements on PyQT5 and python-difflib)

`tcpproxy_gui.py YourRedisInstanceIP`

# Uses cases and example usage (DOCUMENTATION IN PROGRESS)

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

# Writing a module (DOCUMENTATION IN PROGRESS)

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


# TODO

- [ ] make the process interactive by implementing some kind of editor module (will probably complicate matters with regard to timeouts, can be done for now by using the burp solution detailed above and modifying data inside burp)
- [ ] Create and maintain a parallel branch that is compatible with jython but also has most of the new stuff introduced after e3290261

# Contributions

I want to thank the following people for spending their valuable time and energy on improving this little tool:

- [Adrian Vollmer](https://github.com/AdrianVollmer)
- [Michael Füllbier](https://github.com/mfuellbier)
- [Stefan Grönke](https://github.com/gronke)
- [Mattia](https://github.com/sowdust)
- [bjorns163](https://github.com/bjorns163)
- [Pernat1y](https://github.com/Pernat1y)
