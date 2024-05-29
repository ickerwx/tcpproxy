# tcpproxy.py - An intercepting proxy for TCP data

This tool opens a listening socket, receives data and then runs this data through a chain of proxy modules. After the modules are done, the resulting data is sent to the target server. The response is received and again run through a chain of modules before sending the final data back to the client.
To intercept the data, you will either have to be the gateway or do some kind of man-in-the-middle attack. Set up iptables so that the PREROUTING chain will modify the destination and send it to the proxy process. The proxy will then send the data on to whatever target was specified.

This tool is inspired by and partially based on the TCP proxy example used in Justin Seitz' book "Black Hat Python" by no starch press.

## Usage

```
$ ./tcpproxy.py -h
usage: tcpproxy.py [-h] [-ti TARGET_IP] [-tp TARGET_PORT] [-li LISTEN_IP]
                   [-lp LISTEN_PORT] [-pi PROXY_IP] [-pp PROXY_PORT]
                   [-pt {SOCKS4,SOCKS5,HTTP}] [-om OUT_MODULES]
                   [-im IN_MODULES] [-v] [-n] [-l LOGFILE] [--list]
                   [-lo HELP_MODULES] [-s] [-sc SERVER_CERTIFICATE]
                   [-sk SERVER_KEY] [-cc CLIENT_CERTIFICATE] [-ck CLIENT_KEY]

Simple TCP proxy for data interception and modification. Select modules to
handle the intercepted traffic.

optional arguments:
  -h, --help            show this help message and exit
  -ti TARGET_IP, --targetip TARGET_IP
                        remote target IP or host name
  -tp TARGET_PORT, --targetport TARGET_PORT
                        remote target port
  -li LISTEN_IP, --listenip LISTEN_IP
                        IP address/host name to listen for incoming data
  -lp LISTEN_PORT, --listenport LISTEN_PORT
                        port to listen on
  -pi PROXY_IP, --proxy-ip PROXY_IP
                        IP address/host name of proxy
  -pp PROXY_PORT, --proxy-port PROXY_PORT
                        proxy port
  -pt {SOCKS4,SOCKS5,HTTP}, --proxy-type {SOCKS4,SOCKS5,HTTP}
                        proxy type. Options are SOCKS5 (default), SOCKS4, HTTP
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
  -s, --ssl             detect SSL/TLS as well as STARTTLS
  -sc SERVER_CERTIFICATE, --server-certificate SERVER_CERTIFICATE
                        server certificate in PEM format (default: mitm.pem)
  -sk SERVER_KEY, --server-key SERVER_KEY
                        server key in PEM format (default: mitm.pem)
  -cc CLIENT_CERTIFICATE, --client-certificate CLIENT_CERTIFICATE
                        client certificate in PEM format in case client
                        authentication is required by the target
  -ck CLIENT_KEY, --client-key CLIENT_KEY
                        client key in PEM format in case client authentication
                        is required by the target
```

You will have to  provide TARGET_IP and TARGET_PORT, the default listening settings are 0.0.0.0:8080. To make the program actually useful, you will have to decide which modules you want to use on outgoing (client to server) and incoming (server to client) traffic. You can use different modules for each direction. Pass the list of modules as comma-separated list, e.g. -im mod1,mod4,mod2. The data will be passed to the first module, the returned data will be passed to the second module and so on, unless you use the -n/--no/chain switch. In that case, every module will receive the original data.
You can also pass options to each module: -im mod1:key1=val1,mod4,mod2:key1=val1:key2=val2. To learn which options you can pass to a module use -lo/--list-options like this: -lo mod1,mod2,mod4

## Modules

```
$ ./tcpproxy.py --list
digestdowngrade - Find HTTP Digest Authentication and replace it with a Basic Auth
hexdump - Print a hexdump of the received data
http_ok - Prepend HTTP response header
http_post - Prepend HTTP header
http_strip - Remove HTTP header from data
log - Log data in the module chain. Use in addition to general logging (-l/--log).
removegzip - Replace gzip in the list of accepted encodings in a HTTP request with booo.
replace - Replace text on the fly by using regular expressions in a file or as module parameters
hexreplace - Replace hex data in tcp packets
size - Print the size of the data passed to the module
size404 - Change HTTP responses of a certain size to 404.
textdump - Simply print the received data as text
```

Tcpproxy.py uses modules to view or modify the intercepted data. To see the possibly easiest implementation of a module, have a look at the textdump.py module in the proxymodules directory:

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
- [Pernat1y](https://github.com/Pernat1y)
- [hrzlgnm](https://github.com/hrzlgnm)
- [MKesenheimer](https://github.com/MKesenheimer)
