# tcpproxy.py - An intercepting proxy for TCP data

This tool opens a listening socket, receives data and then runs this data through a chain of proxy modules. After the modules are done, the resulting data is sent to the target server. The response is received and again run through a chain of modules before sending the final data back to the client.
To intercept the data, you will either have to be the gateway or do some kind of man-in-the-middle attack. Set up iptables so that the PREROUTING chain will modify the destination and send it to the proxy process. The proxy will then send the data on to whatever target was specified.

This tool is inspired by and partially based on the TCP proxy example used in *Justin Seitz*' book **Black Hat Python**. Indeed, this is a fork of https://github.com/ickerwx/tcpproxy specifically modified for transparent proxying **OT** (Operational Technology) protocols like **MQTT**, **Modbus TCP**, **Siemens S7** (only S7COMM with magic = 0x32, 0x72 S7COMM_PLUS not supported yet), **Siemens Logo!** programming protocol. There is also a draft module of flexible **default** that permit you to create L7 content based filters/alerts (ala Snort/Suricata **content**). All of these modules read only the payload and audit it, so they can works as IDS/IPS (they can also close the connection).

## Usage

```
$ ./tcpproxy.py -h
usage: tcpproxy.py [-h] [-ti TARGET_IP] [-tp TARGET_PORT] [-li LISTEN_IP]
                   [-lp LISTEN_PORT] [-pi PROXY_IP] [-pp PROXY_PORT]
                   [-pt {SOCKS4,SOCKS5,HTTP}] [-om OUT_MODULES]
                   [-im IN_MODULES] [-n]
                   [-l {DEBUG,INFO,WARNING,ERROR,CRITICAL}] [--list]
                   [-lo HELP_MODULES] [-s] [-sc SERVER_CERTIFICATE]
                   [-sk SERVER_KEY] [-cc CLIENT_CERTIFICATE] [-ck CLIENT_KEY]
                   [-od] [-f FILTERS] [-lc LOG_CONFIG]

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
  -n, --no-chain        Don't send output from one module to the next one
  -l {DEBUG,INFO,WARNING,ERROR,CRITICAL}, --log-level {DEBUG,INFO,WARNING,ERROR,CRITICAL}
                        Logging level (verbosity)
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
  -od, --original-destination
                        use SO_ORIGINAL_DST (if supported by OS) instead of
                        static options -ti/-tp
  -f FILTERS, --filters FILTERS
                        IDS/IPS mode, specify a CSV file with alert/filters
                        configurations for out modules
  -lc LOG_CONFIG, --log-config LOG_CONFIG
                        Logging configuration file (mutually exclusive with -l
                        --loglevel)
```

You will have to  provide TARGET_IP and TARGET_PORT, the default listening settings are 0.0.0.0:8080 or to activate the option **-od/--original-destination** to let netfilter says the destination to the proxy (only works under Linux/netfilter). To make the program actually useful, you will have to decide which modules you want to use on outgoing (client to server) and incoming (server to client) traffic. You can use different modules for each direction. Pass the list of modules as comma-separated list, e.g. **-im mod1,mod4,mod2**. The data will be passed to the first module, the returned data will be passed to the second module and so on, unless you use the **-n/--no-chain** switch. In that case, every module will receive the original data.
You can also pass options to each module: **-im mod1:key1=val1,mod4,mod2:key1=val1:key2=val2**. To learn which options you can pass to a module use **-lo/--list-options** like this: **-lo mod1,mod2,mod4**

Nefilter setup for transparent proxy redirection and usage example:

```bash
sudo iptables -t nat -A OUTPUT -p tcp -m owner ! --uid-owner tcpproxy --dport 102 -j REDIRECT --to-port 9999
sudo iptables -t nat -A OUTPUT -p tcp -m owner ! --uid-owner tcpproxy --dport 502 -j REDIRECT --to-port 9999
sudo iptables -t nat -A OUTPUT -p tcp -m owner ! --uid-owner tcpproxy --dport 1883 -j REDIRECT --to-port 9999
sudo iptables -t nat -A OUTPUT -p tcp -m owner ! --uid-owner tcpproxy --dport 8080 -j REDIRECT --to-port 9999
sudo iptables -t nat -A OUTPUT -p tcp -m owner ! --uid-owner tcpproxy --dport 10005 -j REDIRECT --to-port 9999
sudo -u tcpproxy ./tcpproxy.py -od -lp 9999 -n -im default,logo,modbus,mqtt,s7comm -om default,logo,modbus,mqtt,s7comm -l DEBUG -f filters.csv -lc logging.conf
```

## Changelog

Detail of changes compared to https://github.com/ickerwx/tcpproxy

    Python logging with DEBUG/INFO/WARNING/CRITICAL levels, complex logging configurable through logging.config python module.
    Dynamic destination ip address using SO_ORIGINAL_DST
    Optimized start_proxy_thread() for thread safety and speed. Source and destination passed as parameters to modules.
    Added configurable filtering using CSV files.
    Added checking for duplicate modules, so it can be used only one time in in or out direction; default module will be always the last one.
    Added Snort/Suricata style actions like pass, drop, reject (TCP RST) and alert.
    Added default module with configurable L7 payload ala Snort/Suricata "content"
    Added multiple and configurable modules destination ports

## Modules

```
$ ./tcpproxy.py --list
default - Default module (for L7 filtering ala Snort/Suricata "content")
logo - Siemens Logo! module
modbus - Modbus TCP module
mqtt - MQTT module
s7comm - Siemens S7 (0x32) module
```

Tcpproxy.py uses modules to view or modify the intercepted data. This is an example module (a bit different from original ickerwx's):

```python
#!/usr/bin/env python3
import os.path as path
import builtins
import logging
import threading

logger = logging.getLogger(__name__)

class Module(threading.local):
    def __init__(self, incoming=False, loglevel=logging.INFO, options=None, filters=None):
        # extract the file name from __file__. __file__ is proxymodules/name.py
        self.name = path.splitext(path.basename(__file__))[0]
        self.description = 'Simply print the received data as text'
        self.incoming = incoming  # incoming means module is on -im chain
        self.filters = filters
        logger.setLevel(loglevel)

        self.find = None  # if find is not None, this text will be highlighted
        if options is not None:
            if 'find' in options.keys():
                self.find = bytes(options['find'], 'ascii')  # text to highlight
            if 'color' in options.keys():
                self.color = bytes('\033[' + options['color'] + 'm', 'ascii')  # highlight color
            else:
                self.color = b'\033[31;1m'

    def execute(self, data, source, destination):
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

Every module file contains a class named **Module**. Every module MUST set **self.description** and MUST implement an execute method that accepts three parameters, input data, source and destination address. The execute method MUST return something, this something is then either passed to the next module or sent on. You can also raise an exception to drop (**Drop** exception) or reset the connection (**Reject** exception); exceptions are defined in **filter.py** and can used importing **builtins** module.
The **incoming** parameter in the constructor is set to True when the module is in the incoming chain (**-im**), otherwise it's False. Eventual defined filters are applied only where **incoming == False** (output direction, from proxy server to intended destination).
There is no more a verbose parameter but there is a **loglevel** that can be set to loglevel.DEBUG/INFO/WARNING/ERROR/CRITICAL (option **-l/--log-level**), default is **INFO**.
The option **parameter** is a dictionary with the keys and values passed to the module on the command line. Note that if you use the options dictionary in your module, you should also implement a **help()** method. This method must return a string. Use one line per option, make sure each line starts with a \t character for proper indentation.
The option **filters** is an instance of **CSVFilter()** class defined in **filter.py**. It's used to read a list of rules (alert or pass/drop/reject) from a CSV file (option **-f/--filters**) and use them in output direction (**incoming == False**).

To pass more than one option to a single module, seperate the options with a : character, modname:key1=val1:key2=val2...

## Filtering and alerting

This fork of tcpproxy can actually works as an IDS/IPS, alerting or dropping/rejecting sessions. With the option **-f/--filters** you can optionally indicate a CSV file containing the rules.

This is an example of some rules:

```
# module s7comm, sid, action, protocol, source_address, source_port, destination_address, destination_port, source_tsap, destination_tsap, rosctr, function, subfunction, address, szl-id
s7comm, 10001, pass, tcp, any, any, 10.10.10.46, any, 0x100, 0x101, 1, 0xf0
s7comm, 10002, alert, tcp, any, any, 10.10.10.46, any, 0x100, 0x101, 7, 4, 1, ,0x0424
s7comm, 10003, pass, tcp, any, any, 10.10.10.46, any, 0x100, 0x101, 1, 4
s7comm, 10004, alert, tcp, any, any, 10.10.10.46, any, 0x100, 0x101, 1, 4,, MD1
s7comm, 10005, alert, tcp, any, any, 10.10.10.46, any, 0x100, 0x101, 1, 4,, DB1.DBX0
s7comm, 10006, pass, tcp, any, any, 10.1.1.13, any, 0x300, 0x200
s7comm, 10007, drop
# module mqtt, sid, action, protocol, source_address, source_port, destination_address, destination_port, type, qos, username, topic, message
mqtt, 11001, alert, tcp, any, any, 10.10.10.196, any, MqttConnect, any, any, *, 
mqtt, 11002, pass, tcp, any, any, 10.10.10.196, any, any, any, any, *,
mqtt, 11003, drop
# module logo, sid, action, protocol, source_address, source_port, destination_address, destination_port, request
logo, 12001, pass, tcp, any, any, 10.10.10.13, any, any
logo, 12002, alert, tcp, any, any, any, any, StartDown
logo, 12003, alert, tcp, any, any, any, any, SetClock
logo, 12004, alert, tcp, any, any, any, any, GetProfile
logo, 12005, drop
# module modbus, sid, action, protocol, source_address, source_port, destination_address, destination_port, unit, function, start, length
modbus, 13001, alert, tcp, any, any, 10.10.10.47, any, 2, any, any, any
modbus, 13002, pass, tcp, any, any, 10.10.10.47, any, any, any, any, any
modbus, 13003, drop
# default module, sid, source_address, source_port, destination_address, destination_port, content
*, 14001, alert, tcp, any, any, !10.10.10.196, any
*, 14002, drop, tcp, any, any, any, 8080, !"GET"
*, 14003, drop

```
In the above example we leave to pass S7 towards 10.10.10.46 with source TSAP 0x100, destination TSAP 0x101, Job (0x01), Setup communication (0xf0); alert towards 10.10.10.46 with source TSAP 0x100, destination TSAP 0x101, UserData (0x07), funzione 0x04 (CPU), subfunction 0x01 (Read SZL); pass towards 10.10.10.46 with source TSAP 0x100, destination TSAP 0x101, Job (0x01), Read Var (0x04); alert towards 10.10.10.46 with source TSAP 0x100, destination TSAP 0x101, Job (0x01), Read Var (0x04), MD1; alert towards 10.10.10.46 with source TSAP 0x100, destination TSAP 0x101, Job (0x01), Read Var (0x04), DB1.DBX0; pass towards 10.1.1.13 with source TSAP 0x300, destination TSAP 0x200; drop anything all.
MQTT: alert towards 10.10.10.196 with MqttConnect; pass towards 10.10.10.196, drop anything all.
Siemens Logo!: pass towards 10.1.1.13; alert if StartDown (upload of a program from the PC to the PLC), SetClock or GetProfile; drop anything all.
Modbus: pass towards 10.10.10.47; alert in case of 10.10.10.47 with slave 2; drop anything all.
Default: alert if destination different from 10.10.10.196; drop traffic towards any destination if port 8080 and the payload does not contains "GET"; drop anything all.

## Logging

Logging is now managed by python logging module. You can set a logging level (DEBUG/INFO/WARNING/ERROR/CRITICAL) with option **-l/--log-level** or you can define complex logging rules with logging.config (option **-lc/--logging-config**). 

There are two main qualifiers: **alert** (used by alert action of filters) and **filters** (used by drop/reject action). Obviously there is a root **tcpproxy** qualified and you can also define logging paths using the name of the modules as **qualname**.

```
[loggers]
keys=root,tcpproxy,filter,alert,s7comm

[handlers]
keys=consoleHandler,syslogHandler,fileHandler,fileHandlerAlert,fileHandlerFilter

[formatters]
keys=simpleFormatter,syslogFormatter,fileFormatter,CSVFormatter

[logger_root]
level=DEBUG
handlers=consoleHandler,fileHandler

[logger_tcpproxy]
level=INFO
propagate=0
qualname=__main__
handlers=consoleHandler,fileHandler,syslogHandler

[logger_alert]
level=DEBUG
handlers=fileHandlerAlert
propagate=0
qualname=alert

[logger_filter]
level=INFO
handlers=fileHandlerFilter
propagate=0
qualname=filter

[logger_s7comm]
level=INFO
handlers=fileHandlerFilter
propagate=0
qualname=s7comm

[handler_consoleHandler]
class=StreamHandler
level=DEBUG
formatter=simpleFormatter
args=(sys.stdout,)

[handler_syslogHandler]
class=handlers.SysLogHandler
level=INFO
formatter=syslogFormatter
args=('/dev/log', handlers.SysLogHandler.LOG_USER)

[handler_fileHandler]
class=FileHandler
level=DEBUG
formatter=fileFormatter
args=('/tmp/tcpproxy.log','a')

[handler_fileHandlerAlert]
class=FileHandler
level=DEBUG
formatter=CSVFormatter
args=('/tmp/alert.log','a')

[handler_fileHandlerFilter]
class=FileHandler
level=DEBUG
formatter=CSVFormatter
args=('/tmp/filter.log','a')

[formatter_simpleFormatter]
format=%(asctime)-15s %(threadName)-15s %(levelname)-8s %(module)-15s %(message)s
datefmt=%Y-%m-%dT%H:%M:%S%z

[formatter_syslogFormatter]
format=%(asctime)-15s %(threadName)-15s %(levelname)-8s %(module)-15s %(message)s
datefmt=%Y-%m-%dT%H:%M:%S%z

[formatter_fileFormatter]
format=%(asctime)-15s %(threadName)-15s %(levelname)-8s %(module)-15s %(message)s
datefmt=%Y-%m-%dT%H:%M:%S%z

[formatter_CSVFormatter]
format=%(asctime)s,%(thread)s,%(mod)s,%(sid)s,%(action)s,%(protocol)s,%(src_address)s,%(src_port)s,%(dst_address)s,%(dst_port)s,%(message)s
datefmt=%Y-%m-%dT%H:%M:%S%z
```

## FAQ

**Why we changed tcpproxy and wrote OT protocol modules instead of using Snort, Suricata and other ready to use software?** Because IT IDS/IPS lack of a real L7 DPI, you can define only static and hardwired rules while we need to define parametric rules (eg. alert or pass or drop only on a specific modbus register or S7 variable). This is a PoC only but at now there is no solutions or products that can works as OT parametric IDS/IPS. Moreover, the S7, Logo!, MQTT and Modbus TCP modules can audit/alert with a level of details including commands and parameters of the payloads while and IT IDS can only alert the triggering of a rule.

## TODO and limitations

    This is a TCP only proxy. We are working on a UDP experimental version but SO_ORIGINAL_DST is not working at all, so it would be really limited.
    This is a simple standalone script, not a real daemon. And it's limited to only one port and ip address listening for connections. 
    SSL mode is working for HTTPS, but it was impossible to made it working for MQTT.
    SO_ORIGINAL_DST only works for GNU/Linux with netfilter (iptables). Teoretically it would be possibile to run the tcpproxy under other *nix OS and using other firewalls like OpenBSD pf, but without SO_ORIGINAL_DST the proxy is almost useless.
    Filters at now have a variable number of columns depending by the module (protocol) used.

## Acknowledgements

We want to thanks:

- [René Werner](https://github.com/ickerwx) and all contributors of https://github.com/ickerwx/tcpproxy
- [Justin Seitz for his book Black Hat Python: Python Programming for Hackers and Pentesters](https://smile.amazon.com/Black-Hat-Python-Programming-Pentesters-ebook/dp/B00QL616DW)

