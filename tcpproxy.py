#!/usr/bin/env  python3
import argparse
import pkgutil
import os
import sys
import threading
import socket
import select
import queue
import ssl
import logging
import logging.config
import builtins
import re
# ConnData is an object that contains basic information about the connection.
# Plugins can also use this object to exchange connection or status information.
from conndata import ConnData
import inspect
from urllib.parse import urlparse

from protocol_tcp import ProtocolTCP
from protocol_socks import ProtocolSOCKS

FORMAT = ('%(asctime)-15s %(threadName)-15s %(levelname)-8s %(calling_module)-15s %(conn_str)s %(message)s')
logging.basicConfig(format=FORMAT)
LOG_LEVEL_TRACE = 2
logging.addLevelName(LOG_LEVEL_TRACE,  "TRACE")


def trace(self, message, *args, **kwargs):
    if self.isEnabledFor(LOG_LEVEL_TRACE):
        print("TRACE", message)


logging.Logger.trace = trace
loglevels = {'CRITICAL': logging.CRITICAL, 'ERROR': logging.ERROR, 'WARNING': logging.WARNING, 'INFO': logging.INFO, 'DEBUG': logging.DEBUG,  'TRACE': LOG_LEVEL_TRACE}


def trace(self, message, *args, **kwargs):
    if self.isEnabledFor(LOG_LEVEL_TRACE):
        print("TRACE", message)


logging.Logger.trace = trace
loglevels = {'CRITICAL': logging.CRITICAL, 'ERROR': logging.ERROR, 'WARNING': logging.WARNING, 'INFO': logging.INFO, 'DEBUG': logging.DEBUG,  'TRACE': LOG_LEVEL_TRACE}


class ConnectionLogAdapter(logging.LoggerAdapter):

    trace = trace

    def __init__(self, logger, extra={}):
        logging.LoggerAdapter.__init__(self,  logger, extra={})
        self.conn_none = ConnData(("0.0.0.0", 0), ("0.0.0.0", 0))

    def process(self,  msg,  kwargs):
        if 'extra' in kwargs:
            if 'conn' in kwargs['extra'] and kwargs['extra']['conn']:
                kwargs['extra'].update(kwargs['extra']['conn'].get_dict())
                kwargs['extra']['conn_str'] = kwargs['extra']['conn'].get_string()

                if 'direction' in kwargs['extra'] and kwargs['extra']['direction'] is not None:
                    if kwargs['extra']['direction'].lower() in [">",  "client",  "in",  "incoming"]:
                        kwargs['extra']['conn_str'] = kwargs['extra']['conn_str'].replace(" ",  ">")
                    elif kwargs['extra']['direction'].lower() in ["<",  "server",  "out",  "outgoing"]:
                        kwargs['extra']['conn_str'] = kwargs['extra']['conn_str'].replace(" ",  "<")

            if 'calling_module' not in kwargs['extra'] and 'self' in kwargs['extra']:
                kwargs['extra']['calling_module'] = kwargs['extra']['self'].__class__.__module__.split(".")[-1]

        if 'extra' not in kwargs:
            kwargs['extra'] = {}

        if 'conn' not in kwargs['extra'] or not kwargs['extra']['conn']:
            kwargs['extra']['conn'] = self.conn_none
            kwargs['extra'].update(self.conn_none.get_dict())
            kwargs['extra'].update({
                'src': None,
                'srcport': None,
                'dst': None,
                'dstport': None,
                'conn_str': None,
            })

        # Ugly hack to to find caller module name
        if 'calling_module' not in kwargs['extra']:
            kwargs['extra']['calling_module'] = inspect.currentframe().f_back.f_back.f_back.f_globals['__name__']
        return msg,  kwargs


logger_raw = logging.getLogger(__name__)
logger = ConnectionLogAdapter(logger_raw)
builtins.logger = logger


# some code snippets, as well as the original idea, from Black Hat Python
def is_valid_ip4(ip):
    # some rudimentary checks if ip is actually a valid IP
    octets = ip.split('.')
    if len(octets) != 4:
        return False
    return octets[0] != 0 and all(0 <= int(octet) <= 255 for octet in octets)


def parse_args():
    parser = argparse.ArgumentParser(description='Simple TCP proxy for data ' +
                                                 'interception and ' +
                                                 'modification. ' +
                                                 'Select modules to handle ' +
                                                 'the intercepted traffic.')

    parser.add_argument('-ti', '--targetip', dest='target_ip',
                        help='remote target IP or host name (none for transparent proxying based on iptable)',
                        default=None)

    parser.add_argument('-tp', '--targetport', dest='target_port', type=int,
                        help='remote target port',
                        default=0)

    parser.add_argument('-li', '--listenip', dest='listen_ip',
                        default='0.0.0.0', help='IP address/host name to listen for ' +
                        'incoming data')

    parser.add_argument('-lp', '--listenport', dest='listen_port', type=int,
                        default=8080, help='port to listen on')

    parser.add_argument('-om', '--outmodules', dest='out_modules',
                        help='comma-separated list of modules to modify data' +
                             ' before sending to remote target.')

    parser.add_argument('-im', '--inmodules', dest='in_modules',
                        help='comma-separated list of modules to modify data' +
                             ' received from the remote target.')

    parser.add_argument('-n', '--no-chain', dest='no_chain_modules',
                        action='store_true', default=False,
                        help='Don\'t send output from one module to the ' +
                             'next one')

    parser.add_argument('-l', '--log-level', dest='log_level', default='INFO', choices=['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL', 'TRACE'],
                        help='Logging level (verbosity)')

    parser.add_argument('-lc', '--log-config', dest='log_config', default=None,
                        help='Logging configuration file (mutually exclusive with -l --loglevel)')

    parser.add_argument('--list', dest='list', action='store_true',
                        help='list available modules')

    parser.add_argument('-lo', '--list-options', dest='help_modules', default=None,
                        help='Print help of selected module')

    parser.add_argument('-r', '--rules', dest='rules', default=None,
                        help='Use a json module ruleset loaded from an URL instead of -im or -om')

    parser.add_argument('-t', '--timeout', dest='timeout', default=5,
                        help='Specify server side timeout to get fast failure feedback (seconds)')

    parser.add_argument('--protocol', dest='protocol',  default="TCP", choices=['TCP',  'SOCKS'],
                        help='Specify protocol for listening thread (default TCP)')

    return parser.parse_args()


def load_module(n, args, incoming=False, prematch=None, conn_obj=None):
    name, options = parse_module_options(n, args, conn_obj)
    try:
        __import__('proxymodules.' + name)
        if hasattr(sys.modules['proxymodules.' + name], "Module"):
            mod = sys.modules['proxymodules.' + name].Module(incoming, args, options)
            mod.prematch = prematch
            return mod
        else:
            connection_warning(None, "Invalid module %s: cannot load class 'Module'" % name, args, conn_obj, modulename=name)
            return None
    except ImportError as ex:
        connection_warning(None, "Cannot load module %s: %s" % (name, str(ex)), args, conn_obj, modulename=name)
        return None
        # sys.exit(3)


class RulesLoader():
    __instance = None
    uri = None

    @staticmethod
    def getInstance():
        if RulesLoader.__instance is None:
            RulesLoader()
        return RulesLoader.__instance

    def __init__(self):
        if RulesLoader.__instance is not None:
            raise Exception("This class is a singleton!")
        else:
            RulesLoader.__instance = self

    def setup(self, args):
        try:
            self.uri = urlparse(args.rules)
        except Exception as ex:
            connection_failed(None, "Invalid URI provided for loading ruleset: %s" % str(ex), args)
            sys.exit(1)

        if self.uri.scheme in ["http", "https"]:
            connection_failed(None, "Loading ruleset from http/https is not implemented", args)
            sys.exit(1)

        elif self.uri.scheme in ["redis", "rediss", "unix"]:
            import api_redis
            infos = get_modules_list()
            self.api = api_redis.API(args,  infos,  self.uri)

        elif self.uri.scheme in ["file", "csv", "json"]:
            import api_file
            self.api = api_file.API(args,  infos,  self.uri)

        else:
            connection_failed(None, "Invalid URI sheme %s for loading ruleset" % self.uri.scheme, args)
            sys.exit(1)

    def read(self, args, conn):
        return self.api.rules()


def generate_module_list(namelist, args, incoming=False):
    # This method receives a list of modules name, imports the modules
    # and creates a Module instance for each module. A list of these instances
    # is then returned.
    # The incoming parameter is True when the modules belong to the incoming
    # chain (-im)
    # modstring looks like mod1,mod2:key=val,mod3:key=val:key2=val2,mod4 ...
    modlist = []
    for n in namelist:
        mod = load_module(n, args)
        if mod:
            modlist.append(mod)
    return modlist


def parse_module_options(n,  args, conn_obj):
    # n is of the form module_name:key1=val1:key2=val2 ...
    # this method returns the module name and a dict with the options
    n = n.split(':', 1)
    if len(n) == 1:
        # no module options present
        return n[0], None
    name = n[0]
    optionlist = n[1].split(':')
    options = {}
    for op in optionlist:
        try:
            k, v = op.split('=')
            options[k] = v
        except ValueError:
            connection_warning(None, "Argument %s for module %s is not valid" % (op, name), args, conn_obj, modulename=name)
            # sys.exit(23)
    return name, options


def get_modules_list():
    mlist = {}
    # get all available proxy modules help and descriptions
    cwd = os.getcwd()
    module_path = cwd + os.sep + 'proxymodules'
    for _, module, _ in pkgutil.iter_modules([module_path]):
        __import__('proxymodules.' + module)
        if hasattr(sys.modules['proxymodules.' + module], 'Module'):
            m = sys.modules['proxymodules.' + module].Module()
            if hasattr(m, 'getInfos') and callable(getattr(m, 'getInfos')):
                mname, mdesc, mhelp = m.getInfos()
            else:
                mname = m.name
                mdesc = m.description
                if hasattr(m, 'help') and callable(getattr(m, 'help')):
                    mhelp = m.help()
                else:
                    mhelp = None
            mlist[mname] = mdesc
            if mhelp:
                mlist[mname] += "\n"
                mlist[mname] += mhelp

    return mlist


# Find if a value is a a given range (eg: 5 is not in 1-4,6)
def inrange(strrange, value):
    for subrange in strrange.split(","):
        subrange = subrange.split("-")
        if len(subrange) == 1 and int(value) == int(subrange[0]):
            return True
        elif len(subrange) == 2 and int(value) in range(int(subrange[0]), int(subrange[1])):
            return True
    return False


# Load module list related to the given current connection
# The modules and options are loaded depending on a rule
# dictionnary list in the following form:
# [{"src":".*","dst":".*","hostname":".*","dstport":"0-65535","c2s":True,"s2c":True,"rules":["stats"]}]
# Note that the order for rules matters
def load_modules_from_rules(args, rules, conn):
    in_modules = []
    out_modules = []
    for rule in rules:
        if (re.match(rule['src'], conn.src) and
                re.match(rule['dst'], conn.dst) and
                ("dstport" not in rule or inrange(rule['dstport'], conn.dstport)) and
                ("srcport" not in rule or inrange(rule['srcport'], conn.srcport))):

            # Note that we cannot match on hostname at this point
            # because hostname is discovered during peek operations
            # so we will preload a matcher inside the module
            if 'hostname' in rule and rule['hostname']:
                prematch = re.compile(rule['hostname'])
            else:
                prematch = None
            if rule['c2s']:
                for r in rule['rules']:
                    mod = load_module(r, args, incoming=False, prematch=prematch, conn_obj=conn)
                    if mod:
                        out_modules.append(mod)
            if rule['s2c']:
                for r in rule['rules']:
                    mod = load_module(r, args, incoming=True, prematch=prematch, conn_obj=conn)
                    if mod:
                        in_modules.append(mod)

    return (out_modules, in_modules)


def list_modules():
    # show all available proxy modules
    for name, description in get_modules_list().items():
        print('%s - %s' % (name, description))


def print_module_help(modliststr,  args):
    # parse comma-separated list of module names, print module help text
    namelist = modliststr.split(',')
    modules = generate_module_list(namelist, args)
    for m in modules:
        try:
            print(f'{m.name} - {m.description}')
            print(m.help())
        except AttributeError:
            print('\tNo options or missing help() function.')


def update_module_hosts(modules, conn_obj):
    # set source and destination IP/port for each module
    # a plugin can use set_connection() to get a connection object
    # or source and destination are ('IP', port) tuples
    # this can only be done once local and remote connections have been established
    if modules is not None:
        for m in modules:
            if hasattr(m, 'set_connection') and callable(getattr(m, 'set_connection')):
                m.set_connection(conn_obj)
            else:
                if hasattr(m, 'source'):
                    m.source = conn_obj.src
                if hasattr(m, 'destination'):
                    m.destination = conn_obj.dst


def handle_data(data, modules, args, incoming, conn_obj):
    # execute each active module on the data. If no_chain_modules is set, feed the
    # output of one plugin to the following plugin. Not every plugin will
    # necessarily modify the data, though.
    for m in modules:
        if hasattr(m, "execute") and callable(m.execute):
            if not hasattr(m, "is_inhibited") or callable(m.is_inhibited) and not m.is_inhibited():
                connection_debug("client" if incoming else "server", "execute %s" % m.name, args,  conn_obj)
                try:
                    if args.no_chain_modules:
                        m.execute(data)
                    else:
                        data = m.execute(data)
                except Exception as ex:
                    connection_failed(m.name, ex.__str__(), args, conn_obj)
                    import traceback
                    traceback.print_exc()

    return data


def peek_data(data, modules, args, incoming, conn_obj):
    # execute each active module on the peeked data
    peeks = {}
    for m in modules:
        if hasattr(m, "peek") and callable(m.peek):
            if not hasattr(m, "is_inhibited") or callable(m.is_inhibited) and not m.is_inhibited():
                connection_debug("client" if incoming else "server", "peek %s" % m.name, args, conn_obj)
                if args.no_chain_modules:
                    m.peek(data)
                else:
                    peeks.update(m.peek(data))

    return peeks


def wrap_socket(sock, modules, args, incoming, conn_obj):
    wraps = {}
    for m in modules:
        if hasattr(m, "wrap") and callable(m.wrap):
            if not hasattr(m, "is_inhibited") or callable(m.is_inhibited) and not m.is_inhibited():
                connection_debug("client" if incoming else "server", "wrap %s" % m.name, args,  conn_obj)
                try:
                    if args.no_chain_modules:
                        m.wrap(sock)
                    else:
                        if "remote_socket" in wraps:
                            # Wrap remote socket following last wrap
                            sock = [wraps["remote_socket"], sock[1], sock[2]]
                        if "local_socket" in wraps:
                            # Wrap remote socket following last wrap
                            sock = [sock[0], wraps["local_socket"], sock[2]]
                        wraps.update(m.wrap(sock))
                except Exception as ex:
                    connection_failed(m.name+" wrapping", ex.__str__(), args, conn_obj)
                    import traceback
                    traceback.print_exc()

    return wraps


def start_proxy_thread(trunning,  local_socket, args, in_modules, out_modules):
    # This method is executed in a thread. It will relay data between the local
    # host and the remote host, while letting modules work on the data before
    # passing it on.

    if args.protocol == "TCP":
        proto = ProtocolTCP(local_socket,  args)
    elif args.protocol == "SOCKS":
        proto = ProtocolSOCKS(local_socket,  args)
    else:
        raise Exception("Unsupported protocol %s" % args.protocol)

    if not proto.connect_source():
        connection_failed("client",  "Initiating %s connection" % proto.name,  args)

    # Create conn obj based on known information about the connection.
    try:
        conn_obj = ConnData(
            source=local_socket.getpeername()
        )
    except Exception as err:
        connection_failed(None,  err.__str__(),  args)
        return None

    proto.set_connection(conn_obj)
    # If server connection fails we may still want to get client side data

    if not proto.is_valid():
        # If server connection fails we may still want to get client side data
        connection_failed("remote",  "Attempt to connect to TCPProxy itself cancelled",  args,  conn_obj)
        return None

    # Reload ruleset for each connection (in case the ruleset is changed)
    if args.rules:
        out_modules, in_modules = load_modules_from_rules(args, RulesLoader.getInstance().read(args, conn_obj), conn_obj)

    if not proto.connect_destination():
        connection_failed("server",  "Initiating %s connection" % proto.name,  args,  conn_obj)

    update_module_hosts(out_modules, conn_obj)
    update_module_hosts(in_modules, conn_obj)

    # This loop ends when no more data is received on either the local or the
    # remote socket
    running = True
    while running and trunning.qsize() <= 0:
        read_sockets, _, _ = select.select(proto.get_sockets(), [], [])

        # Before execution data modules, run peek and wrap modules
        for sock in read_sockets:
            # First peek data
            try:
                # If socket has support for peeking, retrieve the first 1024 bytes
                if hasattr(sock, "peek") and callable(sock.peek):
                    firstbytes = sock.peek(1024)
                # Python SSL module typically does not support socket peeking
                elif isinstance(sock, ssl.SSLSocket):
                    # Cannot peek from within a SSL socket (not supported by ssl module)
                    firstbytes = None
                # Last try by using the MSG_PEEK API
                else:
                    firstbytes = sock.recv(1024, socket.MSG_PEEK)
            except ConnectionResetError as err:
                # Shutdown sockets cleanly
                proto.shutdown_local()
                proto.shutdown_remote()
                connection_failed("local" if proto.is_local(sock) else "remote", "Connection reset while peeking socket: "+err.__str__(), args, conn_obj)
                return None
            except Exception as err:
                # Shutdown sockets cleanly
                proto.shutdown_local()
                proto.shutdown_remote()
                connection_failed("local" if proto.is_local(sock) else "remote", "Cannot peek socket: "+err.__str__(), args, conn_obj)
                return None

            if firstbytes != None:
                if proto.is_local(sock):
                    peeks = peek_data(firstbytes, out_modules, args, True,  conn_obj)
                elif proto.is_remote(sock):
                    peeks = peek_data(firstbytes, in_modules, args, False,  conn_obj)

                connection_debug("client" if proto.is_local(sock) else "server", "Peeks: %s" % str(peeks), args, conn_obj)

            # Wrapping comes next
            # We parse read socket but we probably need to wrap remote socket first anyway
            sockets = proto.get_sockets()
            sockets.append(sock)
            if proto.is_local(sock):
                wraps = wrap_socket(sockets, out_modules, args, True, conn_obj)
            elif proto.is_remote(sock):
                wraps = wrap_socket(sockets, in_modules, args, False, conn_obj)

            connection_debug("client" if proto.is_local(sock) else "server", "Wraps: %s" % str(wraps), args, conn_obj)

            # Retrieve the last wrapped socket in the chain as our "normal" socket
            if "error" in wraps:
                proto.shutdown_local()
                proto.shutdown_remote()
                return None
            if "local_socket" in wraps:
                proto.wrap_local(wraps["local_socket"])
            if "remote_socket" in wraps:
                proto.wrap_remote(wraps["remote_socket"])

            # If there have been wrapping, read the data from the wrapped sockets
            if "local_socket" in wraps or "remote_socket" in wraps:
                read_sockets, _, _ = select.select(proto.get_sockets(), [], [])

        # Finally retrieve data from socket
        for sock in read_sockets:
            try:
                data = proto.read(sock)
                running = handle_data_read(sock, data, args, proto, in_modules, out_modules, conn_obj)
            except Exception as err:
                # Shutdown sockets cleanly
                proto.shutdown_local()
                proto.shutdown_remote()
                connection_failed("client" if proto.is_local(sock) else "server", err.__str__(), args, conn_obj)
                return None


def handle_data_read(sock, data, args, proto, in_modules, out_modules, conn_obj):

    # Retrieve peer for loggin purposes
    peer = sock.getpeername()

    connection_debug("client" if proto.is_local(sock) else "server", 'Received %d bytes from %s' % (len(data), peer), args,  conn_obj)

    if proto.is_local(sock):
        if len(data):
            data = handle_data(data, out_modules,
                               args,
                               True,  # is incoming initiated?
                               conn_obj)
            proto.send_remote(data.encode() if isinstance(data, str) else data)
        else:
            connection_info("client", "Connection from %s:%d closed" % peer, args)
            proto.shutdown_remote()
            return False

    elif proto.is_remote(sock):
        if len(data):
            data = handle_data(data, in_modules,
                               args,
                               False,  # is incoming initiated?
                               conn_obj)
            proto.send_local(data)
        else:
            connection_info("server", "Connection to %s:%d closed" % peer, args)
            proto.shutdown_local()
            return False

    return True


def connection_failed(direction, msg, args, conn_obj=None, modulename="tcpproxy"):
    if conn_obj:
        error_msg = 'Failed connection with %s : %s' % (direction,  msg)
    else:
        error_msg = '%s' % (msg)
    logger.error(error_msg, extra={'conn': conn_obj, 'direction': direction, 'calling_module': modulename})


def connection_warning(direction, msg, args, conn_obj=None, modulename="tcpproxy"):
    if conn_obj:
        warning_msg = 'Connection with %s : %s' % (direction,  msg)
    else:
        warning_msg = '%s' % (msg)
    logger.warning(warning_msg, extra={'conn': conn_obj, 'direction': direction, 'calling_module': modulename})


def connection_debug(direction, msg, args, conn_obj=None, modulename="tcpproxy"):
    if conn_obj:
        debug_msg = 'Connection with %s : %s' % (direction,  msg)
    else:
        debug_msg = '%s' % (msg)
    logger.debug(debug_msg, extra={'conn': conn_obj, 'direction': direction, 'calling_module': modulename})


def connection_info(direction, msg, args, conn_obj=None, modulename="tcpproxy"):
    if conn_obj:
        info_msg = 'Connection with %s : %s' % (direction,  msg)
    else:
        info_msg = '%s' % msg
    logger.info(info_msg, extra={'conn': conn_obj, 'direction': direction, 'calling_module': modulename})


def main():
    args = parse_args()

    if args.log_config and os.path.isfile(args.log_config):
        try:
            logging.config.fileConfig(args.log_config)
        except KeyError as e:
            logger.critical('Error in logging configuration %s: %s' % (args.log_config, str(e)))
            sys.exit(9)
    else:
        logger.setLevel(loglevels[args.log_level])

    if args.list is False and args.help_modules is None:
        if args.target_port and not args.target_ip:
            print('Both target IP and target Ports are required: missing -ti')
            sys.exit(6)
        if args.target_ip and not args.target_port:
            print('Both target IP and target Ports are required: missing -tp')
            sys.exit(7)

    if args.list:
        list_modules()
        sys.exit(0)

    if args.help_modules is not None:
        print_module_help(args.help_modules, args)
        sys.exit(0)

    if args.listen_ip != '0.0.0.0' and not is_valid_ip4(args.listen_ip):
        try:
            ip = socket.gethostbyname(args.listen_ip)
        except socket.gaierror:
            ip = False
        if ip is False:
            print('%s is not a valid IP address or host name' % args.listen_ip)
            sys.exit(1)
        else:
            args.listen_ip = ip

    if args.target_ip and not is_valid_ip4(args.target_ip):
        try:
            ip = socket.gethostbyname(args.target_ip)
        except socket.gaierror:
            ip = False
        if ip is False:
            print('%s is not a valid IP address or host name' % args.target_ip)
            sys.exit(2)
        else:
            args.target_ip = ip

    if args.rules:
        # Prepare the rule loader
        loader = RulesLoader()
        loader.setup(args)

    # Generate requested 'in' modules list
    # Append specific modules required by
    # provided parameters such as ssl or proxy
    if args.in_modules is not None:
        in_modules_list = args.in_modules.split(',')
    else:
        in_modules_list = []

    in_modules = generate_module_list(in_modules_list, args,  incoming=True)

    # Generate requested 'out' modules list
    # Append specific modules required by
    # provided parameters such as ssl or proxy
    if args.out_modules is not None:
        out_modules_list = args.out_modules.split(',')
    else:
        out_modules_list = []

    out_modules = generate_module_list(out_modules_list, args,  incoming=False)

    # this is the socket we will listen on for incoming connections
    proxy_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    proxy_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    try:
        proxy_socket.bind((args.listen_ip, args.listen_port))
    except socket.error as e:
        print(e.strerror)
        sys.exit(5)

    proxy_socket.listen(10)
    logger.info("Starting tcpproxy.py (%s)" % str(args))

    threads = []
    running = queue.Queue()

    # endless loop until ctrl+c
    try:
        while True:
            in_socket, in_addrinfo = proxy_socket.accept()
            connection_info(None, "Connection from %s:%d" % in_addrinfo, args)
            proxy_thread = threading.Thread(target=start_proxy_thread,
                                            args=(running,  in_socket, args, in_modules,
                                                  out_modules))
            connection_info(None, "Starting proxy thread %s " % str(proxy_thread.name), args)
            proxy_thread.start()
            threads.append(proxy_thread)
    except KeyboardInterrupt:
        print('\nCtrl+C detected, exiting...')
        connection_info(None, "Ctrl+C detected, exiting...", args)
        running.put(True)
        for thread in threads:
            connection_info(None, "Killing thread %s..." % str(thread.ident), args)
            if thread.is_alive():
                thread.join()
                connection_info(None, "Thread %s killed." % str(thread.ident), args)
            else:
                connection_info(None, "Thread %s already dead." % str(thread.ident), args)
        sys.exit(0)


if __name__ == '__main__':
    main()
