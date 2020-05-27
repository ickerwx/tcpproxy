#!/usr/bin/env  python3
import argparse
import pkgutil
import os
import sys
import threading
import socket
import time
import select
import errno
import queue
import ssl

# ConnData is an object that contains basic information about the connection.
# Plugins can also use this object to exchange connection or status information.
from conndata import ConnData

# TODO: implement verbose output
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

    parser.add_argument('-v', '--verbose', dest='verbose', default=False,
                        action='store_true',
                        help='More verbose output of status information')

    parser.add_argument('-n', '--no-chain', dest='no_chain_modules',
                        action='store_true', default=False,
                        help='Don\'t send output from one module to the ' +
                             'next one')

    parser.add_argument('-l', '--log', dest='logfile', default=None,
                        help='Log all data to a file before modules are run.')

    parser.add_argument('--list', dest='list', action='store_true',
                        help='list available modules')

    parser.add_argument('-lo', '--list-options', dest='help_modules', default=None,
                        help='Print help of selected module')

    return parser.parse_args()

def load_module(n, args, incoming=False, prematch=None, conn_obj=None):
    name, options = parse_module_options(n, args, conn_obj)
    try:
        __import__('proxymodules.' + name)
        if hasattr(sys.modules['proxymodules.' + name], "Module"):
            mod = sys.modules['proxymodules.' + name].Module(incoming, args.verbose, options)
            mod.prematch = prematch
            return mod
        else:
            connection_warning("none","Invalid module %s: cannot load class 'Module'" % name, args, conn_obj)
            return None
    except ImportError as ex:
        connection_warning("none","Cannot load module %s: %s" % (name,str(ex)), args, conn_obj)
        return None
        #sys.exit(3)

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
            connection_warning("none","Argument %s for module %s is not valid" % (op, name), args, conn_obj)
            #sys.exit(23)
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
            mlist[m.name] = m.description
            if hasattr(m, 'help') and callable(getattr(m, 'help')):
                mlist[m.name] += "\n"
                mlist[m.name] += m.help()
    return mlist

def list_modules():
    # show all available proxy modules
    for name, description in get_modules_list().items():
        print ('%s - %s' % (name, description))

def print_module_help(modliststr,  args):
    # parse comma-separated list of module names, print module help text
    namelist = modliststr.split(',')
    modules = generate_module_list(namelist, args)
    for m in modules:
        try:
            print(m.name)
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
                    m.source = conn_obj.source
                if hasattr(m, 'destination'):
                    m.destination = conn_obj.destination

def receive_from(s):
    # receive data from a socket until no more data is there
    b = b""
    while True:
        data = s.recv(4096)
        b += data
        if not data or len(data) < 4096:
            break
    return b


def handle_data(data, modules, args, incoming, conn_obj):
    # execute each active module on the data. If no_chain_modules is set, feed the
    # output of one plugin to the following plugin. Not every plugin will
    # necessarily modify the data, though.
    for m in modules:
        if hasattr(m,"execute") and callable(m.execute):
            vprint(("> > > > in: " if incoming else "< < < < out: ") + m.name, args.verbose)
            try:
                if args.no_chain_modules:
                    m.execute(data)
                else:
                    data = m.execute(data)
            except Exception as ex:
                connection_failed(m.name,ex.__str__(),args,conn_obj)

    return data


def peek_data(data, modules, args, incoming, conn_obj):
    # execute each active module on the peeked data
    peeks = {}
    for m in modules:
        if hasattr(m,"peek") and callable(m.peek):
            vprint(("> > > > in " if incoming else "< < < < out ") + m.name + " peek", args.verbose)
            if args.no_chain_modules:
                m.peek(data)
            else:
                peeks.update(m.peek(data))

    return peeks


def wrap_socket(sock, modules, args, incoming, conn_obj):
    wraps = {}
    for m in modules:
        if hasattr(m,"wrap") and callable(m.wrap):
            vprint(("> > > > in: " if incoming else "< < < < out ") + m.name + " wrap", args.verbose)
            try:
                if args.no_chain_modules:
                    m.wrap(sock)
                else:
                    if "remote_socket" in wraps:
                        vprint("Wrap remote socket following last wrap", args.verbose)
                        sock = [wraps["remote_socket"],sock[1],sock[2]]
                    if "local_socket" in wraps:
                        vprint("Wrap local socket following last wrap", args.verbose)
                        sock = [wraps[0],wraps["local_socket"],sock[2]]
                    wraps.update(m.wrap(sock))
            except Exception as ex:
                connection_failed(m.name+" wrapping",ex.__str__(), args, conn_obj)
                import traceback
                traceback.print_exc()

    return wraps


def start_proxy_thread(trunning,  local_socket, args, in_modules, out_modules):
    # This method is executed in a thread. It will relay data between the local
    # host and the remote host, while letting modules work on the data before
    # passing it on.
    remote_socket = socket.socket()

    # Create conn obj based on known information about the connection.
    try:
        conn_obj = ConnData(
            source=local_socket.getpeername(),
            destination=(args.target_ip,args.target_port),
            dest_socket=local_socket
        )
    except Exception as err:
        connection_failed("none",  err.__str__(),  args)
        return None

    # TODO improve error check by verifying all Local IP addresses (if listen_ip is not used)
    if (conn_obj.dst == args.listen_ip and conn_obj.dstport == args.listen_port):
        connection_failed("server",  "Attempt to connect to TCPProxy itself cancelled",  args,  conn_obj)
        return None

    try:
        remote_socket.connect((conn_obj.dst, conn_obj.dstport))
        vprint('Connected to %s:%d' % remote_socket.getpeername(), args.verbose)
        log(args.logfile, 'Connected to %s:%d' % remote_socket.getpeername())
    except socket.error as serr:
        if serr.errno == errno.ECONNREFUSED:
            connection_failed("server","connection refused", args, conn_obj)
            #return None
        else:
            connection_failed("server","connection error "+serr.__str__(),args,conn_obj)
            #raise serr

    update_module_hosts(out_modules, conn_obj)
    update_module_hosts(in_modules, conn_obj)

    # This loop ends when no more data is received on either the local or the
    # remote socket
    running = True
    while running and trunning.qsize() <= 0:
        read_sockets, _, _ = select.select([remote_socket, local_socket], [], [])

        # Before execution data modules, run peek and wrap modules
        for sock in read_sockets:
            # First peek data
            try:
                # If socket has support for peeking, retrieve the first 1024 bytes
                if hasattr(sock, "peek") and callable(sock.peek):
                    firstbytes = sock.peek(1024)
                # Python SSL module typically does not support socket peeking
                elif isinstance(sock, ssl.SSLSocket):
                    firstbytes = ""
                # Last try by using the MSG_PEEK API
                else:
                    firstbytes = sock.recv(1024, socket.MSG_PEEK)
            except Exception as err:
                connection_failed("client" if sock==local_socket else "server", "Cannot peek socket: "+err.__str__(), args, conn_obj)
                return None

            if sock == local_socket:
                peeks = peek_data(firstbytes, out_modules, args, sock==remote_socket,  conn_obj)
            else:
                peeks = peek_data(firstbytes, in_modules, args, sock==remote_socket,  conn_obj)

            # Wrapping comes next
            # We parse read socket but we probably need to wrap remote socket first anyway
            if sock == local_socket:
                wraps = wrap_socket([remote_socket, local_socket, sock], out_modules, args, sock==remote_socket, conn_obj)
            else:
                wraps = wrap_socket([remote_socket, local_socket, sock], in_modules, args, sock==remote_socket, conn_obj)

            # Retrieve the last wrapped socket in the chain as our "normal" socket
            if "local_socket" in wraps:
                local_socket = wraps["local_socket"]
            if "remote_socket" in wraps:
                remote_socket = wraps["remote_socket"]

            # If there have been wrapping, read the data from the wrapped sockets
            if "local_socket" in wraps or "remote_socket" in wraps:
                read_sockets, _, _ = select.select([local_socket, remote_socket], [], [])

        # Finally retrieve data from socket
        for sock in read_sockets:
            try:
                data = receive_from(sock)
                running = handle_data_read(sock, data, args, local_socket, remote_socket, in_modules, out_modules, conn_obj)
            except Exception as err:
                connection_failed("client" if sock==local_socket else "server", err.__str__(), args, conn_obj)
                return None

def handle_data_read(sock, data, args, local_socket, remote_socket, in_modules, out_modules, conn_obj):

    # Retrieve peer for loggin purposes
    peer = sock.getpeername()

    if args.logfile:
        log(args.logfile, 'Received %d bytes from %s' % (len(data),peer))

    if sock == local_socket:
        if len(data):
            log(args.logfile, b'< < < out\n' + data)
            data = handle_data(data, out_modules,
                                args,
                                False,  # incoming data?
                                conn_obj
            )
            remote_socket.send(data.encode() if isinstance(data, str) else data)
        else:
            vprint("Connection from local client %s:%d closed" % peer, args.verbose)
            log(args.logfile, "Connection from local client %s:%d closed" % peer)
            remote_socket.close()
            return False

    elif sock == remote_socket:
        if len(data):
            log(args.logfile, b'> > > in\n' + data)
            data = handle_data(data, in_modules,
                                args,
                                True,  # incoming data?
                                conn_obj
            )
            local_socket.send(data)
        else:
            vprint("Connection to remote server %s:%d closed" % peer, args.verbose)
            log(args.logfile, "Connection to remote server %s:%d closed" % peer)
            local_socket.close()
            return False

    return True

def connection_failed(direction, msg, args, conn_obj=None):
    if conn_obj:
        error_msg = '%s FAILED for connection to %s:%d - %s' % (direction, conn_obj.dst, conn_obj.dstport, msg)
    else:
        error_msg = 'FAILED: %s' % (msg)
    print(error_msg)
    log(args.logfile, error_msg)

def connection_warning(direction, msg, args, conn_obj=None):
    if conn_obj:
        warning_msg = '%s WARNING while connecting to %s:%d - %s' % (direction, conn_obj.dst, conn_obj.dstport, msg)
    else:
        warning_msg = 'WARNING: %s' % (msg)
    print(warning_msg)
    log(args.logfile, warning_msg)

def log(handle, message, message_only=False):
    # if message_only is True, only the message will be logged
    # otherwise the message will be prefixed with a timestamp and a line is
    # written after the message to make the log file easier to read
    if not isinstance(message, bytes):
        message = bytes(message, 'ascii')
    if handle is None:
        return
    if not message_only:
        logentry = bytes("%s %s\n" % (time.strftime('%Y%m%d-%H%M%S'), str(time.time())), 'ascii')
    else:
        logentry = b''
    logentry += message
    if not message_only:
        logentry += b'\n' + b'-' * 20 + b'\n'
    handle.write(logentry)


def vprint(msg, is_verbose):
    # this will print msg, but only if is_verbose is True
    if is_verbose:
        print(msg)


def main():
    args = parse_args()
    if args.list is False and args.help_modules is None:
        if args.target_port and not args.target_ip:
            print('Both target IP and target Ports are required: missing -ti')
            sys.exit(6)
        if args.target_ip and not args.target_port:
            print('Both target IP and target Ports are required: missing -tp')
            sys.exit(7)

    if args.logfile is not None:
        try:
            args.logfile = open(args.logfile, 'ab', 0)  # unbuffered
        except Exception as ex:
            print('Error opening logfile')
            print(ex)
            sys.exit(4)

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
        out_modules_list =  args.out_modules.split(',')
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
    log(args.logfile, str(args))

    threads=[]
    running = queue.Queue()

    # endless loop until ctrl+c
    try:
        while True:
            in_socket, in_addrinfo = proxy_socket.accept()
            vprint('Connection from %s:%d' % in_addrinfo, args.verbose)
            log(args.logfile, 'Connection from %s:%d' % in_addrinfo)
            proxy_thread = threading.Thread(target=start_proxy_thread,
                                            args=(running,  in_socket, args, in_modules,
                                                  out_modules))
            log(args.logfile, "Starting proxy thread " + proxy_thread.name)
            proxy_thread.start()
            threads.append(proxy_thread)
    except KeyboardInterrupt:
        log(args.logfile, 'Ctrl+C detected, exiting...')
        print('\nCtrl+C detected, exiting...')
        running.put(True)
        for thread in threads:
            print("Killing thread",thread.ident,"...",)
            if thread.is_alive():
                thread.join()
                print("killed.")
            else:
                print("already dead.")
        sys.exit(0)


if __name__ == '__main__':
    main()
