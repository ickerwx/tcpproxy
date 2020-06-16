#!/usr/bin/env  python3
import argparse
import pkgutil
import os
import sys
import threading
import socket
import socks
import ssl
import time
import select
import errno

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
                        help='remote target IP or host name')

    parser.add_argument('-tp', '--targetport', dest='target_port', type=int,
                        help='remote target port')

    parser.add_argument('-li', '--listenip', dest='listen_ip',
                        default='0.0.0.0', help='IP address/host name to listen for ' +
                        'incoming data')

    parser.add_argument('-lp', '--listenport', dest='listen_port', type=int,
                        default=8080, help='port to listen on')

    parser.add_argument('-pi', '--proxy-ip', dest='proxy_ip', default=None,
                        help='IP address/host name of proxy')

    parser.add_argument('-pp', '--proxy-port', dest='proxy_port', type=int,
                        default=1080, help='proxy port', )

    parser.add_argument('-pt', '--proxy-type', dest='proxy_type', default='SOCKS5', choices=['SOCKS4', 'SOCKS5', 'HTTP'],
                        help='proxy type. Options are SOCKS5 (default), SOCKS4, HTTP')

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

    parser.add_argument('-s', '--ssl', dest='use_ssl', action='store_true',
                        default=False, help='detect SSL/TLS as well as STARTTLS')

    parser.add_argument('-sc', '--server-certificate', default='mitm.pem',
                        help='server certificate in PEM format (default: %(default)s)')

    parser.add_argument('-sk', '--server-key', default='mitm.pem',
                        help='server key in PEM format (default: %(default)s)')

    parser.add_argument('-cc', '--client-certificate', default=None,
                        help='client certificate in PEM format in case client authentication is required by the target')

    parser.add_argument('-ck', '--client-key', default=None,
                        help='client key in PEM format in case client authentication is required by the target')

    return parser.parse_args()


def generate_module_list(modstring, incoming=False, verbose=False):
    # This method receives the comma-separated module list, imports the modules
    # and creates a Module instance for each module. A list of these instances
    # is then returned.
    # The incoming parameter is True when the modules belong to the incoming
    # chain (-im)
    # modstring looks like mod1,mod2:key=val,mod3:key=val:key2=val2,mod4 ...
    modlist = []
    namelist = modstring.split(',')
    for n in namelist:
        name, options = parse_module_options(n)
        try:
            __import__('proxymodules.' + name)
            modlist.append(sys.modules['proxymodules.' + name].Module(incoming, verbose, options))
        except ImportError:
            print('Module %s not found' % name)
            sys.exit(3)
    return modlist


def parse_module_options(n):
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
            print(op, ' is not valid!')
            sys.exit(23)
    return name, options


def list_modules():
    # show all available proxy modules
    cwd = os.getcwd()
    module_path = cwd + os.sep + 'proxymodules'
    for _, module, _ in pkgutil.iter_modules([module_path]):
        __import__('proxymodules.' + module)
        m = sys.modules['proxymodules.' + module].Module()
        print(f'{m.name} - {m.description}')


def print_module_help(modlist):
    # parse comma-separated list of module names, print module help text
    modules = generate_module_list(modlist)
    for m in modules:
        try:
            print(f'{m.name} - {m.description}')
            print(m.help())
        except AttributeError:
            print('\tNo options or missing help() function.')


def update_module_hosts(modules, source, destination):
    # set source and destination IP/port for each module
    # source and destination are ('IP', port) tuples
    # this can only be done once local and remote connections have been established
    if modules is not None:
        for m in modules:
            if hasattr(m, 'source'):
                m.source = source
            if hasattr(m, 'destination'):
                m.destination = destination


def receive_from(s):
    # receive data from a socket until no more data is there
    b = b""
    while True:
        data = s.recv(4096)
        b += data
        if not data or len(data) < 4096:
            break
    return b


def handle_data(data, modules, dont_chain, incoming, verbose):
    # execute each active module on the data. If dont_chain is set, feed the
    # output of one plugin to the following plugin. Not every plugin will
    # necessarily modify the data, though.
    for m in modules:
        vprint(("> > > > in: " if incoming else "< < < < out: ") + m.name, verbose)
        if dont_chain:
            m.execute(data)
        else:
            data = m.execute(data)
    return data


def is_client_hello(sock):
    firstbytes = sock.recv(128, socket.MSG_PEEK)
    return (len(firstbytes) >= 3 and
            firstbytes[0] == 0x16 and
            firstbytes[1:3] in [b"\x03\x00",
                                b"\x03\x01",
                                b"\x03\x02",
                                b"\x03\x03",
                                b"\x02\x00"]
            )


def enable_ssl(args, remote_socket, local_socket):
    try:
        local_socket = ssl.wrap_socket(local_socket,
                                       server_side=True,
                                       certfile=args.server_certificate,
                                       keyfile=args.server_key,
                                       ssl_version=ssl.PROTOCOL_TLSv1_2,
                                       )
    except ssl.SSLError as e:
        print("SSL handshake failed for listening socket", str(e))
        raise

    try:
        if args.client_certificate and args.client_key:
            remote_socket = ssl.wrap_socket(remote_socket,
                                            certfile=args.client_certificate,
                                            keyfile=args.client_key,
                                            )
        else:
            remote_socket = ssl.wrap_socket(remote_socket)
    except ssl.SSLError as e:
        print("SSL handshake failed for remote socket", str(e))
        raise

    return [remote_socket, local_socket]


def starttls(args, local_socket, read_sockets):
    return (args.use_ssl and
            local_socket in read_sockets and
            not isinstance(local_socket, ssl.SSLSocket) and
            is_client_hello(local_socket)
            )


def start_proxy_thread(local_socket, args, in_modules, out_modules):
    # This method is executed in a thread. It will relay data between the local
    # host and the remote host, while letting modules work on the data before
    # passing it on.
    remote_socket = socks.socksocket()

    if args.proxy_ip:
        proxy_types = {'SOCKS5': socks.SOCKS5, 'SOCKS4': socks.SOCKS4, 'HTTP': socks.HTTP}
        remote_socket.set_proxy(proxy_types[args.proxy_type], args.proxy_ip, args.proxy_port)

    try:
        remote_socket.connect((args.target_ip, args.target_port))
        vprint('Connected to %s:%d' % remote_socket.getpeername(), args.verbose)
        log(args.logfile, 'Connected to %s:%d' % remote_socket.getpeername())
    except socket.error as serr:
        if serr.errno == errno.ECONNREFUSED:
            for s in [remote_socket, local_socket]:
                s.close()
            print(f'{time.strftime("%Y%m%d-%H%M%S")}, {args.target_ip}:{args.target_port}- Connection refused')
            log(args.logfile, f'{time.strftime("%Y%m%d-%H%M%S")}, {args.target_ip}:{args.target_port}- Connection refused')
            return None
        elif serr.errno == errno.ETIMEDOUT:
            for s in [remote_socket, local_socket]:
                s.close()
            print(f'{time.strftime("%Y%m%d-%H%M%S")}, {args.target_ip}:{args.target_port}- Connection timed out')
            log(args.logfile, f'{time.strftime("%Y%m%d-%H%M%S")}, {args.target_ip}:{args.target_port}- Connection timed out')
            return None
        else:
            for s in [remote_socket, local_socket]:
                s.close()
            raise serr

    try:
        update_module_hosts(out_modules, local_socket.getpeername(), remote_socket.getpeername())
        update_module_hosts(in_modules, remote_socket.getpeername(), local_socket.getpeername())
    except socket.error as serr:
        if serr.errno == errno.ENOTCONN:
            # kind of a blind shot at fixing issue #15
            # I don't yet understand how this error can happen, but if it happens I'll just shut down the thread
            # the connection is not in a useful state anymore
            for s in [remote_socket, local_socket]:
                s.close()
            return None
        else:
            for s in [remote_socket, local_socket]:
                s.close()
            print(f"{time.strftime('%Y%m%d-%H%M%S')}: Socket exception in start_proxy_thread")
            raise serr

    # This loop ends when no more data is received on either the local or the
    # remote socket
    running = True
    while running:
        read_sockets, _, _ = select.select([remote_socket, local_socket], [], [])

        if starttls(args, local_socket, read_sockets):
            try:
                ssl_sockets = enable_ssl(args, remote_socket, local_socket)
                remote_socket, local_socket = ssl_sockets
                vprint("SSL enabled", args.verbose)
                log(args.logfile, "SSL enabled")
            except ssl.SSLError as e:
                print("SSL handshake failed", str(e))
                log(args.logfile, "SSL handshake failed", str(e))
                break

            read_sockets, _, _ = select.select(ssl_sockets, [], [])

        for sock in read_sockets:
            try:
                peer = sock.getpeername()
            except socket.error as serr:
                if serr.errno == errno.ENOTCONN:
                    # kind of a blind shot at fixing issue #15
                    # I don't yet understand how this error can happen, but if it happens I'll just shut down the thread
                    # the connection is not in a useful state anymore
                    for s in [remote_socket, local_socket]:
                        s.close()
                    running = False
                    break
                else:
                    print(f"{time.strftime('%Y%m%d-%H%M%S')}: Socket exception in start_proxy_thread")
                    raise serr

            data = receive_from(sock)
            log(args.logfile, 'Received %d bytes' % len(data))

            if sock == local_socket:
                if len(data):
                    log(args.logfile, b'< < < out\n' + data)
                    if out_modules is not None:
                        data = handle_data(data, out_modules,
                                           args.no_chain_modules,
                                           False,  # incoming data?
                                           args.verbose)
                    remote_socket.send(data.encode() if isinstance(data, str) else data)
                else:
                    vprint("Connection from local client %s:%d closed" % peer, args.verbose)
                    log(args.logfile, "Connection from local client %s:%d closed" % peer)
                    remote_socket.close()
                    running = False
                    break
            elif sock == remote_socket:
                if len(data):
                    log(args.logfile, b'> > > in\n' + data)
                    if in_modules is not None:
                        data = handle_data(data, in_modules,
                                           args.no_chain_modules,
                                           True,  # incoming data?
                                           args.verbose)
                    local_socket.send(data)
                else:
                    vprint("Connection to remote server %s:%d closed" % peer, args.verbose)
                    log(args.logfile, "Connection to remote server %s:%d closed" % peer)
                    local_socket.close()
                    running = False
                    break


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
        if not args.target_ip:
            print('Target IP is required: -ti')
            sys.exit(6)
        if not args.target_port:
            print('Target port is required: -tp')
            sys.exit(7)

    if ((args.client_key is None) ^ (args.client_certificate is None)):
        print("You must either specify both the client certificate and client key or leave both empty")
        sys.exit(8)

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
        print_module_help(args.help_modules)
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

    if not is_valid_ip4(args.target_ip):
        try:
            ip = socket.gethostbyname(args.target_ip)
        except socket.gaierror:
            ip = False
        if ip is False:
            print('%s is not a valid IP address or host name' % args.target_ip)
            sys.exit(2)
        else:
            args.target_ip = ip

    if args.in_modules is not None:
        in_modules = generate_module_list(args.in_modules, incoming=True, verbose=args.verbose)
    else:
        in_modules = None

    if args.out_modules is not None:
        out_modules = generate_module_list(args.out_modules, incoming=False, verbose=args.verbose)
    else:
        out_modules = None

    # this is the socket we will listen on for incoming connections
    proxy_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    proxy_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    try:
        proxy_socket.bind((args.listen_ip, args.listen_port))
    except socket.error as e:
        print(e.strerror)
        sys.exit(5)

    proxy_socket.listen(100)
    log(args.logfile, str(args))
    # endless loop until ctrl+c
    try:
        while True:
            in_socket, in_addrinfo = proxy_socket.accept()
            vprint('Connection from %s:%d' % in_addrinfo, args.verbose)
            log(args.logfile, 'Connection from %s:%d' % in_addrinfo)
            proxy_thread = threading.Thread(target=start_proxy_thread,
                                            args=(in_socket, args, in_modules,
                                                  out_modules))
            log(args.logfile, "Starting proxy thread " + proxy_thread.name)
            proxy_thread.start()
    except KeyboardInterrupt:
        log(args.logfile, 'Ctrl+C detected, exiting...')
        print('\nCtrl+C detected, exiting...')
        sys.exit(0)


if __name__ == '__main__':
    main()
