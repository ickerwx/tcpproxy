#!/usr/bin/env  python3
import argparse
import pkgutil
import os
import sys
import threading
import socket
import socks
import ssl
import struct
import time
import select
import errno
import logging
import logging.config
import builtins
from filter import CSVFilters

FORMAT = ('%(asctime)-15s %(threadName)-15s %(levelname)-8s %(module)-15s %(message)s')
logging.basicConfig(format=FORMAT)
logger = logging.getLogger(__name__)
builtins.logger = logger

loglevels = {'CRITICAL': logging.CRITICAL, 'ERROR': logging.ERROR, 'WARNING': logging.WARNING, 'INFO': logging.INFO, 'DEBUG': logging.DEBUG}

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
                        type = str.upper, help='proxy type. Options are SOCKS5 (default), SOCKS4, HTTP')

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

    parser.add_argument('-l', '--log-level', dest='log_level', default='INFO', choices=['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL'],
                        help='Logging level (verbosity)')

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

    parser.add_argument('-od', '--original-destination', dest='orig_dest',
                        action='store_true', default=False,
                        help='use SO_ORIGINAL_DST (if supported by OS) instead of static options -ti/-tp')

    parser.add_argument('-f', '--filters', dest='filters', default=None,
                        help='IDS/IPS mode, specify a CSV file with alert/filters configurations for out modules')

    parser.add_argument('-lc', '--log-config', dest='log_config', default=None,
                        help='Logging configuration file (mutually exclusive with -l --loglevel)')

    return parser.parse_args()


def generate_module_list(modstring, incoming=False, loglevel=logging.INFO, filters=[]):
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
            modlist.append(sys.modules['proxymodules.' + name].Module(incoming, loglevel, options, filters))
        except ImportError:
            logger.critical('Module %s not found' % name)
            sys.exit(3)

    # Avoid duplicates, put default '*' module at the end of list
    modlist = list({i.name:i for i in reversed(modlist)}.values())
    oldindex = next((i for i, item in enumerate(modlist) if item.name == '*'), None)
    if oldindex:
        modlist.insert(len(modlist), modlist.pop(oldindex))
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
            logger.critical('%s is not valid!' % op)
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


def receive_from(s):
    # receive data from a socket until no more data is there
    b = b""
    while True:
        data = s.recv(4096)
        b += data
        if not data or len(data) < 4096:
            break
    return b

def handle_data(modules, no_chain, source, destination, data):
    for m in modules:
        if no_chain:
            m.execute(data, source, destination)
        else:
            data = m.execute(data, source, destination)
        if hasattr(m, 'detection') and m.detection == True:
            break
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
    sni = None

    def sni_callback(sock, name, ctx):
        nonlocal sni
        sni = name

    try:
        ctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        ctx.sni_callback = sni_callback
        ctx.load_cert_chain(certfile=args.server_certificate,
                            keyfile=args.server_key,
                            )
        local_socket = ctx.wrap_socket(local_socket,
                                       server_side=True,
                                       )
    except ssl.SSLError as e:
        logger.error("SSL handshake failed for listening socket: %s" % str(e))
        raise

    try:
        ctx = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        if args.client_certificate and args.client_key:
            ctx.load_cert_chain(certfile=args.client_certificate,
                                keyfile=args.client_key,
                                )
        remote_socket = ctx.wrap_socket(remote_socket,
                                        server_hostname=sni,
                                        )
    except ssl.SSLError as e:
        logger.error("SSL handshake failed for remote socket %s" % str(e))
        raise

    return [remote_socket, local_socket]


def starttls(args, local_socket, read_sockets):
    return (args.use_ssl and
            local_socket in read_sockets and
            not isinstance(local_socket, ssl.SSLSocket) and
            is_client_hello(local_socket)
            )


def connections_drop(reset, local_socket, remote_socket, reason):
    addr, port = remote_socket.getpeername()
    if reset == True:
        l_onoff = 1
        l_linger = 0
        local_socket.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack('ii', l_onoff, l_linger))
        remote_socket.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack('ii', l_onoff, l_linger))
        logger.warning("Connection to remote server %s:%d rejected (%s)" % (addr, port, reason))
    else:
        logger.warning("Connection to remote server %s:%d dropped (%s)" % (addr, port, reason))
    for s in [remote_socket, local_socket]:
        s.shutdown(socket.SHUT_RDWR)
        s.close()

def start_proxy_thread(local_socket, args, in_modules, out_modules):
    # This method is executed in a thread. It will relay data between the local
    # host and the remote host, while letting modules work on the data before
    # passing it on.
    remote_socket = socks.socksocket()

    if args.proxy_ip:
        proxy_types = {'SOCKS5': socks.SOCKS5, 'SOCKS4': socks.SOCKS4, 'HTTP': socks.HTTP}
        remote_socket.set_proxy(proxy_types[args.proxy_type], args.proxy_ip, args.proxy_port)
    if args.orig_dest:
        SO_ORIGINAL_DST = 80
        SOCKADDR_MIN = 16
        sockaddr_in = local_socket.getsockopt(socket.SOL_IP, SO_ORIGINAL_DST, SOCKADDR_MIN)
        (proto, port, a, b, c, d) = struct.unpack('!HHBBBB', sockaddr_in[:8])
        assert(socket.htons(proto) == socket.AF_INET)
        args.target_ip = '%d.%d.%d.%d' % (a, b, c, d)
        args.target_port = port

    try:
        remote_socket.connect((args.target_ip, args.target_port))
        logger.info('Connected to %s:%d' % remote_socket.getpeername())
    except socket.error as serr:
        if serr.errno == errno.ECONNREFUSED:
            for s in [remote_socket, local_socket]:
                s.close()
            logger.warning('%s:%d - Connection refused' % (args.target_ip, args.target_port))
            return None
        elif serr.errno == errno.ETIMEDOUT:
            for s in [remote_socket, local_socket]:
                s.close()
            logger.warning('%s:%d - Connection timed out' % (args.target_ip, args.target_port))
            return None
        else:
            for s in [remote_socket, local_socket]:
                s.close()
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
                logger.info("SSL enabled")
            except ssl.SSLError as e:
                logger.error("SSL handshake failed %s" % str(e))
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
                    logger.error('Socket exception in start_proxy_thread')
                    raise serr

            try:
                data = receive_from(sock)
                logger.debug('Received %d bytes' % len(data))
            except ConnectionResetError as e:
                logger.warning(str(e))
                return

            # moved here to use dynamic remote_socket determined by SO_ORIGINAL_DESTINATION
            try:
                (local, remote) = local_socket.getpeername(), remote_socket.getpeername()
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
                    logger.error('Socket exception in start_proxy_thread')
                    raise serr
            if sock == local_socket:
                if len(data):
                    if out_modules:
                        try:
                            data = handle_data(out_modules, args.no_chain_modules, local, remote, data)
                        except Drop as e:
                            connections_drop(False, local_socket, remote_socket, str(e))
                            return
                        except Reject as e:
                            connections_drop(True, local_socket, remote_socket, str(e))
                            return
                    remote_socket.send(data.encode() if isinstance(data, str) else data)
                else:
                    logger.info("Connection from local client %s:%d closed" % peer)
                    remote_socket.close()
                    running = False
                    break
            elif sock == remote_socket:
                if len(data):
                    if in_modules:
                        handle_data(in_modules, args.no_chain_modules, remote, local, data)
                    local_socket.send(data)
                else:
                    logger.info("Connection to remote server %s:%d closed" % peer)
                    local_socket.close()
                    running = False
                    break

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
        if not args.target_ip and not args.orig_dest:
            logger.critical('Target IP is required: -ti or Original destination -od')
            sys.exit(6)
        if not args.target_port and not args.orig_dest:
            logger.critical('Target port is required: -tp or Original destination -od')
            sys.exit(7)

    if ((args.client_key is None) ^ (args.client_certificate is None)):
        logger.critical("You must either specify both the client certificate and client key or leave both empty")
        sys.exit(8)

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
            logger.critical('%s is not a valid IP address or host name' % args.listen_ip)
            sys.exit(1)
        else:
            args.listen_ip = ip

    if not args.orig_dest and not is_valid_ip4(args.target_ip):
        try:
            ip = socket.gethostbyname(args.target_ip)
        except socket.gaierror:
            ip = False
        if ip is False:
            logger.critical('%s is not a valid IP address or host name' % args.target_ip)
            sys.exit(2)
        else:
            args.target_ip = ip

    filters = []
    if args.filters is not None:
        try:
            filters = CSVFilters(args.filters)
        except (FileNotFoundError, ValueError) as e:
            logger.critical(str(e))
            sys.exit(3)

    if args.in_modules is not None:
        in_modules = generate_module_list(args.in_modules, incoming=True, loglevel=loglevels[args.log_level])
    else:
        in_modules = []

    if args.out_modules is not None:
        out_modules = generate_module_list(args.out_modules, incoming=False, loglevel=loglevels[args.log_level], filters=filters)
    else:
        out_modules = []

    # this is the socket we will listen on for incoming connections
    proxy_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    proxy_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    try:
        proxy_socket.bind((args.listen_ip, args.listen_port))
    except socket.error as e:
        logger.error(e.strerror)
        sys.exit(5)

    proxy_socket.listen(100)
    # endless loop until ctrl+c
    try:
        while True:
            in_socket, in_addrinfo = proxy_socket.accept()
            logger.info('Connection from %s:%d' % in_addrinfo)
            proxy_thread = threading.Thread(target=start_proxy_thread,
                                            args=(in_socket, args, in_modules,
                                                  out_modules))
            proxy_thread.start()
    except KeyboardInterrupt:
        logger.warning('\nCtrl+C detected, exiting...')
        sys.exit(0)


if __name__ == '__main__':
    main()
