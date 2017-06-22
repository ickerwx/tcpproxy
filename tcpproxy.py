#!/usr/bin/env  python2
import argparse
import pkgutil
import os
import sys
import threading
import socket
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

    parser.add_argument('-ti', '--targetip', dest='target_ip', required=True,
                        help='remote target IP')

    parser.add_argument('-tp', '--targetport', dest='target_port', type=int,
                        help='remote target port', required=True)

    parser.add_argument('-li', '--listenip', dest='listen_ip',
                        default='0.0.0.0', help='IP address to listen for ' +
                        'incoming data')

    parser.add_argument('-lp', '--listenport', dest='listen_port', type=int,
                        default=8080, help='port to listen on')

    parser.add_argument('-om', '--outmodules', dest='out_modules',
                        help='comma-separated list of modules to modify data' +
                             ' before sending to remote target.')

    parser.add_argument('-im', '--inmodules', dest='in_modules',
                        help='comma-separated list of modules to modify data' +
                             ' received from the remote target.')

    parser.add_argument('-t', '--timeout', dest='timeout', type=float, default=5,
                        help='Socket timeout to wait for incoming data')

    parser.add_argument('-v', '--verbose', dest='verbose', default=False,
                        action='store_true',
                        help='More verbose output of status information')

    parser.add_argument('-r', '--receivefirst', dest='receive_first',
                        action='store_true', default=False,
                        help='Receive data from remote first, e.g. a banner')

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
                        default=False, help='use SSL, certificate is mitm.pem')

    parser.add_argument('-a', '--starttls', dest='use_starttls', action='store_true',
                        default=False, help='use STARTTLS, certificate is mitm.pem')

    return parser.parse_args()


def generate_module_list(modstring, incoming=False):
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
            modlist.append(sys.modules['proxymodules.' + name].Module(incoming, options))
        except ImportError:
            print 'Module %s not found' % name
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
            print op, ' is not valid!'
            sys.exit(23)
    return name, options


def list_modules():
    # show all available proxy modules
    cwd = os.getcwd()
    module_path = cwd + os.sep + 'proxymodules'
    for _, module, _ in pkgutil.iter_modules([module_path]):
        __import__('proxymodules.' + module)
        m = sys.modules['proxymodules.' + module].Module()
        print '%s - %s' % (m.name, m.description)


def print_module_help(modlist):
    # parse comma-separated list of module names, print module help text
    modules = generate_module_list(modlist)
    for m in modules:
        try:
            print m.name
            print m.help()
        except AttributeError:
            print '\tNo options.'


def receive_from(s, timeout):
    # receive data from a socket until no more data is there or until timeout
    b = ""
    #  s.settimeout(timeout)
    while True:
        data = s.recv(4096)
        b += data
        if not data or len(data)<4096:
            break
    return b


def handle_data(data, modules, dont_chain, verbose=False):
    # execute each active module on the data. If dont_chain is set, feed the
    # output of one plugin to the following plugin. Not every plugin will
    # necessarily modify the data, though.
    for m in modules:
        print ("> > > > in: " if m.incoming else "< < < < out: ") + m.name
        if dont_chain:
            m.execute(data)
        else:
            data = m.execute(data)
    return data


def is_client_hello(sock):
    firstbytes = sock.recv(128, socket.MSG_PEEK)
    return (len(firstbytes) >= 3 and
            firstbytes[0] == "\x16" and
            firstbytes[1:3] in [ "\x03\x00",
                                 "\x03\x01",
                                 "\x03\x02",
                                 "\x03\x03",
                                 "\x02\x00", ]
        )


def enable_ssl(remote_socket, local_socket):
    local_socket = ssl.wrap_socket(local_socket,
                server_side=True,
                certfile="mitm.pem",
                keyfile="mitm.pem",
                #  ssl_version=ssl.PROTOCOL_SSLv23,
              )

    remote_socket = ssl.wrap_socket(remote_socket)
    return [remote_socket, local_socket]


def waiting_for_starttls(local_socket, read_sockets):
    return (args.use_starttls and
        local_socket in read_sockets and
        not isinstance(local_socket, ssl.SSLSocket) and
        is_client_hello(local_socket)
       )

def start_proxy_thread(local_socket, args, in_modules, out_modules):
    # This method is executed in a thread. It will relay data between the local
    # host and the remote host, while letting modules work on the data before
    # passing it on.
    remote_socket = socket.socket()
    if args.use_ssl:
        remote_socket = ssl.wrap_socket(remote_socket)

    try:
        remote_socket.connect((args.target_ip, args.target_port))
    except socket.error as serr:
        if serr.errno == errno.ECONNREFUSED:
            print '%s:%d - Connection refused' % (args.target_ip,
                                                  args.target_port)
            return None
        else:
            raise serr

    # This loop ends when no more data is received on either the local or the
    # remote socket
    running = True
    while running:
        read_sockets, _, _ = select.select([remote_socket, local_socket], [], [])

        if waiting_for_starttls(local_socket, read_sockets):
            try:
                if args.verbose:
                    print "Enable SSL"
                ssl_sockets = enable_ssl(remote_socket, local_socket)
            except ssl.SSLError as e:
                print "SSL handshake failed", str(e)
                break

            read_sockets, _, _ = select.select(ssl_sockets, [], [])

        for sock in read_sockets:
            data = receive_from(sock, args.timeout)
            if len(data)==0:
                if args.verbose:
                    print "Connection closed"
                remote_socket.close()
                local_socket.close()
                running = False
                break

            if sock == local_socket:
                log(args.logfile, '< < < out\n' + data)
                if out_modules is not None:
                    data = handle_data(data, out_modules,
                                           args.no_chain_modules, args.verbose)
                remote_socket.send(data)
            elif sock == remote_socket:
                log(args.logfile, '> > > in\n' + data)
                if in_modules is not None:
                    in_data = handle_data(data, in_modules,
                                          args.no_chain_modules, args.verbose)
                local_socket.send(data)



def log(handle, message, message_only=False):
    # if message_onlz is True, only the message will be logged
    # otherwise the message will be prefixed with a timestamp and a line is
    # written after the message to make the log file easier to write
    if handle is None:
        return
    if not message_only:
        logentry = "%s %s\n" % (time.strftime('%Y%m%d-%H%M%S'),
                                 str(time.time()))
    else:
        logentry = ''
    logentry += message
    if not message_only:
        logentry += '\n' + '-' * 20 + '\n'
    handle.write(logentry)


def main():
    args = parse_args()
    if args.logfile is not None:
        try:
            args.logfile = open(args.logfile, 'a', 0)  # unbuffered
        except Exception as ex:
            print 'Error opening logfile'
            print ex
            sys.exit(4)

    if args.list:
        list_modules()
        sys.exit(0)

    if args.help_modules is not None:
        print_module_help(args.help_modules)
        sys.exit(0)

    if args.listen_ip != '0.0.0.0' and not is_valid_ip4(args.listen_ip):
        print '%s is not a valid IP address' % args.listen_ip
        sys.exit(1)

    if not is_valid_ip4(args.target_ip):
        print '%s is not a valid IP address' % args.target_ip
        sys.exit(2)

    if args.in_modules is not None:
        in_modules = generate_module_list(args.in_modules, True)
    else:
        in_modules = None

    if args.out_modules is not None:
        out_modules = generate_module_list(args.out_modules)
    else:
        out_modules = None

    # this is the socket we will listen on for incoming connections
    proxy_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    proxy_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    try:
        proxy_socket.bind((args.listen_ip, args.listen_port))
    except socket.error as e:
        print e.strerror
        sys.exit(5)

    proxy_socket.listen(10)
    log(args.logfile, str(args))
    # endless loop until ctrl+c
    try:
        while True:
            in_socket, in_addrinfo = proxy_socket.accept()
            if args.verbose:
                print 'Connection from %s:%d' % in_addrinfo
            if args.use_ssl:
                in_socket = ssl.wrap_socket(in_socket, certfile="mitm.pem",
                                        keyfile="mitm.pem",
                                        do_handshake_on_connect=False,
                                        server_side=True,
                                        ssl_version=ssl.PROTOCOL_SSLv23)
            proxy_thread = threading.Thread(target=start_proxy_thread,
                                            args=(in_socket, args, in_modules,
                                                  out_modules))
            log(args.logfile, "Starting proxy thread")
            proxy_thread.start()
    except KeyboardInterrupt:
        log(args.logfile, 'Ctrl+C detected, exiting...')
        print '\nCtrl+C detected, exiting...'
        sys.exit(0)


if __name__ == '__main__':
    main()
