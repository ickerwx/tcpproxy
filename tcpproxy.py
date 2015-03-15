#!/usr/bin/env  python2
import argparse
import pkgutil
import os
import sys
import threading
import socket

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

    parser.add_argument('-li', '--listenip', dest='listen_ip',
                        default='0.0.0.0', help='IP address to listen for ' +
                        'incoming data')

    parser.add_argument('-ti', '--targetip', dest='target_ip',
                        help='remote target IP')

    parser.add_argument('-lp', '--listenport', dest='listen_port', type=int,
                        default=8080, help='port to listen on')

    parser.add_argument('-tp', '--targetport', dest='target_port', type=int,
                        help='remote target port')

    parser.add_argument('-om', '--outmodules', dest='out_modules',
                        help='comma-separated list of modules to modify data' +
                             ' before sending to remote target.')

    parser.add_argument('-im', '--inmodules', dest='in_modules',
                        help='comma-separated list of modules to modify data' +
                             ' received from the remote target.')

    parser.add_argument('-t', '--timeout', dest='timeout', type=int, default=5,
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

    parser.add_argument('-l', '--list', dest='list', action='store_true',
                        help='list available modules')

    return parser.parse_args()


def generate_module_list(modstring):
    # This method receives the comma-separated module list, imports the modules
    # and creates a Module instance for each module. A list of these instances
    # is then returned.
    modlist = []
    if modstring == 'all':
        cwd = os.getcwd()
        # all modules must exist in the proxymodules directory
        module_path = cwd + os.sep + 'proxymodules'
        for _, n, _ in pkgutil.iter_modules([module_path]):
            __import__('proxymodules.' + n)
            modlist.append(sys.modules['proxymodules.' + n].Module())
    else:
        namelist = modstring.split(',')
        for n in namelist:
            try:
                __import__('proxymodules.' + n)
                modlist.append(sys.modules['proxymodules.' + n].Module())
            except ImportError:
                print 'Module %s not found' % n
                sys.exit(3)
    return modlist


def list_modules():
    # show all available proxy modules
    cwd = os.getcwd()
    module_path = cwd + os.sep + 'proxymodules'
    for _, module, _ in pkgutil.iter_modules([module_path]):
        __import__('proxymodules.' + module)
        print '%s - %s' % (module, sys.modules['proxymodules.' +
                                               module].Module().description)
    print 'all - use all available modules'


def receive_from(s, timeout):
    # receive data from a socket until no more data is there or until timeout
    b = ""
    s.settimeout(timeout)
    try:
        while True:
            data = s.recv(4096)
            if not data:
                break
            b += data
    except:
        pass
    return b


def handle_data(data, modules, dont_chain):
    # execute each active module on the data. If dont_chain is set, feed the
    # output of one plugin to the following plugin. Not every plugin will
    # necessarily modify the data, though.
    for m in modules:
        if dont_chain:
            m.execute(data)
        else:
            data = m.execute(data)
    return data


def start_proxy_thread(local_socket, args, in_modules, out_modules):
    # This method is executed in a thread. It will relay data between the local
    # host and the remote host, while letting modules work on the date before
    # passing it on.
    remote_socket = socket.socket()
    remote_socket.connect((args.target_ip, args.target_port))
    in_data = ''  # incoming data, intended for the local host
    out_data = ''  # outgoing data, intended for the remote host

    # instead of sending data to the remote host, receive some data first.
    # might be necessary to read banners, etc.
    if args.receive_first:
        in_data = receive_from(remote_socket, args.timeout)
        if len(in_data):
            if in_modules is not None:
                in_data = handle_data(in_data, in_modules, args.chain_modules)
            local_socket.send(in_data)

    # This loop ends when no more data is received on either the local or the
    # remote socket
    while True:
        out_data = receive_from(local_socket, args.timeout)
        if len(out_data):
            if out_modules is not None:
                out_data = handle_data(out_data, out_modules,
                                       args.no_chain_modules)
            remote_socket.send(out_data)

        in_data = receive_from(remote_socket, args.timeout)
        if len(in_data):
            if in_modules is not None:
                in_data = handle_data(in_data, in_modules,
                                      args.no_chain_modules)
            local_socket.send(in_data)

        if not len(in_data) or not len(out_data):
            # no more data on one of the sockets, exit the loop and return
            local_socket.close()
            remote_socket.close()
            break


def main():
    args = parse_args()
    if args.list:
        list_modules()
        sys.exit(0)

    if args.listen_ip != '0.0.0.0' and not is_valid_ip4(args.listen_ip):
        print '%s is not a valid IP address' % args.listen_ip
        sys.exit(1)

    if not is_valid_ip4(args.target_ip):
        print '%s is not a valid IP address' % args.target_ip
        sys.exit(2)

    if args.in_modules is not None:
        in_modules = generate_module_list(args.in_modules)
    else:
        in_modules = None

    if args.out_modules is not None:
        out_modules = generate_module_list(args.out_modules)
    else:
        out_modules = None

    # this is the socket we will listen on for incoming connections
    proxy_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    try:
        proxy_socket.bind((args.listen_ip, args.listen_port))
    except socket.error, e:
        print e.strerror
        sys.exit(5)

    proxy_socket.listen(10)

    # endless loop until ctrl+c
    try:
        while True:
            in_socket, in_addrinfo = proxy_socket.accept()
            if args.verbose:
                print 'Connection from %s:%d' % in_addrinfo

            proxy_thread = threading.Thread(target=start_proxy_thread,
                                            args=(in_socket, args, in_modules,
                                                  out_modules))
            proxy_thread.start()
    except KeyboardInterrupt:
        print '\nCtrl+C detected, exiting...'
        sys.exit(0)


if __name__ == '__main__':
    main()
