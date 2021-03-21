import struct
import socket
import errno

class ProtocolTCP():
    
    name = "TCP"

    def connection_failed(self, direction, msg):
        if self.conn:
            error_msg = 'Failed connection with %s : %s' % (direction,  msg)
        else:
            error_msg = '%s' % (msg)
        logger.error(error_msg, extra={'conn':self.conn, 'direction':direction})

    def connection_warning(self, direction, msg):
        if self.conn:
            warning_msg = 'Connection with %s : %s' % (direction,  msg)
        else:
            warning_msg = '%s' % (msg)
        logger.warning(warning_msg, extra={'conn':self.conn, 'direction':direction})

    def connection_debug(self, direction, msg):
        if self.conn:
            debug_msg = 'Connection with %s : %s' % (direction,  msg)
        else:
            debug_msg = '%s' % (msg)
        logger.debug(debug_msg, extra={'conn':self.conn, 'direction':direction})

    def connection_info(self, direction, msg):
        if self.conn:
            info_msg = 'Connection with %s : %s' % (direction,  msg)
        else:
            info_msg = '%s' % msg
        logger.info(info_msg, extra={'conn':self.conn, 'direction':direction})

    def __init__(self, in_socket,  args):
        self.in_socket = in_socket
        
        self.args = args
        #print("Client IN socket:",self.in_socket )
        self.remote_socket = socket.socket()
        #print("Server OUT socket", self.remote_socket )
        
        # Set timeout to 5 seconds by default to get faster failure feedback
        self.remote_socket.settimeout(self.args.timeout)

    def connect_destination(self):
        try:
            self.remote_socket.connect((self.conn.dst, self.conn.dstport))
            self.connection_info("remote", "Connected to %s:%d" % self.remote_socket.getpeername())
            return True
        except socket.error as serr:
            # Do not shutdown socket there as it will be selected on the reading loop
            if serr.errno == errno.ECONNREFUSED:
                self.connection_failed("remote","connection refused")
            elif serr.errno == errno.ETIMEDOUT:
                self.connection_failed("remote","connection timed out")
            else:
                self.connection_failed("remote","connection error "+serr.__str__())
        
        return False
    
    def get_sockets(self):
        return [self.remote_socket, self.in_socket]

    def connect_source(self):
        return True

    def is_local(self,  sock):
        #print("is_local",sock == self.in_socket, sock )
        return sock == self.in_socket
        
    def is_remote(self, sock):
        return sock == self.remote_socket

    def wrap_local(self,  sock):
        self.in_socket = sock
        
    def wrap_remote(self,  sock):
        self.remote_socket = sock

    def shutdown_local(self):
        try:
            self.in_socket.shutdown(socket.SHUT_RDWR)
            self.in_socket.close()
        except:
            pass

    def shutdown_remote(self):
        try:
            self.remote_socket.shutdown(socket.SHUT_RDWR)
            self.remote_socket.close()
        except:
            pass

    def send_remote(self,  data):
        self.remote_socket.send(data)

    def send_local(self,  data):
        self.in_socket.send(data)

    def read(self, s):
        # receive data from a socket until no more data is there
        b = b""
        while True:
            data = s.recv(4096)
            b += data
            if not data or len(data) < 4096:
                break
        return b

    def set_connection(self,  conn):
        self.conn = conn

        if self.args.target_ip == None:
            self.conn.set_destination(self.get_realdest())
        else:
            self.conn.set_destination((self.args.target_ip, self.args.target_port))

    # Retrieve the destination address and port of the connection
    def get_realdest(self):
        # SO_ORIGINAL_DST option is set when iptable REDIRECT target are used
        # and allows retrieving the original socket destination IP and port (if supported)
        SOCKADDR_MIN = 16
        try:
            socket.SO_ORIGINAL_DST
        except AttributeError:
            # This is often not defined as valid socket option. Lets force it
            socket.SO_ORIGINAL_DST = 80

        # Use the Linux specific socket option to query NetFilter
        try:
            odestdata = self.in_socket.getsockopt(socket.SOL_IP, socket.SO_ORIGINAL_DST, SOCKADDR_MIN)
        except FileNotFoundError:
            raise Exception("Cannot initiate connection in transparent proxy mode (get socket destination from Netfilter failed).")

        # Unpack the first 6 bytes, which hold the destination data needed
        proto, port, a1, a2, a3, a4 = struct.unpack("!HHBBBBxxxxxxxx", odestdata)
        assert(socket.htons(proto) == socket.AF_INET)
        address = "%d.%d.%d.%d" % (a1, a2, a3, a4)

        return (address, port)

    def is_valid(self):
        # Check that it is not a direct connection to the tcpproxy port
        return self.conn.dst != None and self.conn.dst != "0.0.0.0" and (self.conn.dst , self.conn.dstport) != self.in_socket.getsockname()
