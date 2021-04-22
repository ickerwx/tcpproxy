import socket
from struct import unpack, pack

from protocol_tcp import ProtocolTCP

class ProtocolSOCKS(ProtocolTCP):
    
    name = "SOCKS5"
    
    # Code retrieved from pysoxy
    # https://github.com/MisterDaneel/pysoxy/blob/master/pysoxy.py
    #
    # Constants
    #
    '''Version of the protocol'''
    # PROTOCOL VERSION 5
    VER = b'\x05'
    '''Method constants'''
    # '00' NO AUTHENTICATION REQUIRED
    M_NOAUTH = b'\x00'
    # 'FF' NO ACCEPTABLE METHODS
    M_NOTAVAILABLE = b'\xff'
    '''Command constants'''
    # CONNECT '01'
    CMD_CONNECT = b'\x01'
    '''Address type constants'''
    # IP V4 address '01'
    ATYP_IPV4 = b'\x01'
    # DOMAINNAME '03'
    ATYP_DOMAINNAME = b'\x03'
    BUFSIZE = 2048
    
    dst_addr = None
    dst_port = None
    dst_hostname = None
    
    def subnegotiation_client(self):
        """
            The client connects to the server, and sends a version
            identifier/method selection message
        """
        # Client Version identifier/method selection message
        # +----+----------+----------+
        # |VER | NMETHODS | METHODS  |
        # +----+----------+----------+
        try:
            identification_packet = self.in_socket.recv(self.BUFSIZE)
        except socket.error:
            error()
            return self.M_NOTAVAILABLE
        # VER field
        if self.VER != identification_packet[0:1]:
            return self.M_NOTAVAILABLE
        # METHODS fields
        nmethods = identification_packet[1]
        methods = identification_packet[2:]
        if len(methods) != nmethods:
            return self.M_NOTAVAILABLE
        for method in methods:
            if method == ord(self.M_NOAUTH):
                return self.M_NOAUTH
        return self.M_NOTAVAILABLE
    
    def subnegotiation(self):
        """
            The client connects to the server, and sends a version
            identifier/method selection message
            The server selects from one of the methods given in METHODS, and
            sends a METHOD selection message
        """
        method = self.subnegotiation_client()
        # Server Method selection message
        # +----+--------+
        # |VER | METHOD |
        # +----+--------+
        if method != self.M_NOAUTH:
            return False
        reply = self.VER + method
        try:
            self.in_socket.sendall(reply)
        except socket.error:
            error()
            return False
        return True

    def request_client(self):
        """ Client request details """
        # +----+-----+-------+------+----------+----------+
        # |VER | CMD |  RSV  | ATYP | DST.ADDR | DST.PORT |
        # +----+-----+-------+------+----------+----------+
        try:
            s5_request = self.in_socket.recv(self.BUFSIZE)
        except ConnectionResetError:
            if self.in_socket != 0:
                self.in_socket.close()
            error()
            return False
        # Check VER, CMD and RSV
        if (
                s5_request[0:1] != self.VER or
                s5_request[1:2] != self.CMD_CONNECT or
                s5_request[2:3] != b'\x00'
        ):
            return False
        # IPV4
        if s5_request[3:4] == self.ATYP_IPV4:
            self.dst_addr = socket.inet_ntoa(s5_request[4:-2])
            self.dst_port = unpack('>H', s5_request[8:len(s5_request)])[0]
        # DOMAIN NAME
        elif s5_request[3:4] == self.ATYP_DOMAINNAME:
            sz_domain_name = s5_request[4]
            self.dst_hostname = s5_request[5: 5 + sz_domain_name - len(s5_request)]
            port_to_unpack = s5_request[5 + sz_domain_name:len(s5_request)]
            self.dst_port = unpack('>H', port_to_unpack)[0]
        else:
            return False
        return (self.dst_addr, self.dst_port)

    def request(self):
        """
            The SOCKS request information is sent by the client as soon as it has
            established a connection to the SOCKS server, and completed the
            authentication negotiations.  The server evaluates the request, and
            returns a reply
        """
        dst = self.request_client()
        # Server Reply
        # +----+-----+-------+------+----------+----------+
        # |VER | REP |  RSV  | ATYP | BND.ADDR | BND.PORT |
        # +----+-----+-------+------+----------+----------+
        rep = b'\x07'
        bnd = b'\x00' + b'\x00' + b'\x00' + b'\x00' + b'\x00' + b'\x00'
        # If client requested connection
        if dst:
            self.dst = dst
        # Don't connect yet this will be done by the incoming socket thread
        #    socket_dst = connect_to_dst(dst[0], dst[1])
        # If client request or connection to server is invalid
        if not dst:# or socket_dst == 0:
            rep = b'\x01'
        else:
            rep = b'\x00'
            bnd = socket.inet_aton(self.remote_socket.getsockname()[0])
            bnd += pack(">H", self.remote_socket.getsockname()[1])
        reply = self.VER + rep + b'\x00' + self.ATYP_IPV4 + bnd
        try:
            self.in_socket.sendall(reply)
        except socket.error:
            if self.in_socket != 0:
                self.in_socket.close()
            return False

        # start proxy
        if rep == b'\x00':
            return True
        else:
            return False

    def connect_source(self):
        if self.subnegotiation():
            return self.request()
            
    def set_connection(self,  conn):
        self.conn = conn
        if self.dst_hostname != None:
            self.conn.set_hostname(self.dst_hostname)
            if self.dst_addr == None:
                try:
                    self.dst_addr = socket.gethostbyname(self.dst_hostname)
                except socket.gaierror as ex:
                    self.conn.set_destination(("0.0.0.0",  self.dst_port))
                    self.connection_failed("remote", "Cannot resolve %s" % self.dst_hostname.decode("utf8"))
                    return False
        
        if self.dst_addr == None:
            return False
            
        self.conn.set_destination((self.dst_addr,  self.dst_port))
        return True
        
    def is_valid(self):
        # We actually expect a direct connection to the tcpproxy port but destination could be invalid
        return True
