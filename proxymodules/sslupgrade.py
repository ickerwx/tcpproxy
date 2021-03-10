#!/usr/bin/env python3
import sys
import os.path as path
from proxymodules.basemoduleredis import BaseModuleRedis
import ssl
import socket
import tempfile
from random import randint

try:
    import redis
except Exception:
    print("WARNING: cannot load pyredis. sslupgrade wont be able to cache generated certificates into redis")

try:
    import OpenSSL
    from OpenSSL import crypto
except Exception:
    print("WARNING: cannot load pyOpenSSL. sslupgrade module will only work with mode=file (default)")

try:
    from cryptography.hazmat.primitives import serialization
except Exception:
    print("WARNING: cannot load cryptography. sslupgrade module will only work with mode=file (default)")

class Module(BaseModuleRedis):

    def __init__(self, incoming=False, args=None, options=None):
        BaseModuleRedis.__init__(self, incoming, args, options)
        self.description = 'Upgrade connection to SSL automatically if requested by the client (ClientHello)'
        self.name = path.splitext(path.basename(__file__))[0]

        self.cache = True
        self.sslr = False
        self.sslc = False
        self.mode = "file"
        self.file = "mitm.pem"
        self.static_cn = None
        self.version = "PROTOCOL_TLS"
        self.server_version = "PROTOCOL_SSLv23"
        self.client = False
        self.ssl_client_socket = None
        self.ssl_client_info_init = None
        self.ssl_server_socket = None
        self.ssl_server_info_init = None
        self.ignore_servfail = False

        if options is not None:
            if 'mode' in options.keys():
                self.mode = options['mode']
                if self.mode not in ['file', 'fake', 'spoof', 'cafake', 'caspoof']:
                    self.missing("valid mode")

            if 'cn' in options.keys():
                self.static_cn = options['cn']
            if 'version' in options.keys():
                self.version = options['version']
            if 'server_version' in options.keys():
                self.server_version = options['server_version']
            if 'show' in options.keys():
                self.client = options['show'] == "True"
            if 'ignore_servfail' in options.keys():
                self.ignore_servfail = options['ignore_servfail'] == "True"
            if 'file' in options.keys():
                self.file = options['file']
            if 'nocache' in options.keys():
                self.cache = options['nocache'] == "True"

        if self.mode == "file":
            try:
                self.fakechain = open(self.file, 'r')
            except Exception as ex:
                self.log_error("Cannot load pem file %s: %s" % (self.file, str(ex)))
                self.missing("pemfile")
                return

        if self.mode != 'file':
            if 'OpenSSL' not in sys.modules:
                self.missing("OpenSSL")
            if 'cryptography' not in sys.modules:
                self.missing("cryptography")
            if self.redis_db == None:
                self.cache = False
                if self.mode in ['cafake', 'caspoof']:
                    self.missing("redis")

    def help(self):
        return '\tmode: certificate generation mode (newly generated certificates will be cached into redis) : file(default),fake,spoof,cafake,caspoof,ca\n' + '\tfile: where to load the certificate and key from in static mode (default:mitm.pem)\n' + '\tcn: force certificate CN\n' + '\tversion: use TLS version (PROTOCOL_SSLv2, PROTOCOL_SSLv3, PROTOCOL_TLSv1, PROTOCOL_TLSv1_1, PROTOCOL_TLSv1_2)\n' + '\tshow: show selected ciphers and client certificate requests\n' + '\tserver_version: use TLS version for server (PROTOCOL_SSLv23, PROTOCOL_SSLv2 ...)\n' + '\tignore_servfail: ignore server connection failure\n' + '\tnocache: disable caching on redis\n'


    def is_client_hello(self, firstbytes):
        return (len(firstbytes) >= 3 and
                firstbytes[0] in [0x16, 0x17] and
                firstbytes[1:3] in [b"\x03\x00",
                                b"\x03\x01",
                                b"\x03\x02",
                                b"\x03\x03",
                                b"\x02\x00"]
                )

    def set_orig_x509(self, asn):
        self.orig_x509 = crypto.load_certificate(crypto.FILETYPE_ASN1, asn)

    def get_fake_key(self):
        hostid = self.conn.hostname if self.conn.hostname else self.conn.dst
        hostid += ":"+str(self.conn.dstport)
        return self.get_or_gen_key(hostid)

    def get_fake_x509(self, pkey):
        hostid = self.conn.hostname if self.conn.hostname else self.conn.dst
        hostid += ":"+str(self.conn.dstport)

        self.log_trace("Retrieving fake certificate from Redis for "+hostid)

        return self.get_or_gen_x509(hostid, self.mode, pkey, static_cn=self.static_cn)

    def get_or_gen_key(self,hostid,allow_generic=True):

        hostid += ":key"

        # Trying to retrieve a host specific key
        pemkey = None
        if self.cache:
            pemkey = self.redis_db.get(hostid)
            if not pemkey and allow_generic:
                # Trying to retrieve the generic CA key
                hostid = "generic:key"
                pemkey = self.redis_db.get(hostid)

        if pemkey:
            self.log_trace("Retrieved fake key from Redis for "+hostid)
            pkey = crypto.load_privatekey(crypto.FILETYPE_PEM, pemkey)
        else:
            self.log_trace("Generating fake RSA keypair for "+hostid)
            pkey = crypto.PKey()
            pkey.generate_key(crypto.TYPE_RSA, 2048)
            pemkey = crypto.dump_privatekey(crypto.FILETYPE_PEM, pkey)
            if self.cache:
                self.redis_db.set(hostid, pemkey)

        return pkey,pemkey

    def get_or_gen_x509(self, hostid, mode, pkey, static_cn=""):

        hostid += ":x509:"+mode

        # Try first to load an existing certificate
        pemcert = None
        if self.cache:
            pemcert = self.redis_db.get(hostid)

        if pemcert:
            cert = crypto.load_certificate(crypto.FILETYPE_PEM, pemcert)
            return cert, pemcert

        # Failed to load an existing certificate. Generate a new one.
        cert = crypto.X509()
        cert.set_version(2)

        # Prepare the new certificate
        if mode in ["fake", "cafake", "ca"]:
            # Use a bulk organisation
            cert.get_subject().C = "LU"
            cert.get_subject().O = "TCPProxy"

            if static_cn:
                self.log_trace("adding static CN '%s' for certificate" % static_cn)

                # Uses a static CN
                cert.get_subject().CN = static_cn

                # Need to use subjectAltName or some clients such as chrome will generate a NET::ERR_CERT_COMMON_NAME_INVALID error message
                # Possible Values starts with URI: DNS: IP: dirName: (distinguished name) otherName: RID: (object ID, 1.2.3.4 for the CN)
                #ext = crypto.X509Extension("subjectAltName", False, str("IP:"+static_cn))
                ext = crypto.X509Extension(b"subjectAltName", False, b"RID:1.2.3.4")
                cert.add_extensions([ext])

            else:
                self.log_trace("adding spoofed CN '%s' for certificate" % self.orig_x509.get_subject().CN)

                # Spoof the server certificate CN
                cert.get_subject().CN = self.orig_x509.get_subject().CN

                # Spoof the server alternative name extension
                for i in range(0, self.orig_x509.get_extension_count()):
                    ext = self.orig_x509.get_extension(i)
                    if ext.get_short_name() == b"subjectAltName":
                        cert.add_extensions([ext])
                        self.log_trace("adding spoofed subjectAltName '%s' for certificate" % ext.get_data())

            # Add bulk serial and timestamps
            # Serial need to be random to avoid SEC_ERROR_REUSED_ISSUER_AND_SERIAL especially when using CA
            cert.set_serial_number(randint(0,100000000000))

            cert.gmtime_adj_notBefore(-4320000)
            cert.gmtime_adj_notAfter(4320000)

        elif mode in ["spoof", "caspoof"]:
            # Spoof the server Subject Organisation and CN
            cert.set_subject(self.orig_x509.get_subject())

            # Spoof the server serial number
            cert.set_serial_number(self.orig_x509.get_serial_number())

            # Spoof the server timestamps
            cert.set_notBefore(self.orig_x509.get_notBefore())
            cert.set_notAfter(self.orig_x509.get_notAfter())

            # Spoof the extensions:
            extensions = []
            for i in range(0, self.orig_x509.get_extension_count()):
                ext = self.orig_x509.get_extension(i)
                self.log_trace("Checking certificate extension to spoof: %d of %d" % (i,self.orig_x509.get_extension_count()))
                if ext.get_short_name() == b"UNDEF":
                    self.log_warning("Unsupported extension %s" % str(ext.get_data()))
                elif ext.get_short_name() == b"subjectKeyIdentifier":
                    self.log_warning("subjectKeyIdentifier spoofing may break certificate validity. Ignoring %s" % str(ext))
                elif ext.get_short_name() == b"authorityKeyIdentifier":
                    self.log_warning("authorityKeyIdentifier spoofing may break certificate validity. Ignoring %s" % str(ext))
                else:
                    self.log_trace("Adding extension to certificate: %s %s" % (ext.get_short_name().decode("utf-8"),str(ext)))#(ext.get_short_name(),ext.__str__())
                    extensions.append(ext)
            cert.add_extensions(extensions)

        # Sign the new certificate
        if mode in [ "fake" ]:
            # Self-signed so issuer is the subject
            cert.set_issuer(cert.get_subject())
            # Sign cert using the provided key (self-signed)
            sign_pkey = pkey
        elif mode in [ "spoof" ]:
            # Spoof the issuer, even if it does not match with the signature
            cert.set_issuer(self.orig_x509.get_issuer())
            # Sign cert using the provided key (self-signed)
            sign_pkey = pkey
        elif mode in [ "cafake", "caspoof" ]:
            # Retrieve the CA certificate
            ca_pkey, ca_keypem = self.get_or_gen_key("ca",allow_generic=False)
            ca_cert, ca_certpem = self.get_or_gen_x509("ca","ca",ca_pkey, static_cn="TCPProxy CA")
            if mode == "cafake":
                # Issuer is the CA certificate
                cert.set_issuer(ca_cert.get_subject())
            else:
                # Spoof the issuer, even if it does not match with the signature
                cert.set_issuer(self.orig_x509.get_issuer())

            # Sign cert using the ca_key
            sign_pkey = ca_pkey
        elif mode in [ "ca" ]:
            # Need to Add CA certificate extensions
            ext = crypto.X509Extension(b"basicConstraints", True, b"CA:TRUE")
            cert.add_extensions([ext])

            # CA certificates are self signed
            cert.set_issuer(cert.get_subject())
            sign_pkey = pkey

        # Sign the certificate
        cert.set_pubkey(pkey)
        cert.sign(sign_pkey, 'sha256')

        pemcert = crypto.dump_certificate(crypto.FILETYPE_PEM, cert)
        if self.cache:
            self.redis_db.set(hostid, pemcert)

        return cert, pemcert

    def wrap(self, sock):
        #self.log_trace("starting wrap"+str(sock)+str(self.sslr)+str(self.sslc))
        remote_socket,local_socket,sock = sock
        if self.sslr:
            # If socket is already wrapped
            if self.sslc and isinstance(sock, ssl.SSLSocket):
                return {}

            # Wrap socket
            if self.incoming:
                self.log_trace("Trying to wrap socket to SSL (incoming connection)")
            else:
                self.log_trace("Trying to wrap socket to SSL (outgoing connection)")

            remote_ssock, server_error_msg = self.wrap_server(remote_socket)
            if not remote_ssock:
                return {"error": "Server Side: "+server_error_msg}

            if self.mode == "file":
                self.log_info("Wrapping client connection with certificate retrieved from %s" % self.fakechain.name)
            else:
                pkey, pemkey = self.get_fake_key()
                cert, pemcert = self.get_fake_x509(pkey)

                # Load key and cert inside a tempfile for ssl.wrap
                self.fakechain = tempfile.NamedTemporaryFile()
                self.fakechain.write(pemkey)
                self.fakechain.write(pemcert)
                self.fakechain.seek(0)

                self.log_info("Wrapping client connection with certificate CN=%s generated with mode=%s" % (cert.get_subject().CN, self.mode))

            local_ssock, client_error_msg = self.wrap_client(local_socket)
            if not local_ssock:
                return {"error": "Client Side: "+client_error_msg}

            self.conn.add_tag("sslc")
            self.sslc = True
       
            return {"remote_socket":remote_ssock, "local_socket":local_ssock, "client_info":client_error_msg, "local_info":client_error_msg, "remote_info":server_error_msg}

        return {}

    def wrap_client(self, sock):
        # Wrap client socket
        try:
            version = getattr(ssl, self.version)
            context = ssl.SSLContext(version)# ssl.PROTOCOL_TLS) # PROTOCOL_SSLv2, PROTOCOL_SSLv3, PROTOCOL_TLSv1, PROTOCOL_TLSv1_1, PROTOCOL_TLSv1_2 
        except AttributeError as e1:
            self.log_error("SSL handshake failed for local socket: invalid TLS version : %s. Please use a version supported by python ssl (ex: PROTOCOL_TLS PROTOCOL_SSLv2 PROTOCOL_SSLv3 PROTOCOL_TLSv1 PROTOCOL_TLSv1_1 PROTOCOL_TLSv1_2)" % self.version)
            return None, "Invalid TLS version : "+self.version
        context.load_cert_chain(self.fakechain.name)

        # If client cert, try to request a certificate
        if self.client:
            #context.load_default_certs()
            context.verify_mode = ssl.CERT_OPTIONAL
            if hasattr(context,"set_cert_verify_callback"):
                self.log_trace("Using modified python SSL stack to disable client certificate verification")
                def verif(x,y):
                    return 1
                context.set_cert_verify_callback(verif)
            else:
                self.log_warning("Not possible to intercept client certificate requests as we need a modified python SSL stack (set_cert_verify_callback)")
        try:
            ssl_socket = context.wrap_socket(sock, server_side = True)
        except ssl.SSLError as e:
            self.log_error("SSL handshake failed for local socket"+str(e))
            return None, str(e)
        except Exception as e2:
            self.log_error("SSL handshake failed for local socket on a non ssl related Exception"+str(e2))
            return None, str(e2)

        self.ssl_client_socket = ssl_socket

        self.ssl_client_info_init = self.get_client_info()

        if self.ssl_client_info_init:
            self.log_info(self.ssl_client_info_init)

        return ssl_socket, self.ssl_client_info_init

    def get_client_info(self):
        if self.client:
            info = ""
            peercert = self.ssl_client_socket.getpeercert(binary_form = True)
            if peercert:
                peercert = crypto.load_certificate(crypto.FILETYPE_ASN1, peercert)
                info = "Client certificate:"+peercert.get_subject().CN+" Issuer:"+peercert.get_issuer().CN+"\n"
            info += "Client SSL protocol:"+self.ssl_client_socket.version().__str__()+"\n"
            info += "Client negotiated cipher:"+self.ssl_client_socket.cipher().__str__()+"\n"
            return info
        return None

    def wrap_server(self, sock):

        # Wrap server socket and parse certificate
        try:
            version = getattr(ssl, self.server_version)
            context = ssl.SSLContext(version) # PROTOCOL_TLS_CLIENT for Python3
        except AttributeError as e1:
            self.log_error("SSL handshake failed for remote socket: invalid TLS version : %s. Please use one of the supported version (PROTOCOL_SSLv23 PROTOCOL_SSLv2 PROTOCOL_SSLv3 PROTOCOL_TLSv1 PROTOCOL_TLSv1_1 PROTOCOL_TLSv1_2)" % self.server_version)
            return None, "Invalid TLS version : "+self.server_version

        # Disable all SSL security as we don't care in the context of the debugger
        # We want to inspect at any price
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        if self.conn.hostname:
            # Wrap with SNI
            ssl_socket = context.wrap_socket(sock, server_hostname=self.conn.hostname, do_handshake_on_connect=False)
        else:
            # Legacy wrap
            ssl_socket = context.wrap_socket(sock, do_handshake_on_connect=False)

        failed = False
        try:
            ssl_socket.do_handshake()
        except ssl.SSLError as e:
            failed = True
            self.log_error("SSL handshake failed for remote socket"+str(e))
            if not self.ignore_servfail:
                return None, str(e)
        except Exception as e2:
            failed = True
            self.log_error("SSL handshake failed for remote socket on a non ssl related Exception "+str(e2))
            if not self.ignore_servfail:
                return None, str(e2)

        if failed and self.ignore_servfail:
            #data = self.get_server_client_ca(force_list=True)
            #self.log_info(data)
            bulkcert = crypto.X509()
            bulkcert.set_version(2)
            bulkcert.get_subject().CN = "unknown"
            self.orig_x509 = bulkcert
            return sock, None

        # If mode = file we don't care about the server certificate
        if self.mode != "file":
            # Now retrieve the certificate
            # Take the binary for or it wont be loaded if the certificate is not trusted
            cert = ssl_socket.getpeercert(binary_form = True)
            
            self.set_orig_x509(cert)
            #print "Retrieved server certificate",self.orig_x509

        self.ssl_server_socket = ssl_socket

        self.ssl_server_info_init = self.get_server_info(force_list=True)

        if self.ssl_server_info_init:
            self.log_info(self.ssl_server_info_init)

        return ssl_socket, self.ssl_server_info_init

    def get_server_info(self, force_list=False):
        info = None
        if self.client:
            info = ""
            ca_names = self.get_server_client_ca(force_list)
            if ca_names:
                info += "Server proposed client CAs:"+ca_names.__str__()+"\n"
            info += "Server SSL protocol:"+self.ssl_server_socket.version().__str__()+"\n"
            info += "Server negotiated cipher:"+self.ssl_server_socket.cipher().__str__()
        return info

    def get_server_client_ca(self, force_list=False):
        ca_names = None
        # Check if we have a modified python SSL stack that provide get_client_ca_list
        if hasattr(self.ssl_server_socket._sslobj, "get_client_ca_list"):
            self.log_trace("Retrieving proposed server CAs using modified python SSL stack")
            ca_names = self.ssl_server_socket._sslobj.get_client_ca_list()
        elif force_list:
            self.log_trace("Retrieving proposed server CAs by creating a new server connection (modified python SSL stack not available)")
            # Creation of a new connection to the server for TLS client cert inspection.
            # After a full handshake has been performed, we are able to eventually retrieve
            # the proposed CA list using the default python stack.
            tmp_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            tmp_ctx = OpenSSL.SSL.Context(OpenSSL.SSL.SSLv23_METHOD)
            tmp_conn = OpenSSL.SSL.Connection(tmp_ctx, tmp_sock)
            if self.conn.hostname:
                tmp_dst = self.conn.hostname
            else:
                tmp_dst = self.conn.dst
            try:
                tmp_conn.connect((tmp_dst, self.conn.dstport))
                tmp_conn.do_handshake()
            except Exception as ex:
                self.log_warning("Failed to perform handshake for SSL Client inspection"+str(ex))
                return
            ca_names = tmp_conn.get_client_ca_list()
        else:
            self.log_trace("No method to retrieve proposed server CAs has been found (requires modified python SSL stack or 'force_list')")

        return ca_names

    def peek(self, data):
        if self.client and self.ssl_server_socket:
            server_info = self.get_server_info()
            if self.ssl_server_info_init and server_info != self.ssl_server_info_init:
                self.log_info("Server SSL Configuration changed after connection init:\n" + server_info)

        if self.client and self.ssl_client_socket:
            client_info = self.get_client_info()
            if self.ssl_client_info_init and client_info != self.ssl_client_info_init:
                self.log_info("Client SSL Configuration changed after connection init:\n" + client_info)

        # Only upgrade to SSL for outgoing traffic
        if self.incoming:
            return {}

        # Do not upgrade if a SSL connection has already been wrapped
        if self.sslc:
            return {}

        client_hello = self.is_client_hello(data)
        self.log_trace("Looking if packet is a TLS Hello "+str(client_hello))
        if client_hello:
            self.conn.add_tag("sslr")
            self.sslr = True
            return { "ssl_upgrade": True }

        return {}

if __name__ == '__main__':
    print ('This module is not supposed to be executed alone!')
