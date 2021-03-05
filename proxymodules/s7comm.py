#!/usr/bin/env python3
import os.path as path
import struct
import builtins
import logging
import threading

# Definitions and classes forked from icssploit protocols https://github.com/tijldeneut/icssploit

COTP_PDU_TYPE = {0xe0: "CR", 0xd0: "CC", 0xf0: "DT"}
COTP_PARAMETER_CODE = {0xc0: "tpdu-size", 0xc1: "src-tsap", 0xc2: "dst-tsap"}

S7_PDU_TYPE = {0x01: "Job", 0x02: "Ack", 0x03: "AckData", 0x07: "UserData"}

S7_JB_FUNCTION = {
    0x00: "CPU services (0x00)",
    0x04: "Read Var (0x04)",
    0x05: "Write Var (0x05)",
    0x1a: "Request download (0x1a)",
    0x1b: "Download block (0x1b)",
    0x1c: "Download ended (0x1c)",
    0x1d: "Start upload (0x1d)",
    0x1e: "Upload (0x1e)",
    0x1f: "End upload (0x1f)",
    0x28: "PI-Service (0x28)",
    0x29: "PLC Stop (0x29)",
    0xf0: "Setup communication (0xf0)"
}

S7_TRANSPORT_SIZE_IN_DATA_ITEMS = {
    0x00: "Null (0x00)",                #
    0x01: "BIT (0x01)",                 # Bit access, len is in bits
    0x03: "BIT (0x03)",                 # Bit access, len is in bits
    0x04: "BYTE/WORD/DWORD (0x04)",     # BYTE/WORD/DWORD access, len is in bits
    0x05: "INTEGER (0x05)",             # Integer access, len is in bits
    0x06: "DINTEGER (0x06)",            # Integer access, len is in bytes
    0x07: "Real (0x07)",                # Real access, len is in bytes
    0x09: "Str (0x09)"                  # Octet string, len is in bytes
}

S7_AREA_TYPE = {
    0x03: "SYSInfo",        # System info of 200 family
    0x05: "SYSFlags",       # System flags of 200 family
    0x06: "ANAIn",          # Analog inputs of 200 family
    0x07: "ANAOut",         # Analog outputs of 200 family
    0x80: "P",              # Direct peripheral access
    0x81: "Input",
    0x82: "Output",
    0x83: "Flags",
    0x84: "DB",             # Data blocks
    0x85: "DI",             # Instance data blocks
    0x86: "Local",          # Local data (should not be accessible over network) */
    0x87: "V",              # Previous (Vorgaenger) local data (should not be accessible over network)
    0x1c: "Counter",        # S7 counters
    0x1d: "Timer",          # S7 timers
    0x1e: "Counter200",     # IEC counters (200 family)
    0x1f: "Timer200"        # IEC timers (200 family)
}

S7_RETURN_CODE = {
    0x00: "Reserved (0x00)",
    0x0a: "Object does not exist (0x0a)",
    0xff: "success (0xff)"
}


S7_SZL_METHODS = {
    0x11: "Request (0x11)",
    0x12: "Response (0x12)"
}

S7_UD_FUNCTION_GROUP = {
    0x0: "Mode-transition",
    0x1: "Programmer commands",
    0x2: "Cyclic data",
    0x3: "Block functions",
    0x4: "CPU functions",
    0x5: "Security",
    0x6: "PBC BSEND/BRECV",
    0x7: "Time functions",
    0xf: "NC programming"
}

S7_UD_PARAMETER_TYPE = {
    0x0: "Push",
    0x4: "Request",
    0x8: "Response",
    0x3: "NC Push",                     # used only by Sinumerik NC
    0x7: "NC Request",                  # used only by Sinumerik NC
    0xb: "NC Response",                 # used only by Sinumerik NC
}

S7_UD_SUB_FUNCTION_PROG = {
    0x01: "Request diag data (Type 1) (0x01)",  # Start online block view
    0x02: "VarTab (0x02)",                      # Variable table
    0x0c: "Erase (0x0c)",
    0x0e: "Read diag data (0x0e)",              # Online block view
    0x0f: "Remove diag data (0x0f)",            # Stop online block view
    0x10: "Forces (0x10)",
    0x13: "Request diag data (Type 2) (0x13)"   # Start online block view

}

S7_UD_SUB_FUNCTION_PROG = {
    0x01: "Request diag data (Type 1) (0x01)",  # Start online block view
    0x02: "VarTab (0x02)",                      # Variable table
    0x0c: "Erase (0x0c)",
    0x0e: "Read diag data (0x0e)",              # Online block view
    0x0f: "Remove diag data (0x0f)",            # Stop online block view
    0x10: "Forces (0x10)",
    0x13: "Request diag data (Type 2) (0x13)"   # Start online block view

}

S7_UD_SUB_FUNCTION_CYCLIC = {
    0x01: "Memory (0x01)",                      # read data from memory (DB/M/etc.)
    0x04: "Unsubscribe (0x04)"                  # Unsubscribe (disable) cyclic data
}

S7_UD_SUB_FUNCTION_BLOCK = {
    0x01: "List blocks (0x01)",
    0x02: "List blocks of type (0x02)",
    0x03: "Get block info (0x03)"
}

S7_UD_SUB_FUNCTION_CPU = {
    0x01: "Read SZL (0x01)",
    0x02: "Message service (0x02)",
    0x03: "Diagnostic message (0x03)",
    0x05: "ALARM_8 indication (0x05)",
    0x06: "NOTIFY indication (0x06)",
    0x07: "ALARM_8 lock (0x07)",
    0x08: "ALARM_8 unlock (0x08)",
    0x0b: "ALARM ack (0x0b)",
    0x0c: "ALARM ack indication (0x0c)",
    0x0d: "ALARM lock indication (0x0d)",
    0x0e: "ALARM unlock indication (0x0e)",
    0x11: "ALARM_SQ indication (0x11)",
    0x12: "ALARM_S indication (0x12)",
    0x13: "ALARM query (0x13)",
    0x16: "NOTIFY_8 indication (0x16)"
}

S7_UD_SUB_FUNCTION_SEC = {
    0x01: "PLC password (0x01)",
    0x02: "Clean session (0x02)"
}

S7_UD_SUB_FUNCTION_TIME = {
    0x01: "Read clock (0x01)",
    0x02: "Set clock (0x02)",
    0x03: "Read clock (following) (0x03)",
    0x04: "Set clock (0x04)"

}

S7_SUB_FUNCTIONS = {
    # Mode-transition (0x0)
    0x00: {},
    # Programmer commands (0x01)
    0x01: S7_UD_SUB_FUNCTION_PROG,
    # Cyclic data (0x02)
    0x02: S7_UD_SUB_FUNCTION_CYCLIC,
    # Block functions (0x03)
    0x03: S7_UD_SUB_FUNCTION_BLOCK,
    # CPU functions (0x04)
    0x04: S7_UD_SUB_FUNCTION_CPU,
    # Security (0x05)
    0x05: S7_UD_SUB_FUNCTION_SEC,
    # PBC BSEND/BRECV (0x06)
    0x06: {},
    # Time functions (0x07)
    0x07: S7_UD_SUB_FUNCTION_TIME,
    # NC programming (0x0f)
    0x0f: {}
}

S7_SZL_BZU_ID_NAMES = {
    0x0: "Unknown",
    0x1: "STOP (update)",
    0x2: "STOP (memory reset)",
    0x3: "STOP (self initialization)",
    0x4: "STOP (internal)",
    0x5: "Startup (complete restart)",
    0x7: "Restart",
    0x8: "RUN",
    0xa: "HOLD",
    0xd: "DEFECT"
}

class TPKTPacket:
    """ TPKT packet. RFC 1006
    """
    def __init__(self, data=''):
        self.data = data

    def unpack(self,packet):
        try:
            header = struct.unpack('!BBH', packet[:4])
        except struct.error as e:
            raise S7ProtocolError("Unknown TPKT format")
        self.data = packet[4:4+header[2]]
        self.version = header[0]
        self.reserved = header[1]
        self.packet_length = header[2]
        self.payload = packet[4:4 + header[2]]
        self.audit = 'TPKT version %d len %d' % (self.version, self.packet_length)
        return self

class COTPConnectionPacket:
    """ COTP Connection Request or Connection Confirm packet (ISO on TCP). RFC 1006
    """
    def __init__(self, dst_ref=0, src_ref=0, dst_tsap=0, src_tsap=0, tpdu_size=0):
        self.dst_ref    = dst_ref
        self.src_ref    = src_ref
        self.dst_tsap   = dst_tsap
        self.src_tsap   = src_tsap
        self.tpdu_size  = tpdu_size

    def unpack(self, packet):
        """ parse Connection Confirm Packet (header only)
        """
        header_size = 18
        try:
            size, pdu_type, self.dst_ref, self.src_ref, flags, _, _, self.tpdu_size, _, _, self.src_tsap, _, _, self.dst_tsap = struct.unpack('!BBHHBBBBBBHBBH', packet[:header_size])
        except struct.error as e:
            raise S7ProtocolError("Wrong CR/CC packet format")
        if len(packet) != size + 1:
            raise S7ProtocolError("Wrong CR/CC packet size")
        if pdu_type not in (0xd0, 0xe0):
            raise S7ProtocolError("Not a CR/CC packet")
        self.parameters = packet[header_size:]
        self.audit = 'COTP %s (0x%02x) TPDU size %d source TSAP 0x%04x destination TSAP 0x%04x' % (COTP_PDU_TYPE[pdu_type], pdu_type, 2 ^ self.tpdu_size, self.src_tsap, self.dst_tsap)
        if self.dst_tsap & 0xff:
            self.audit += ' (rack %d slot %d)' % ((self.dst_tsap & 0xff) >> 4, self.dst_tsap & 0xf)
        return self

class COTPDataPacket:
    """ COTP Data packet (ISO on TCP). RFC 1006
    """
    def __init__(self, data=''):
        self.data = data

    def unpack(self, packet):
        try:
            header = struct.unpack('!BBB', packet[:3])
        except struct.error:
            raise S7ProtocolError("Wrong DT packet format")
        self.packet_length = header[0]
        self.tpdu_type = int(header[1])
        if self.tpdu_type != 0xf0:
            raise S7ProtocolError("Not a DT packet")
        self.trailer = packet[1 + self.packet_length:]
        if self.tpdu_type == 0xf0:
            # the DT DATA TPDU features another header byte that shifts our structure
            self.opt_field = header[2]
            self.payload = packet[3:1 + self.packet_length]
        else:
            self.payload = packet[2:1 + self.packet_length]
        self.data = self.payload
        self.audit = 'COTP %s (0x%02x)' % (COTP_PDU_TYPE[self.tpdu_type], self.tpdu_type)
        return self

class S7Packet:
    """ S7 packet
    """
    def __init__(self, type=1, req_id=0, parameters='', data=''):
        self.type       = type
        self.req_id     = req_id
        self.parameters = parameters
        self.data       = data
        self.error      = 0

    def unpack(self, packet):
        try:
            if packet[1] in [2,3]:   # pdu-type = response
                header_size = 12
                magic, self.type, reserved, self.req_id, parameters_length, data_length, self.error = struct.unpack('!BBHHHHH', packet[:header_size])
                if self.error:
                    raise S7Error(self.error)
            elif packet[1] in [1,7]:
                header_size = 10
                magic, self.type, reserved, self.req_id, parameters_length, data_length = struct.unpack('!BBHHHH', packet[:header_size])
            else:
                raise S7ProtocolError("Unknown pdu type (%d)" % packet[1])
        except struct.error as e:
            raise S7ProtocolError("Wrong S7 packet format")

        self.parameters = packet[header_size:header_size+parameters_length]
        self.data = packet[header_size+parameters_length:header_size+parameters_length+data_length]
        self.audit = "S7Packet ROSCTR %s (0x%02x) PDU reference 0x%04x" % (S7_PDU_TYPE[self.type], self.type, self.req_id)
        return self


class S7WriteVarParameterReq:
    def __init__(self, parameters=''):
        self.parameters = parameters
        self.area = 0
        self.db_num = 0
        self.address = 0

    def unpack(self, packet=None):
        (function, count) = struct.unpack('!BB', self.parameters[:2])
        if function != 0x05:
            raise S7ProtocolError("Not a WritVar parameter")
        self.audit = '%s Request ' % S7_JB_FUNCTION[function]
        if count:
            self.audit += 'Item count %d: ' % count
        offset = 2
        item = 1
        while (count):
            (variable_specification, param_length, syntax_id, transport_size, get_length, block_num, area_type, addr1, addr2, addr3) = struct.unpack('!BBBBHHBBBB', self.parameters[offset:offset+12])
            address = (addr1 << 16) | (addr2 << 8) | addr3
            self.area = area_type
            self.db_num = block_num
            self.address = address
            descr = '[%d] %s%d.DBX%d' % (item, S7_AREA_TYPE[area_type], block_num, (address >> 3))
            if transport_size in [1,3]:
                descr += '.%d' % (address & 7)
            descr += ' '
            self.audit += descr
            offset += 2 + param_length
            item += 1
            count -= 1
        params = S7ParseParameters(parameters=self.parameters).unpack(packet)
        self.audit += '( '
        self.audit += params.audit
        self.audit += ')'
        return self

class S7ReadVarParameterReq:
    def __init__(self, parameters=''):
        self.parameters = parameters
        self.area = 0
        self.db_num = 0
        self.address = 0

    def unpack(self, packet=None):
        (function, count) = struct.unpack('!BB', self.parameters[:2])
        if function != 0x04:
            raise S7ProtocolError("Not a ReadVar parameter")
        self.audit = '%s Request ' % S7_JB_FUNCTION[function]
        if count:
            self.audit += 'Item count %d: ' % count
        offset = 2
        item = 1
        while (count):
            (variable_specification, param_length, syntax_id, transport_size, get_length, block_num, area_type, addr1, addr2, addr3) = struct.unpack('!BBBBHHBBBB', self.parameters[offset:offset+12])
            address = (addr1 << 16) | (addr2 << 8) | addr3
            self.area = area_type
            self.db_num = block_num
            self.address = address
            descr = '[%d] %s%d.DBX%d' % (item, S7_AREA_TYPE[area_type], block_num, (address >> 3))
            if transport_size in [1,3]:
                descr += '.%d' % (address & 7)
            descr += ' '
            self.audit += descr
            offset += 2 + param_length
            item += 1
            count -= 1
        return self

class S7ParseParameters:
    def __init__(self, parameters=''):
        self.parameters = parameters

    def unpack(self, packet):
        (function, count) = struct.unpack('!BB', self.parameters[:2])
        descr = ''
        offset = 0
        item = 1
        while (count):
            (return_code, transport_size, length) = struct.unpack('!BBH', packet[offset:offset+4])
            offset += 4
            result = packet[offset:offset+length]
            descr = '[%d] ' % item
            if transport_size in [0x01, 0x03]:
                descr += '%s' % struct.unpack('?', result)[0]
            if transport_size == 0x04:
                descr += '0x%s' % result.hex()
            elif transport_size == 0x05:
                descr += '%d' % struct.unpack('>H', result)[0]
            elif transport_size == 0x06:
                descr += '%d' % struct.unpack('>I', result)[0]
            elif transport_size == 0x07:
                descr += '%d' % struct.unpack('>f', result)[0]
            elif transport_size == 0x09:
                descr += '%s' % str(result)
            descr += ' '
            offset += 4 + length
            item += 1
            count -= 1
        self.audit = descr
        return self

class S7ReadVarParameterRsp:
    def __init__(self, parameters=''):
        self.parameters = parameters

    def unpack(self, packet):
        if not packet:
            raise S7ProtocolError("Not a ReadVar response")
        (function, count) = struct.unpack('!BB', self.parameters)
        if function != 0x04:
            raise S7ProtocolError("Not a ReadVar response")
        self.audit = '%s Response ' % S7_JB_FUNCTION[function]
        if count:
            self.audit += 'Item count %d: ' % count
        if not packet:
            return
        params = S7ParseParameters(self.parameters).unpack(packet)
        self.audit += params.audit
        return self

class S7WriteVarParameterRsp:
    def __init__(self, parameters=''):
        self.parameters = parameters

    def unpack(self, packet):
        if not packet:
            raise S7ProtocolError("Not a WriteVar response")
        (function, count) = struct.unpack('!BB', self.parameters)
        if function != 0x05:
            raise S7ProtocolError("Not a WriteVar response")
        self.audit = '%s Response ' % S7_JB_FUNCTION[function]
        if count:
            self.audit += 'Item count %d: ' % count
        if not packet:
            return
        descr = ''
        offset = 0
        item = 1
        while (count):
            return_code = packet[offset]
            descr += '[%d] %s ' % (item, S7_RETURN_CODE[return_code])
            self.audit += descr
            offset += 1
            item += 1
            count -= 1
        return self

class S7SetConParameter:
    def __init__(self, parameters=''):
        self.parameters = parameters

    def unpack(self, packet = None):
        if not self.parameters:
            raise S7ProtocolError("Not a Setup Communication")
        (function, count,MaxAmQcalling, MaxAmQcalled, PDULength) = struct.unpack('!BBHHH', self.parameters)
        if function != 0xf0:
            raise S7ProtocolError("Not a Setup Communication")
        self.audit = '%s ' % S7_JB_FUNCTION[function]
        self.audit += 'Max AmQ calling %d Max AmQ called %d PDU length %d' % (MaxAmQcalling, MaxAmQcalled, PDULength)
        return self

class S7ReadSZLParameter:
    def __init__(self, parameters=''):
        self.parameters = parameters
        self.function = 0
        self.subfunction = 0
        self.szl_id = 0
        self.szl_index = 0

    def unpack(self, packet):
        if not packet:
            raise S7ProtocolError("Not a ReadSZL Parameter")
        (length, method, req_type, subfunction, sequence) = struct.unpack('!BBBBB', self.parameters[3:8])
        self.audit = ''
        self.audit += '%s %s %s: %s ' % (S7_SZL_METHODS[method], S7_UD_PARAMETER_TYPE[req_type >> 4], S7_UD_FUNCTION_GROUP[req_type & 0xf], S7_SUB_FUNCTIONS[req_type & 0xf][subfunction])
        self.function = req_type & 0xf
        self.subfunction = subfunction
        (self.error, transport_size, length) = struct.unpack('!BBH', packet[:4])
        if self.error != 0xff:
            raise S7Error(self.error)
        (self.szl_id, self.szl_index) = struct.unpack('!HH', packet[4:8])
        self.audit += 'ID = 0x%04x Index = 0x%04x' % (self.szl_id, self.szl_index)
        if self.szl_id == 0x424 and len(packet) > 8:
            self.audit += ' ( '
            (szl_length, szl_count) = struct.unpack('!HH', packet[8:12])
            descr = ''
            offset = 12
            item = 1
            while (szl_count):
                (ereig, ae, bzu_id) = struct.unpack('!HBB', packet[offset:offset+4])
                descr += '[%d] Requested mode: %s Previous mode: %s ' % (item, S7_SZL_BZU_ID_NAMES[bzu_id & 0xf], S7_SZL_BZU_ID_NAMES[bzu_id >> 4])
                self.audit += descr
                offset += 4
                item += 1
                szl_count -= 1
            self.audit += ')'
        return self

class S7ProtocolError(Exception):
    def __init__(self, message, packet=''):
        self.message = message
        self.packet = packet
    def __str__(self):
        return "[ERROR][S7Protocol] %s" % self.message

class S7Error(Exception):
    def __init__(self, code):
        self.code = code
        self._errors = {
            # s7 data errors
            0x05: 'Address Error',
            0x0a: 'Item not available',
            # s7 header errors
            0x8104: 'Context not supported',
            0x8500: 'Wrong PDU size'
        }
    def __str__(self):
        if self.code in self._errors:
            message = self._errors[self.code]
        else:
            message = 'Unknown error'
        return "[ERROR][S7][0x%x] %s" % (self.code, message)

S7_PACKET_TYPES_JOB = {
    0x04: S7ReadVarParameterReq,
    0x05: S7WriteVarParameterReq,
    0xf0: S7SetConParameter,
}

S7_PACKET_TYPES_ACKDATA = {
    0x04: S7ReadVarParameterRsp,
    0x05: S7WriteVarParameterRsp,
    0xf0: S7SetConParameter,
}

S7_PACKET_UD_SUB_FUNCTION_PROG = {
}

S7_PACKET_UD_SUB_FUNCTION_CYCLIC = {
}

S7_PACKET_UD_SUB_FUNCTION_BLOCK = {
}

S7_PACKET_UD_SUB_FUNCTION_CPU = {
    0x01: S7ReadSZLParameter,
    0x02: {},
}

S7_PACKET_UD_SUB_FUNCTION_SEC = {
}

S7_PACKET_UD_SUB_FUNCTION_TIME = {
}

S7_PACKET_UD_SUB_FUNCTIONS = {
    # Mode-transition (0x0)
    0x00: {},
    # Programmer commands (0x01)
    0x01: S7_PACKET_UD_SUB_FUNCTION_PROG,
    # Cyclic data (0x02)
    0x02: S7_PACKET_UD_SUB_FUNCTION_CYCLIC,
    # Block functions (0x03)
    0x03: S7_PACKET_UD_SUB_FUNCTION_BLOCK,
    # CPU functions (0x04)
    0x04: S7_PACKET_UD_SUB_FUNCTION_CPU,
    # Security (0x05)
    0x05: S7_PACKET_UD_SUB_FUNCTION_SEC,
    # PBC BSEND/BRECV (0x06)
    0x06: {},
    # Time functions (0x07)
    0x07: S7_PACKET_UD_SUB_FUNCTION_TIME,
    # NC programming (0x0f)
    0x0f: {}
}

S7_PACKET_TYPES = {
    # Job
    0x01: S7_PACKET_TYPES_JOB,
    # Ack
    0x02: {},
    # AckData,
    0x03: S7_PACKET_TYPES_ACKDATA,
    # UserData
    0x07: S7_PACKET_UD_SUB_FUNCTIONS
}

class Module(threading.local):
    def __init__(self, incoming=False, loglevel=logging.INFO, options=None, filters=[]):
        global logger
        # extract the file name from __file__. __file__ is proxymodules/name.py
        self.name = path.splitext(path.basename(__file__))[0]
        logger = logging.getLogger(self.name)
        logger.setLevel(loglevel)
        self.description = 'Siemens S7 (0x32) module'
        self.protocol = 'TCP'
        self.incoming = incoming
        self.direction = ('OUT','IN')[self.incoming] 
        self.ports = [102]
        self.magic = 0x32
        self.detection = False
        self.filters = filters
        self.source_tsap = 0
        self.destination_tsap = 0
        self.rosctr = 0
        self.function = 0
        self.subfunction = 0
        self.area = 0
        self.db_num = 0
        self.address = 0
        self.szl_id = 0
        self.audit = ''

        logger.setLevel(loglevel)
        if options is not None:
            if 'ports' in options.keys():
                try:
                    self.ports = [int(port) for port in options['ports'].split(',')]
                except ValueError as e:
                    logger.error('Invalid ports specified, using default configuration.')

    def execute(self, data, source, destination):
        # Protocol detection
        self.detection = False
        if self.incoming:
            addr, port = source
        else:
            addr, port = destination
        if (port not in self.ports):
            return data
        self.detection = True
        try:
            tktp = TPKTPacket().unpack(data)
            logger.debug(tktp.audit)
        except S7ProtocolError as e:
            logger.error(str(e))
            return data
        try:
            cotp = COTPConnectionPacket().unpack(tktp.data)
            logger.debug(cotp.audit)
            self.source_tsap = cotp.src_tsap
            self.destination_tsap = cotp.dst_tsap
            return data
        except S7ProtocolError as e:
            pass
        try:
            cotp = COTPDataPacket().unpack(tktp.data)
            logger.debug(cotp.audit)
            magic = int(cotp.trailer[0])
            if magic != self.magic:
                logger.debug('Bad magic number 0x%02x for this module (expected 0x%02x)' % (magic, self.magic))
                self.detection = False
                return data
            response = S7Packet().unpack(cotp.trailer)
            logger.info(response.audit)
        except (S7ProtocolError, S7Error) as e:
            logger.error(str(e))
            return data
        self.rosctr = response.type
        if response.type == 0x07:
            (length, method, type_group, subfunction, sequence) = struct.unpack('!BBBBB', response.parameters[3:8])
            callback = S7_PACKET_TYPES[response.type][type_group & 0xf][subfunction]
            self.function = type_group & 0xf
            self.subfunction = subfunction
        else:
            (function, count) = struct.unpack('!BB', response.parameters[:2])
            callback = S7_PACKET_TYPES[response.type][function]
            self.function = function
            self.subfunction = 0
        if callback:
            try:
                response = callback(parameters = response.parameters).unpack(response.data)
            except (S7ProtocolError, S7Error) as e:
                logger.error(str(e))
                return data
            self.audit = response.audit 
            logger.info(response.audit)
            # better solution to be found for S7 address parameters...
            if hasattr(response,'area'):
                self.area = response.area
            if hasattr(response,'db_num'):
                self.db_num = response.db_num
            if hasattr(response,'address'):
                self.address = response.address
            if hasattr(response,'szl_id'):
                self.szl_id = response.szl_id
        else:
            logging.error('Not implemented: %s Function 0x%02x Subfunction 0x%02x' % (S7_PDU_TYPE[response.type], self.function, self.subfunction))
        if self.incoming == False and self.filters:
            params = [
            (self.protocol, PType.IP_PROTO), 
            (source[0], PType.IP_ADDR), 
            (source[1], PType.NUMERIC), 
            (destination[0], PType.IP_ADDR),
            (destination[1], PType.NUMERIC),
            (self.source_tsap, PType.NUMERIC),
            (self.destination_tsap, PType.NUMERIC), 
            (self.rosctr, PType.NUMERIC), 
            (self.function, PType.NUMERIC), 
            (self.subfunction, PType.NUMERIC), 
            (self.address, PType.S7_ADDR),
            (self.szl_id, PType.NUMERIC)]
            # better solution to be found for S7 address parameters...
            self.filters.source = source
            self.filters.destination = destination
            self.filters.protocol = self.protocol
            self.filters.direction = self.direction
            self.filters.area = self.area
            self.filters.db_num = self.db_num
            self.filters.address = self.address
            self.filters.audit = self.audit
            self.filters.filter(self.name, params)
        return data

    def help(self):
        h = '\tports: override default TCP port (102), multiple ports comma separated'
        return h

if __name__ == '__main__':
    print('This module is not supposed to be executed alone!')
