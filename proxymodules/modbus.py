#!/usr/bin/env python3
import os.path as path
from distutils.util import strtobool

from pymodbus.factory import ClientDecoder, ServerDecoder
from pymodbus.transaction import ModbusSocketFramer
from pymodbus.transaction import ModbusBinaryFramer
from pymodbus.transaction import ModbusAsciiFramer
from pymodbus.transaction import ModbusRtuFramer
import codecs
import collections
import textwrap
import logging
import builtins
import threading

class Decoder(object):

    def __init__(self, framer, encode=False):
        """ Initialize a new instance of the decoder

        :param framer: The framer to use
        :param encode: If the message needs to be encoded
        """
        self.framer = framer
        self.encode = encode

        self.unit = 0
        self.function = 0
        self.addr = 0
        self.count = 0
        self.audit = ''

    def decode(self, message, incoming):
        value = message if self.encode else codecs.encode(message, 'hex_codec')
        if incoming == False:
            decoder = self.framer(ServerDecoder(), client=None)
        else:
            decoder = self.framer(ClientDecoder(), client=None)
        try:
            decoder.addToFrame(message)
            if decoder.checkFrame():
                unit = decoder._header.get("uid", 0x00)
                decoder.advanceFrame()
                decoder.processIncomingPacket(message, self.report, unit)
            else:
                self.check_errors(decoder, message)
        except Exception as ex:
            logger.error("Unable to parse message - {} with {}".format(message,
                decoder))

    def report(self, message):
        report = '%s ' % message.__class__.__name__
        if hasattr(message.__class__, 'function_code'):
            self.function = message.__class__.function_code
        if hasattr(message, 'transaction_id'):
            tid = message.transaction_id
            report += 'TID: %s ' % tid
        if hasattr(message, 'unit_id'):
            unit = message.unit_id
            report += 'UID: %s ' % unit
            self.unit = unit
        if hasattr(message, 'address'):
            addr = message.address
            report += 'address: %s ' % addr
            self.addr = addr
        if hasattr(message, 'count'):
            count = message.count
            report += 'count: %s ' % count
            self.count = count
        if hasattr(message, 'registers'):
            regs = message.registers
            report += 'regs: %s ' % regs
        if hasattr(message, 'bits'):
            bits = message.bits
            report += 'bits: %s ' % bits
        logger.info(report)
        self.audit = report

class Module(threading.local):
    def __init__(self, incoming=False, loglevel=logging.INFO, options=None, filters=None):
        global logger
        # extract the file name from __file__. __file__ is proxymodules/name.py
        self.name = path.splitext(path.basename(__file__))[0]
        logger = logging.getLogger(self.name)
        logger.setLevel(loglevel)
        self.description = 'Modbus TCP module'
        self.source = None
        self.destination = None
        self.incoming = incoming
        self.direction = ('OUT','IN')[self.incoming] 
        self.protocol = 'TCP'
        self.ports = [502]
        self.audit = ''
        self.detection = False
        self.filters = filters
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
        decoder = Decoder(ModbusSocketFramer, False)
        decoder.decode(data, self.incoming)
        self.audit = decoder.audit
        if self.incoming == False and self.filters:
            params = [
            (self.protocol, PType.IP_PROTO), 
            (source[0], PType.IP_ADDR), 
            (source[1], PType.NUMERIC),
            (destination[0], PType.IP_ADDR),
            (destination[1], PType.NUMERIC),
            (decoder.unit, PType.NUMERIC),
            (decoder.function, PType.NUMERIC),
            (decoder.addr, PType.NUMERIC),
            (decoder.count, PType.NUMERIC)]
            self.filters.source = source
            self.filters.destination = destination
            self.filters.protocol = self.protocol
            self.filters.direction = self.direction
            self.filters.audit = self.audit
            self.filters.filter(self.name, params)
        return data

    def help(self):
        h = '\tports: override default TCP port (502), multiple ports comma separated'
        return h

if __name__ == '__main__':
    print('This module is not supposed to be executed alone!')
