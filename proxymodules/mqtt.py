#!/usr/bin/env python3
import os.path as path
import sys

try:
    import mqtt_codec
    import mqtt_codec.packet
    import mqtt_codec.io
    from mqtt_codec.packet import MqttControlPacketType, MqttPublish, MqttPubrel, MqttSubscribe, MqttUnsubscribe, MqttConnect, MqttConnack, MqttPuback, MqttPubrec, MqttPubcomp, MqttSuback, MqttUnsuback, MqttPingreq, MqttPingresp, MqttDisconnect
except Exception:
    print("WARNING: cannot load mqtt_codec.")

import logging
import builtins
import threading

from proxymodules.basemodule import BaseModule

class Module(BaseModule):
    def __init__(self, incoming=False, args=None, options=None):
        BaseModule.__init__(self, incoming, args, options)

        # extract the file name from __file__. __file__ is proxymodules/name.py
        self.name = path.splitext(path.basename(__file__))[0]
        self.description = 'MQTT module'
        self.source = None
        self.destination = None
        self.incoming = incoming
        self.direction = ('OUT','IN')[self.incoming] 
        self.protocol = 'TCP'
        self.ports = [1883]
        self.audit = ''
        self.detection = False
        self.username = ''
        self.type = ''
        self.qos = 0
        self.topic = ''
        self.message = ''
        self.filters = None
        if options is not None:
            if 'ports' in options.keys():
                try:
                    self.ports = [int(port) for port in options['ports'].split(',')]
                except ValueError as e:
                    logger.error('Invalid ports specified, using default configuration.')

        if 'mqtt_codec' not in sys.modules:
            self.missing("mqtt_codec")

    def execute(self, data):
        source = self.conn.src
        destination = self.conn.dst

        # Protocol detection
        self.detection = False
        if self.incoming:
            addr, port = source
        else:
            addr, port = destination
        if (port not in self.ports):
            return data
        self.detection = True

        MqttPacketTypes = {
             MqttControlPacketType.publish:     MqttPublish,
             MqttControlPacketType.pubrel:      MqttPubrel,
             MqttControlPacketType.subscribe:   MqttSubscribe,
             MqttControlPacketType.unsubscribe: MqttUnsubscribe,
             MqttControlPacketType.connect:     MqttConnect,
             MqttControlPacketType.connack:     MqttConnack,
             MqttControlPacketType.puback:      MqttPuback,
             MqttControlPacketType.pubrec:      MqttPubrec,
             MqttControlPacketType.pubcomp:     MqttPubcomp,
             MqttControlPacketType.suback:      MqttSuback,
             MqttControlPacketType.unsuback:    MqttUnsuback,
             MqttControlPacketType.pingreq:     MqttPingreq,
             MqttControlPacketType.pingresp:    MqttPingresp,
             MqttControlPacketType.disconnect:  MqttDisconnect
        }

        offset = 0
        try:
            while True:
                with mqtt_codec.io.BytesReader(data[offset:]) as f:
                    (bytes_read, decoded) = mqtt_codec.packet.MqttFixedHeader.decode(f)
                if decoded.packet_type in MqttPacketTypes:
                    with mqtt_codec.io.BytesReader(data[offset:]) as f:
                        (bytes_read, decoded) = MqttPacketTypes[decoded.packet_type].decode(f)
                        self.audit = decoded
                        logger.info(self.audit)
                        self.type = MqttPacketTypes[decoded.packet_type].__name__
                        if hasattr(decoded, 'username'):
                            self.username = decoded.username
                        if hasattr(decoded, 'topic'):
                            self.topic = decoded.topic
                        if hasattr(decoded, 'qos'):
                            self.qos = int(decoded.qos)
                        if hasattr(decoded, 'payload'):
                            self.message = decoded.payload.decode()
                        if self.incoming == False and self.filters:
                            params = [
                            (self.protocol, PType.IP_PROTO), 
                            (source[0], PType.IP_ADDR), 
                            (source[1], PType.NUMERIC), 
                            (destination[0], PType.IP_ADDR),
                            (destination[1], PType.NUMERIC),
                            (self.type, PType.STRING),
                            (self.qos, PType.NUMERIC), 
                            (self.topic, PType.STRING),
                            (self.username, PType.STRING),
                            (self.message, PType.TEXT)]
                            self.filters.source = source
                            self.filters.destination = destination
                            self.filters.protocol = self.protocol
                            self.filters.direction = self.direction
                            self.filters.audit = self.audit
                            self.filters.filter(self.name, params)

                offset += bytes_read
        except mqtt_codec.io.UnderflowDecodeError:
            pass
        except mqtt_codec.io.DecodeError as e:
            logger.warning ('offset: %d: %s' % (offset,  str(e)))

        return data

    def help(self):
        h = '\tports: override default TCP port (1883), multiple ports comma separated'
        return ''

if __name__ == '__main__':
    print('This module is not supposed to be executed alone!')
