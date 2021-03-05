#!/usr/bin/env python3
import logging
import builtins
import csv
from enum import Enum
import queue
import ipaddress
import re

logger = logging.getLogger('filter')
alert = logging.getLogger('alert')

# This exception could be used by modules to silent drop connections
class Drop(Exception):
    pass

# This exception could be used by modules to reject (TCP RST) connections
class Reject(Exception):
    pass

# Parameter type, for modules filters
class PType(Enum):
    IP_ADDR = 1  # IP address
    IP_PROTO = 2 # IP protocol
    NUMERIC = 3  # number (from decimal o hex, can be ranges eg. '100:200')
    STRING = 4   # strict and case insensitive string compare (eg. parameters)
    TEXT = 5     # loose and case sensitive string compare (eg. payload)
    S7_ADDR = 6  # Siemens S7 address
    CONTENT = 7  # Snort/suricata like 'content'

builtins.Drop = Drop
builtins.Reject = Reject
builtins.PType = PType

class CSVFilters():
    def __init__(self, csvfile):
        self.filters = []
        with open(csvfile, 'r') as f:
            lines = csv.reader(self.__decomment(f), skipinitialspace=True, quoting=csv.QUOTE_MINIMAL)
            lines = list(lines)
            self.filters = lines
        f.close()
        if not lines:
            raise ValueError('%s empty (or only invalid/comments lines)' % csvfile);
        self.audit = ''
        self.error = ''

    def __decomment(self, csvfile):
        for row in csvfile:
            raw = row.split('#')[0].strip()
            if raw: yield raw

    def __check_type(self, array, index, typ):
        val = array[index]
        if not isinstance(val, typ):
            raise TypeError("parameter %d ('%s') must be %s, not %s" % (index + 1, val, typ, type(val)))

    def get(self, module):
        return list(filter(lambda f: f[0] == module, self.filters))

    def __get_s7params(self, req, db = 0):
        self.lam = [('IB', 0x81, 1), ('IW', 0x81, 2), ('ID', 0x81, 4), ('I', 0x81, 1),
        ('QB', 0x82, 1), ('QW', 0x82, 2), ('QD', 0x82, 4), ('Q', 0x82, 1), 
        ('MB', 0x83, 1), ('MW', 0x83, 2), ('MD', 0x83, 4), ('M', 0x83, 1), 
        ('DBB', 0x84, 1), ('DBW', 0x84, 2), ('DBD', 0x84, 4), ('DBX', 0x84, 1), 
        ('DB', 0x84, 0), ('C', 0x1C, 2), ('T', 0x1D, 2)]
        try:
            res = list(filter(lambda item: req.startswith(item[0]), self.lam))
            dev = res[0][0]
            s = req.split('.')
            start = int(s[0].replace(dev, ''))
            if dev == 'DB':
                db = int(s[0].replace(dev, ''))
                return self.__get_s7params(req.replace('DB%d.' % start, ''), db)
            bit = 0
            if len(req.split('.')) == 2:
                bit = int(req.split('.')[1])
            address = (start << 3) | bit
            return (db, res[0][1], address, res[0][2])
        except (IndexError, ValueError):
            return ()

    def __get_number(self, string, default=None):
        if not string and default:
            return default
        if string.startswith('0x'):
            return int(string, 16)
        else:
            return int(string)

    def __get_not(self, string):
        if string[0] == '!':
            string = re.sub("['\"]","",string[1:])
            return string, True
        return string, False

    def filter(self, module, params):
        q = queue.Queue()
        for f in self.get(module):
            q.queue.clear()
            for k, v in enumerate(f[3:]):
                try:
                    (pk, pv) = params[k]
                    if pv == PType.IP_ADDR:
                        if v in ['*', 'any', '']:
                            q.put(k)
                            continue
                        v, neg = self.__get_not(v)
                        if (ipaddress.ip_address(pk) in ipaddress.ip_network(v)) ^ neg:
                            q.put(k)
                            continue
                    if pv == PType.IP_PROTO:
                        if v in ['*', 'any', '']:
                            q.put(k)
                            continue
                        # a better solution to be find to check supported protocols (at this time TCP only)...
                        if pk.casefold() == v.casefold():
                            q.put(k)
                            continue
                    if pv == PType.NUMERIC:
                        if v in ['*', 'any', '']:
                            q.put(k)
                            continue
                        v, neg = self.__get_not(v)
                        try:
                            (v_min, v_max) = v.split(':', 1)
                            if (self.__get_number(v_min, int(pk)) <= int(pk) <= self.__get_number(v_max, int(pk))) ^ neg:
                                q.put(k)
                                continue
                        except ValueError:
                            if (int(pk) == self.__get_number(v)) ^ neg:
                                q.put(k)
                                continue
                    if pv == PType.STRING:
                        if v in ['*', 'any', '']:
                            q.put(k)
                            continue
                        v, neg = self.__get_not(v)
                        if (v.casefold() == pk.casefold()) ^ neg:
                            q.put(k)
                            continue
                    if pv == PType.TEXT:
                        if v in pk:
                            q.put(k)
                            continue
                    if pv == PType.S7_ADDR:
                        if v in ['*', 'any', '']:
                            q.put(k)
                            continue
                        (db, area, address, count) = self.__get_s7params(v)
                        if (db, area, address) == (self.db_num, self.area, self.address):
                            q.put(k)
                            continue
                    if pv == PType.CONTENT:
                        v, neg = self.__get_not(v)
                        by = bytes()
                        for m in re.finditer('([^|]+)', v):
                            start, end, match = (m.start(0), m.end(0), m.group(0))
                            if len(v) == end:
                                by += match.encode()
                            elif v[abs(start - 1)] == '|' and v[end] == '|':
                                by += bytes.fromhex(match)
                            else:
                                # a better solution to find here: in case of orphaned '|', it will be skipped...
                                by += match.encode()
                        if (by in pk) ^ neg:
                            q.put(k)
                            continue
                except (ValueError, IndexError) as e:
                    self.error = str(e)
            if (q.qsize() == len(f[3:])):
                (module, sid, action) = f[0:3]
                extra = {'action': action.upper(), 'sid': sid, 'mod': module,
                'direction': self.direction, 'protocol': self.protocol, 
                'src_address': self.source[0], 'src_port': self.source[1], 
                'dst_address': self.destination[0], 'dst_port': self.destination[1]}
                if action.casefold() == 'alert':
                    alert.info(self.audit, extra=extra)
                    logger.info(self.audit, extra=extra)
                    return
                if action.casefold() == 'pass' or action.casefold() == 'allow':
                    return
                if action.casefold() == 'drop':
                    logger.info(self.audit, extra=extra)
                    raise Drop(sid)
                if action.casefold() == 'reject':
                    logger.info(self.audit, extra=extra)
                    raise Reject(sid)


if __name__ == '__main__':
    print('This module is not supposed to be executed alone!')
