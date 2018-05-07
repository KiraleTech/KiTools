#!/usr/bin/python
# -*- coding: latin-1 -*-

'''KBI adaptation layer for kiserial'''

import shlex
import struct
from functools import reduce
from operator import xor
from time import gmtime, strftime

from iptools import ipv6
from colorama import Fore

# Command types
CT_CMD = 0x40
CT_GOL = 0x50
CT_RSC = 0x80  # Response to command
CT_RSG = 0x90  # Response to golden command
CT_NTF = 0xc0  # Notification

# Operations
OP_WRITE = 0x00
OP_EXEC = 0x00
OP_READ = 0x40
OP_DEL = 0x80

# Response codes
RC_OK = 0x00
RC_VALUE = 0x01
RC_BADPAR = 0x02
RC_BADCOM = 0x03
RC_NOTALL = 0x04
RC_MEMERR = 0x05
RC_CFGERR = 0x06
RC_FWUERR = 0x07

# Notification codes
NC_PINGR = 0x00
NC_UDP = 0x01
NC_DSTUN = 0x04
NC_PINGR_N = 0x05
NC_UDP_N = 0x06

# Roles
ROLES = {
    'leader': 6,
    'router': 1,
    'reed': 2,
    'fed': 3,
    'med': 4,
    'sed': 5,
    'not configured': 0
}

# Status codes
STATUSCODES = {
    0: 'none',
    1: 'booting',
    2: 'discovering',
    3: 'comminssioning',
    4: 'attaching',
    5: 'joined',
    6: 'rebooting',
    7: 'changing partition',
    8: 'attaching',  # 'joining'
    9: 'not joined',
    10: 'rejected',
    11: 'attaching',  # 'accepted'
    12: 'attaching',  # 'reattaching'
    13: 'rebooting',  # 'reboot synch'
    14: 'rebooting',  # 'reboot success'
    15: 'attaching',  # 'attach dataset'
    16: 'clearing conf.'
}

NONECODES = {
    0: '',
    1: ' - saved configuration',
    2: ' - network not found',
    3: ' - comminssioning failed',
    4: ' - attaching failed'
}

# Steering data
STDATA = {'all': 0, 'none': 1, 'on': 2}


class TYP:
    '''Data types that can be converted from/to string/bytearray'''
    DEC = 0
    HEX = 1
    CHAR = 2
    STR = 3
    MAC = 4
    ADDR = 5
    ROLE = 6
    STDATA = 7
    STATUS = 8
    TIME = 9
    STRN = 10
    SERV = 11


def s2b(type_, str_, size=0):
    '''String to bytearray transformation'''

    if type_ is TYP.DEC:
        sizes = {1: '>B', 2: '>H', 4: '>L'}
        return struct.pack(sizes[size], int(str_, 10))
    elif type_ is TYP.HEX:
        if len(str_) % 2 == 0 and str_.startswith('0x'):
            return bytearray.fromhex(str_.replace('0x', ''))
    elif type_ is TYP.STR:
        return bytearray(list(map(ord, str_))) + bytearray(1)
    elif type_ is TYP.STRN:
        str_bytes = bytearray(list(map(ord, str_[:size])))
        return str_bytes + bytearray(size - len(str_bytes) + 1)
    elif type_ is TYP.MAC:
        return s2b(TYP.HEX, '0x' + str_.replace('-', ''))
    elif type_ is TYP.ADDR:
        addr = hex(ipv6.ip2long(str_.lower())).replace(
            '0x', '').rstrip('L').zfill(32)
        return bytearray.fromhex(addr)
    elif type_ is TYP.ROLE:
        return bytearray([ROLES.get(str_)])
    elif type_ is TYP.STDATA:
        return bytearray([STDATA.get(str_)])


TEXT2CLI = {
    'clear': {'type': CT_CMD, 'code': 0x00 | OP_EXEC},
    'show uptime': {'type': CT_CMD, 'code': 0x02 | OP_READ},
    'reset': {'type': CT_CMD, 'code': 0x03 | OP_EXEC},
    'config autojoin on': {'type': CT_CMD, 'code': 0x04 | OP_WRITE},
    'config autojoin off': {'type': CT_CMD, 'code': 0x04 | OP_DEL},
    'show autojoin': {'type': CT_CMD, 'code': 0x04 | OP_READ},
    'show status': {'type': CT_CMD, 'code': 0x05 | OP_READ},
    'ping': {'type': CT_CMD, 'code': 0x06 | OP_EXEC, 'params': [lambda x: s2b(TYP.ADDR, x), lambda x: s2b(TYP.DEC, x, 2)]},
    'ifdown': {'type': CT_CMD, 'code': 0x07 | OP_EXEC},
    'ifup': {'type': CT_CMD, 'code': 0x08 | OP_EXEC},
    'config socket add': {'type': CT_CMD, 'code': 0x09 | OP_WRITE, 'params': [lambda x: s2b(TYP.DEC, x, 2)], 'lastParamOptional': True},
    'config socket del': {'type': CT_CMD, 'code': 0x09 | OP_DEL, 'params': [lambda x: s2b(TYP.DEC, x, 2)]},
    'show swver': {'type': CT_CMD, 'code': 0x0a | OP_READ},
    'show hwver': {'type': CT_CMD, 'code': 0x0b | OP_READ},
    'show snum': {'type': CT_CMD, 'code': 0x0c | OP_READ},
    'config emac': {'type': CT_CMD, 'code': 0x0d | OP_WRITE, 'params': [lambda x: s2b(TYP.MAC, x)]},
    'show emac': {'type': CT_CMD, 'code': 0x0d | OP_READ},
    'show eui64': {'type': CT_CMD, 'code': 0x0e | OP_READ},
    'config lowpower on': {'type': CT_CMD, 'code': 0x0f | OP_WRITE},
    'config lowpower off': {'type': CT_CMD, 'code': 0x0f | OP_DEL},
    'show lowpower': {'type': CT_CMD, 'code': 0x0f | OP_READ},
    'config txpower': {'type': CT_CMD, 'code': 0x10 | OP_WRITE, 'params': [lambda x: s2b(TYP.DEC, x, 1)]},
    'show txpower': {'type': CT_CMD, 'code': 0x10 | OP_READ},
    'config panid': {'type': CT_CMD, 'code': 0x11 | OP_WRITE, 'params': [lambda x: s2b(TYP.HEX, x)]},
    'show panid': {'type': CT_CMD, 'code': 0x11 | OP_READ},
    'config channel': {'type': CT_CMD, 'code': 0x12 | OP_WRITE, 'params': [lambda x: s2b(TYP.DEC, x, 1)]},
    'show channel': {'type': CT_CMD, 'code': 0x12 | OP_READ},
    'config xpanid': {'type': CT_CMD, 'code': 0x13 | OP_WRITE, 'params': [lambda x: s2b(TYP.HEX, x)]},
    # Moved here for sequential seek
    'show xpanfilt': {'type': CT_CMD, 'code': 0x1f | OP_READ},
    'show xpanid': {'type': CT_CMD, 'code': 0x13 | OP_READ},
    'config netname': {'type': CT_CMD, 'code': 0x14 | OP_WRITE, 'params': [lambda x: s2b(TYP.STR, x)]},
    'show netname': {'type': CT_CMD, 'code': 0x14 | OP_READ},
    'config mkey': {'type': CT_CMD, 'code': 0x15 | OP_WRITE, 'params': [lambda x: s2b(TYP.HEX, x)]},
    'show mkey': {'type': CT_CMD, 'code': 0x15 | OP_READ},
    'config commcred': {'type': CT_CMD, 'code': 0x16 | OP_WRITE, 'params': [lambda x: s2b(TYP.STR, x)]},
    'show commcred': {'type': CT_CMD, 'code': 0x16 | OP_READ},
    'config joincred': {'type': CT_CMD, 'code': 0x17 | OP_WRITE, 'params': [lambda x: s2b(TYP.STR, x)]},
    'show joincred': {'type': CT_CMD, 'code': 0x17 | OP_READ},
    'config joiner add': {'type': CT_CMD, 'code': 0x18 | OP_WRITE, 'params': [lambda x: s2b(TYP.MAC, x), lambda x: s2b(TYP.STR, x)]},
    'config joiner remove all': {'type': CT_CMD, 'code': 0x18 | OP_DEL},
    'config joiner remove': {'type': CT_CMD, 'code': 0x18 | OP_DEL, 'params': [lambda x: s2b(TYP.MAC, x)]},
    'show joiners': {'type': CT_CMD, 'code': 0x18 | OP_READ},
    'config role': {'type': CT_CMD, 'code': 0x19 | OP_WRITE, 'params': [lambda x: s2b(TYP.ROLE, x)]},
    'show role': {'type': CT_CMD, 'code': 0x19 | OP_READ},
    'show rloc16': {'type': CT_CMD, 'code': 0x1a | OP_READ},
    'config comm on': {'type': CT_CMD, 'code': 0x1b | OP_WRITE},
    'config comm off': {'type': CT_CMD, 'code': 0x1b | OP_DEL},
    'config mlprefix': {'type': CT_CMD, 'code': 0x1c | OP_WRITE, 'params': [lambda x: s2b(TYP.ADDR, x)[:8]]},
    'show mlprefix': {'type': CT_CMD, 'code': 0x1c | OP_READ},
    'config maxchild': {'type': CT_CMD, 'code': 0x1d | OP_WRITE, 'params': [lambda x: s2b(TYP.DEC, x, 1)]},
    'show maxchild': {'type': CT_CMD, 'code': 0x1d | OP_READ},
    'config timeout': {'type': CT_CMD, 'code': 0x1e | OP_WRITE, 'params': [lambda x: s2b(TYP.DEC, x, 4)]},
    'show timeout': {'type': CT_CMD, 'code': 0x1e | OP_READ},
    'config xpanfilt add': {'type': CT_CMD, 'code': 0x1f | OP_WRITE, 'params': [lambda x: s2b(TYP.HEX, x)]},
    'config xpanfilt remove all': {'type': CT_CMD, 'code': 0x1f | OP_DEL},
    'config ipaddr add': {'type': CT_CMD, 'code': 0x20 | OP_WRITE, 'params': [lambda x: s2b(TYP.ADDR, x)]},
    'config ipaddr remove': {'type': CT_CMD, 'code': 0x20 | OP_DEL, 'params': [lambda x: s2b(TYP.ADDR, x)]},
    'show ipaddr': {'type': CT_CMD, 'code': 0x20 | OP_READ},
    'config joinport': {'type': CT_CMD, 'code': 0x21 | OP_WRITE, 'params': [lambda x: s2b(TYP.HEX, x)]},
    'show heui64': {'type': CT_CMD, 'code': 0x22 | OP_READ},
    'config pollrate': {'type': CT_CMD, 'code': 0x23 | OP_WRITE, 'params': [lambda x: s2b(TYP.DEC, x, 4)]},
    'show pollrate': {'type': CT_CMD, 'code': 0x23 | OP_READ},
    'config outband': {'type': CT_CMD, 'code': 0x24 | OP_WRITE},
    'config steering': {'type': CT_CMD, 'code': 0x25 | OP_WRITE, 'params': [lambda x: s2b(TYP.STDATA, x)]},
    'config prefix add': {'type': CT_CMD, 'code': 0x26 | OP_WRITE, 'params': [lambda x: s2b(TYP.ADDR, x), lambda x: s2b(TYP.DEC, x, 1), lambda x: s2b(TYP.HEX, x)]},
    'config prefix remove': {'type': CT_CMD, 'code': 0x26 | OP_DEL, 'params': [lambda x: s2b(TYP.ADDR, x), lambda x: s2b(TYP.DEC, x, 1)]},
    'config route add': {'type': CT_CMD, 'code': 0x27 | OP_WRITE, 'params': [lambda x: s2b(TYP.ADDR, x), lambda x: s2b(TYP.DEC, x, 1), lambda x: s2b(TYP.HEX, x)]},
    'config route remove': {'type': CT_CMD, 'code': 0x27 | OP_DEL, 'params': [lambda x: s2b(TYP.ADDR, x), lambda x: s2b(TYP.DEC, x, 1)]},
    'show parent': {'type': CT_CMD, 'code': 0x28 | OP_READ},
    'show routert': {'type': CT_CMD, 'code': 0x29 | OP_READ},
    'show ldrdata': {'type': CT_CMD, 'code': 0x2a | OP_READ},
    'show netdata': {'type': CT_CMD, 'code': 0x2b | OP_READ},
    'show stats': {'type': CT_CMD, 'code': 0x2c | OP_READ},
    'show childt': {'type': CT_CMD, 'code': 0x2d | OP_READ},
    'netcat': {'type': CT_CMD, 'code': 0x2e | OP_EXEC, 'params': [lambda x: s2b(TYP.DEC, x, 2), lambda x: s2b(TYP.DEC, x, 2), lambda x: s2b(TYP.ADDR, x), lambda x: s2b(TYP.HEX, x)]},
    'config hwmode': {'type': CT_CMD, 'code': 0x30 | OP_WRITE, 'params': [lambda x: s2b(TYP.DEC, x, 1)]},
    'show hwmode': {'type': CT_CMD, 'code': 0x30 | OP_READ},
    'config led on': {'type': CT_CMD, 'code': 0x31 | OP_WRITE},
    'config led off': {'type': CT_CMD, 'code': 0x31 | OP_DEL},
    'show led': {'type': CT_CMD, 'code': 0x31 | OP_READ},
    'config vname': {'type': CT_CMD, 'code': 0x32 | OP_WRITE, 'params': [lambda x: s2b(TYP.STR, x)]},
    'show vname': {'type': CT_CMD, 'code': 0x32 | OP_READ},
    'config vmodel': {'type': CT_CMD, 'code': 0x33 | OP_WRITE, 'params': [lambda x: s2b(TYP.STR, x)]},
    'show vmodel': {'type': CT_CMD, 'code': 0x33 | OP_READ},
    'config vdata': {'type': CT_CMD, 'code': 0x34 | OP_WRITE, 'params': [lambda x: s2b(TYP.STR, x)]},
    'show vdata': {'type': CT_CMD, 'code': 0x34 | OP_READ},
    'config vswver': {'type': CT_CMD, 'code': 0x35 | OP_WRITE, 'params': [lambda x: s2b(TYP.STR, x)]},
    'show vswver': {'type': CT_CMD, 'code': 0x35 | OP_READ},
    'config actstamp': {'type': CT_CMD, 'code': 0x36 | OP_WRITE, 'params': [lambda x: s2b(TYP.HEX, x)]},
    'show actstamp': {'type': CT_CMD, 'code': 0x36 | OP_READ, 'params': [lambda x: s2b(TYP.HEX, x)]},
    'nping': {'type': CT_CMD, 'code': 0x37 | OP_EXEC, 'params': [lambda x: s2b(TYP.STRN, x, 31), lambda x: s2b(TYP.DEC, x, 2)]},
    'nnetcat': {'type': CT_CMD, 'code': 0x38 | OP_EXEC, 'params': [lambda x: s2b(TYP.DEC, x, 2), lambda x: s2b(TYP.DEC, x, 2), lambda x: s2b(TYP.STRN, x, 31), lambda x: s2b(TYP.HEX, x)]},
    'show services': {'type': CT_CMD, 'code': 0x39 | OP_READ},
    # Test Harness Specific Commands
    'config provurl': {'type': CT_GOL, 'code': 0x00 | OP_WRITE, 'params': [lambda x: s2b(TYP.STR, x)]},
    'show commsid': {'type': CT_GOL, 'code': 0x01 | OP_READ},
    'config sjitter': {'type': CT_GOL, 'code': 0x05 | OP_WRITE, 'params': [lambda x: s2b(TYP.DEC, x, 1)]},
    'config seqctr': {'type': CT_GOL, 'code': 0x0b | OP_WRITE, 'params': [lambda x: s2b(TYP.DEC, x, 4)]},
    'show seqctr': {'type': CT_GOL, 'code': 0x0b | OP_READ},
    'config seqguard': {'type': CT_GOL, 'code': 0x0c | OP_WRITE, 'params': [lambda x: s2b(TYP.DEC, x, 4)]},
    'exec activeget': {'type': CT_GOL, 'code': 0x11 | OP_EXEC, 'params': [lambda x: s2b(TYP.ADDR, x), lambda x: s2b(TYP.HEX, '0x' + x)], 'lastParamOptional': True},
    'exec activeset': {'type': CT_GOL, 'code': 0x12 | OP_EXEC, 'params': [lambda x: s2b(TYP.ADDR, x), lambda x: s2b(TYP.HEX, '0x' + x)]},
    'exec commget': {'type': CT_GOL, 'code': 0x13 | OP_EXEC, 'params': [lambda x: s2b(TYP.ADDR, x), lambda x: s2b(TYP.HEX, '0x' + x)], 'lastParamOptional': True},
    'exec commset': {'type': CT_GOL, 'code': 0x14 | OP_EXEC, 'params': [lambda x: s2b(TYP.ADDR, x), lambda x: s2b(TYP.HEX, '0x' + x)]},
    'exec pendget': {'type': CT_GOL, 'code': 0x0f | OP_EXEC, 'params': [lambda x: s2b(TYP.ADDR, x), lambda x: s2b(TYP.HEX, '0x' + x)], 'lastParamOptional': True},
    'exec pendset': {'type': CT_GOL, 'code': 0x10 | OP_EXEC, 'params': [lambda x: s2b(TYP.ADDR, x), lambda x: s2b(TYP.HEX, '0x' + x)]},
    'exec panidqry': {'type': CT_GOL, 'code': 0x19 | OP_EXEC, 'params': [lambda x: s2b(TYP.ADDR, x), lambda x: s2b(TYP.HEX, x), lambda x: s2b(TYP.HEX, x)]},
    'config rotation': {'type': CT_GOL, 'code': 0x23 | OP_WRITE, 'params': [lambda x: s2b(TYP.DEC, x, 2)]}
}


def text_to_kbi(txt_cmd):
    '''Transform a text command into a (type, code, payload) tuple'''
    ctype, ccode = None, None
    payload = bytearray()

    # Combine multiple whitespaces together
    txt_cmd = shlex.split(txt_cmd)

    for key in TEXT2CLI:
        if ' '.join(txt_cmd).startswith(key):
            # Get command definition
            cmd_def = TEXT2CLI.get(key)
            # Fill type and code
            ctype = cmd_def.get('type', None)
            ccode = cmd_def.get('code', None)
            # Get required params
            required_params = cmd_def.get('params', [])
            # Get received params
            key_len = len(key.split())
            received_params = txt_cmd[key_len:]
            # Check if last parameter is optional
            if cmd_def.get('params', False):
                if len(required_params) == len(received_params) + 1:
                    required_params = required_params[:-1]
            # Fill payload
            try:
                for param in required_params:
                    payload += param(received_params.pop(0))
            except:
                return None, None, None
            break

    return ctype, ccode, payload


def b2s(type_, bytes_, size=None):
    '''Bytearray to string transformations'''

    if type_ is TYP.CHAR:
        str_ = ''
        for byte in bytes_:
            if byte == 0:
                break
            str_ += chr(byte)
        return str_
    elif type_ is TYP.HEX:
        str_ = '0x'
        for byte in bytes_:
            str_ += str(hex(byte)).replace('0x', '').zfill(2)
        return str_
    elif type_ is TYP.DEC:
        dec = b2s(TYP.HEX, bytes_).replace('0x', '')
        return str(int(dec, 16))
    elif type_ is TYP.MAC:
        hex_mac = b2s(TYP.HEX, bytes_).replace('0x', '')
        return '-'.join([
            hex_mac[0:2], hex_mac[2:4], hex_mac[4:6], hex_mac[6:8],
            hex_mac[8:10], hex_mac[10:12], hex_mac[12:14], hex_mac[14:16]
        ])
    elif type_ is TYP.ADDR:
        addrs = ''
        while bytes_:
            hex_addr = b2s(TYP.HEX,
                           bytes_[:size]).replace('0x', '').rstrip('L').ljust(
                               32, '0')
            int_addr = int(hex_addr, 16)
            bytes_ = bytes_[size:]
            addrs += ipv6.long2ip(int_addr) + '\r\n'
        return addrs
    elif type_ is TYP.ROLE:
        val = int(b2s(TYP.DEC, bytes_))
        for key in ROLES:
            if val is ROLES[key]:
                return key
        return 'bad role'
    elif type_ is TYP.STATUS:
        status = STATUSCODES.get(int(b2s(TYP.DEC, [bytes_[0]])), 'unknown')
        if 'none' in status:
            status += NONECODES.get(int(b2s(TYP.DEC, [bytes_[1]])), 'unknown')
        return status
    elif type_ is TYP.TIME:
        uptime = struct.unpack('>I', bytes_[0:4])[0]
        utc = struct.unpack('>I', bytes_[4:8])[0]
        temperature = struct.unpack('>b', bytes_[8:9])[0]
        output = 'Uptime           : %u days, %s\r\n' % (
            int(uptime / 86400),
            strftime('%H hours, %M minutes and %S seconds', gmtime(uptime)))
        output += 'Current UTC Time : %s\r\n' % strftime(
            '%H:%M:%S', gmtime(utc))
        output += 'MCU Temperature  : %d°C' % temperature
        return output
    elif type_ is TYP.SERV:
        meaning = {0x01: 'on', 0x00: 'off'}
        output = 'DHCP server: ' + meaning[bytes_[0]]
        output += '\nDNS server: ' + meaning[bytes_[1]]
        output += '\nNTP server: ' + meaning[bytes_[2]]
        return output


CLI2TEXT = {
    (CT_RSC | RC_VALUE, 0x02 | OP_READ): ['uptime', lambda x: b2s(TYP.TIME, x)],
    (CT_RSC | RC_VALUE, 0x04 | OP_READ): ['autojoin', lambda x: b2s(TYP.DEC, x)],
    (CT_RSC | RC_VALUE, 0x05 | OP_READ): ['status', lambda x: b2s(TYP.STATUS, x)],
    (CT_RSC | RC_VALUE, 0x09 | OP_WRITE): ['socket', lambda x: b2s(TYP.DEC, x)],
    (CT_RSC | RC_VALUE, 0x11 | OP_READ): ['panid', lambda x: b2s(TYP.HEX, x)],
    (CT_RSC | RC_VALUE, 0x0a | OP_READ): ['swver', lambda x: b2s(TYP.CHAR, x)],
    (CT_RSC | RC_VALUE, 0x0b | OP_READ): ['hwver', lambda x: b2s(TYP.CHAR, x)],
    (CT_RSC | RC_VALUE, 0x0c | OP_READ): ['snum', lambda x: b2s(TYP.CHAR, x)],
    (CT_RSC | RC_VALUE, 0x0d | OP_READ): ['emac', lambda x: b2s(TYP.MAC, x)],
    (CT_RSC | RC_VALUE, 0x0e | OP_READ): ['eui64', lambda x: b2s(TYP.MAC, x)],
    (CT_RSC | RC_VALUE, 0x0F | OP_READ): ['lowpower', lambda x: b2s(TYP.DEC, x)],
    (CT_RSC | RC_VALUE, 0x10 | OP_READ): ['txpower', lambda x: b2s(TYP.DEC, x)],
    (CT_RSC | RC_VALUE, 0x12 | OP_READ): ['channel', lambda x: b2s(TYP.DEC, x)],
    (CT_RSC | RC_VALUE, 0x13 | OP_READ): ['xpanid', lambda x: b2s(TYP.HEX, x)],
    (CT_RSC | RC_VALUE, 0x14 | OP_READ): ['netname', lambda x: b2s(TYP.CHAR, x)],
    (CT_RSC | RC_VALUE, 0x15 | OP_READ): ['mkey', lambda x: b2s(TYP.HEX, x)],
    (CT_RSC | RC_VALUE, 0x16 | OP_READ): ['commcred', lambda x: b2s(TYP.CHAR, x)],
    (CT_RSC | RC_VALUE, 0x17 | OP_READ): ['joincred', lambda x: b2s(TYP.CHAR, x)],
    (CT_RSC | RC_VALUE, 0x18 | OP_READ): ['joiner', lambda x: b2s(TYP.MAC, x)],
    (CT_RSC | RC_VALUE, 0x19 | OP_READ): ['role', lambda x: b2s(TYP.ROLE, x)],
    (CT_RSC | RC_VALUE, 0x1a | OP_READ): ['rloc16', lambda x: b2s(TYP.HEX, x)],
    (CT_RSC | RC_VALUE, 0x1c | OP_READ): ['mlprefix', lambda x: b2s(TYP.ADDR, x, 8)],
    (CT_RSC | RC_VALUE, 0x1d | OP_READ): ['maxchild', lambda x: b2s(TYP.DEC, x)],
    (CT_RSC | RC_VALUE, 0x1e | OP_READ): ['timeout', lambda x: b2s(TYP.DEC, x)],
    (CT_RSC | RC_VALUE, 0x1f | OP_READ): ['xpanfilt', lambda x: b2s(TYP.HEX, x)],
    (CT_RSC | RC_VALUE, 0x20 | OP_READ): ['ipaddr', lambda x: b2s(TYP.ADDR, x, 16)],
    (CT_RSC | RC_VALUE, 0x22 | OP_READ): ['heui64', lambda x: b2s(TYP.MAC, x)],
    (CT_RSC | RC_VALUE, 0x23 | OP_READ): ['pollrate', lambda x: b2s(TYP.DEC, x)],
    (CT_RSC | RC_VALUE, 0x28 | OP_READ): ['parent', lambda x: b2s(TYP.HEX, x)],
    (CT_RSC | RC_VALUE, 0x29 | OP_READ): ['routert', lambda x: b2s(TYP.HEX, x).replace('0x', '')],
    (CT_RSC | RC_VALUE, 0x2a | OP_READ): ['ldrdata', lambda x: b2s(TYP.HEX, x).replace('0x', '')],
    (CT_RSC | RC_VALUE, 0x2b | OP_READ): ['netdata', lambda x: b2s(TYP.HEX, x).replace('0x', '')],
    (CT_RSC | RC_VALUE, 0x2c | OP_READ): ['stats', lambda x: b2s(TYP.HEX, x).replace('0x', '')],
    (CT_RSC | RC_VALUE, 0x2d | OP_READ): ['childt', lambda x: b2s(TYP.HEX, x).replace('0x', '')],
    (CT_RSC | RC_VALUE, 0x30 | OP_READ): ['hwmode', lambda x: b2s(TYP.DEC, x)],
    (CT_RSC | RC_VALUE, 0x31 | OP_READ): ['led', lambda x: b2s(TYP.DEC, x)],
    (CT_RSC | RC_VALUE, 0x32 | OP_READ): ['vname', lambda x: b2s(TYP.CHAR, x)],
    (CT_RSC | RC_VALUE, 0x33 | OP_READ): ['vmodel', lambda x: b2s(TYP.CHAR, x)],
    (CT_RSC | RC_VALUE, 0x34 | OP_READ): ['vdata', lambda x: b2s(TYP.CHAR, x)],
    (CT_RSC | RC_VALUE, 0x35 | OP_READ): ['vswver', lambda x: b2s(TYP.CHAR, x)],
    (CT_RSC | RC_VALUE, 0x36 | OP_READ): ['actstamp', lambda x: b2s(TYP.HEX, x)],
    (CT_RSC | RC_VALUE, 0x39 | OP_READ): ['services', lambda x: b2s(TYP.SERV, x)],
    (CT_RSG | RC_VALUE, 0x01 | OP_READ): ['commsid', lambda x: b2s(TYP.HEX, x)],
    (CT_RSG | RC_VALUE, 0x0b | OP_READ): ['kseqcounter', lambda x: b2s(TYP.DEC, x)]
}


def kbi_to_text(ctype, ccode, payload):
    # Empty response case
    if ctype == CT_RSC | RC_OK or ctype == CT_RSG | RC_OK and payload is None:
        response = ''
    # Value response case
    elif ctype == CT_RSC | RC_VALUE or ctype == CT_RSG | RC_VALUE:
        rsp_func = CLI2TEXT[(ctype, ccode)] or None
        if rsp_func:
            response = rsp_func[1](payload).encode('latin_1').decode()
        else:
            response = 'Wrong value or parser not implemented'
    elif ctype == CT_RSC | RC_BADPAR or ctype == CT_RSG | RC_BADPAR:
        response = 'Bad parameter'
    elif ctype == CT_RSC | RC_BADCOM or ctype == CT_RSG | RC_BADCOM:
        response = 'Bad command'
    elif ctype == CT_RSC | RC_NOTALL or ctype == CT_RSG | RC_NOTALL:
        response = 'Command not allowed'
    elif ctype == CT_RSC | RC_MEMERR or ctype == CT_RSG | RC_MEMERR:
        response = 'Memory allocation error'
    elif ctype == CT_RSC | RC_CFGERR or ctype == CT_RSG | RC_CFGERR:
        response = 'Configuration conflict error'
    elif ctype == CT_RSC | RC_FWUERR or ctype == CT_RSG | RC_FWUERR:
        response = 'Firmware update error'
    else:
        response = 'Unknown error'

    return response


class KBICommand:
    '''Representation of a Kirale Binary Interface command.
                            KBI Command Format
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    | Payload Len 0 | Payload Len 1 |      Type     |     Code      |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |    Checksum   |                  Payload...                   |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    '''

    def __init__(self, txt_cmd, ctype=None, ccode=None, cpload=None):
        self.valid = False
        self.data = bytearray(5)

        if txt_cmd:
            cmd_type, cmd_code, cmd_payload = text_to_kbi(txt_cmd)
        else:
            cmd_type = ctype
            cmd_code = ccode
            cmd_payload = cpload

        if cmd_type is not None and cmd_code is not None:
            self.valid = True

            self.data += cmd_payload

            # Fill the header
            struct.pack_into('>H', self.data, 0, len(cmd_payload))
            struct.pack_into('>B', self.data, 2, cmd_type)
            struct.pack_into('>B', self.data, 3, cmd_code)
            struct.pack_into('>B', self.data, 4, reduce(xor, self.data))

    def is_valid(self):
        return self.valid

    def get_data(self):
        return self.data

    def get_type(self):
        return struct.unpack('>B', self.data[2:3])[0]

    def get_code(self):
        return struct.unpack('>B', self.data[3:4])[0]

    def get_payload(self):
        return self.data[5:]

    def to_text(self):
        return kbi_to_text(self.get_type(), self.get_code(), self.get_payload())

    def __str__(self):
        '''Print the KBI command as colored text'''
        if len(self.data) < 5:
            return '|  |'
        string = ''
        string += ('| %s%02x%s : %s%02x%s : %s%02x%s : %s%02x%s : %s%02x%s ' % (
            Fore.RED,
            self.data[0],
            Fore.RESET,
            Fore.RED,
            self.data[1],
            Fore.RESET,
            Fore.GREEN,
            self.data[2],
            Fore.RESET,
            Fore.YELLOW,
            self.data[3],
            Fore.RESET,
            Fore.BLUE,
            self.data[4],
            Fore.RESET,
        ))
        for byte in self.data[5:]:
            string += (': %s%02x%s ' % (Fore.MAGENTA, byte, Fore.RESET))
        string += ('|')
        return string


class KBIResponse(KBICommand):
    '''Representation of a Kirale Binary Interface response.'''

    def __init__(self, response, size):
        '''"size" is the result of the COBS decoder, could be a negative value
        to indicate a frame had an error'''
        self.data = response
        self.valid = False

        # Validation
        if size > 4:
            # Checksum
            if reduce(xor, self.data[:4] + self.data[5:size]) is self.data[4]:
                # Length
                if struct.unpack('>H', self.data[0:2])[0] == size - 5:
                    self.valid = True

    def is_notification(self):
        if (self.get_type() & CT_NTF) == CT_NTF:
            return True
        return False

    def to_text(self):
        if self.is_notification():
            code = self.get_type() & 0x0f
            payload = self.get_payload()
            if code == NC_PINGR:
                return '# ping reply: saddr %s id %s sq %s - %s bytes' % (
                    b2s(TYP.ADDR, payload[0:16], 16).rstrip('\r\n'),
                    b2s(TYP.DEC, payload[18:20], 2),
                    b2s(TYP.DEC, payload[20:22], 2),
                    b2s(TYP.DEC, payload[16:18], 2))
            elif code == NC_PINGR_N:
                return '# ping reply: saddr %s [%s] id %s sq %s - %s bytes' % (
                    b2s(TYP.ADDR, payload[32:48], 16).rstrip('\r\n'),
                    b2s(TYP.CHAR, payload[0:32], 32),
                    b2s(TYP.DEC, payload[50:52], 2),
                    b2s(TYP.DEC, payload[52:54], 2),
                    b2s(TYP.DEC, payload[48:50], 2))
            elif code == NC_UDP:
                return '# udp rcv: saddr %s sport %s dport %s - %s bytes' % (
                    b2s(TYP.ADDR, payload[4:20], 16).rstrip('\r\n'),
                    b2s(TYP.DEC, payload[2:4], 2),
                    b2s(TYP.DEC, payload[0:2], 2),
                    len(payload[20:]))
            elif code == NC_UDP_N:
                return '# udp rcv: saddr %s [%s] sport %s dport %s - %s bytes' % (
                    b2s(TYP.ADDR, payload[36:52], 16).rstrip('\r\n'),
                    b2s(TYP.CHAR, payload[4:35], 31),
                    b2s(TYP.DEC, payload[2:4], 2),
                    b2s(TYP.DEC, payload[0:2], 2),
                    len(payload[52:]))
            elif code == NC_DSTUN:
                return '# dst unreachable: daddr %s' % b2s(
                    TYP.ADDR, payload[0:16], 16).rstrip('\r\n')
            else:
                return '# unknown notification'
        else:
            return KBICommand.to_text(self)
