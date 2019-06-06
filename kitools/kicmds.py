#!/usr/bin/python
# -*- coding: latin-1 -*-
'''KBI adaptation layer for kiserial'''

import shlex
import struct
from functools import reduce
from operator import xor
from time import gmtime, strftime

import colorama
from iptools import ipv6

# Frame types
FT_RES = 0x00 << 4
FT_CMD = 0x01 << 4
FT_RSP = 0x02 << 4
FT_NTF = 0x03 << 4

# Command codes
CC_WRIT = 0x00
CC_EXEC = 0x00
CC_READ = 0x01
CC_DELE = 0x02
CC_RESV = 0x03

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
NC_PINGR_N = 0x02
NC_UDP_N = 0x03
NC_DSTUN = 0x04

# Special commands
CMD_FW_UP = 0x30

# Roles
ROLES = {
    'leader': 6,
    'router': 1,
    'reed': 2,
    'fed': 3,
    'med': 4,
    'sed': 5,
    'not configured': 0,
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
    7: 'change partition',
    8: 'attaching',  # 'joining'
    9: 'not joined',
    10: 'rejected',
    11: 'attaching',  # 'accepted'
    12: 'attaching',  # 'reattaching'
    13: 'rebooting',  # 'reboot synch'
    14: 'rebooting',  # 'reboot success'
    15: 'attaching',  # 'attach dataset'
    16: 'clearing',
}

NONECODES = {
    0: '',
    1: ' - saved configuration',
    2: ' - network not found',
    3: ' - comminssioning failed',
    4: ' - attaching failed',
}

# Steering data
STDATA = {'all': 0, 'none': 1, 'on': 2}


class TYP:
    '''Data types that can be converted from/to string/bytearray'''

    HEX = 0
    HEXN = 1
    DEC = 2
    STR = 3
    STRN = 4
    MAC = 5
    ADDR = 6
    ROLE = 7
    STDATA = 8
    STATUS = 9
    TIME = 10
    SERV = 11
    ADDRL = 12


def s2b(type_, str_, size=0):
    '''String to bytearray transformation'''

    if type_ is TYP.DEC:
        sizes = {1: '>B', 2: '>H', 4: '>L'}
        return struct.pack(sizes[size], int(str_, 10))
    elif type_ is TYP.HEX:
        if len(str_) % 2 == 0 and str_.startswith('0x'):
            return bytearray.fromhex(str_.replace('0x', ''))
    elif type_ is TYP.STR:
        return bytearray(list(map(ord, str_)))
    elif type_ is TYP.STRN:
        str_bytes = bytearray(list(map(ord, str_[:size])))
        return str_bytes + bytearray(size - len(str_bytes))
    elif type_ is TYP.MAC:
        return s2b(TYP.HEX, '0x' + str_.replace('-', ''))
    elif type_ is TYP.ADDR:
        addr = hex(ipv6.ip2long(str_.lower())).replace('0x', '').rstrip('L').zfill(32)
        return bytearray.fromhex(addr)
    elif type_ is TYP.ROLE:
        return bytearray([ROLES.get(str_)])
    elif type_ is TYP.STDATA:
        return bytearray([STDATA.get(str_)])


TEXT2CLI = {
    'clear': {'cc': CC_EXEC, 'cmd': 0x00},
    'config thver': {'cc': CC_WRIT, 'cmd': 0x01, 'params': [lambda x: s2b(TYP.DEC, x, 2)]},
    'show thver': {'cc': CC_READ, 'cmd': 0x01},
    'show uptime': {'cc': CC_READ, 'cmd': 0x02},
    'reset': {'cc': CC_EXEC, 'cmd': 0x03},
    'config autojoin on': {'cc': CC_WRIT, 'cmd': 0x04},
    'config autojoin off': {'cc': CC_DELE, 'cmd': 0x04},
    'show autojoin': {'cc': CC_READ, 'cmd': 0x04},
    'show status': {'cc': CC_READ, 'cmd': 0x05},
    'ping': {'cc': CC_EXEC, 'cmd': 0x06, 'params': [lambda x: s2b(TYP.ADDR, x), lambda x: s2b(TYP.DEC, x, 2)]},
    'ifdown': {'cc': CC_EXEC, 'cmd': 0x07},
    'ifup': {'cc': CC_EXEC, 'cmd': 0x08},
    'config socket add': {'cc': CC_WRIT, 'cmd': 0x09, 'params': [lambda x: s2b(TYP.DEC, x, 2)], 'lastParamOptional': True},
    'config socket del': {'cc': CC_DELE, 'cmd': 0x09, 'params': [lambda x: s2b(TYP.DEC, x, 2)]},
    'show swver': {'cc': CC_READ, 'cmd': 0x0A},
    'show hwver': {'cc': CC_READ, 'cmd': 0x0B},
    'show snum': {'cc': CC_READ, 'cmd': 0x0C},
    'config emac': {'cc': CC_WRIT, 'cmd': 0x0D, 'params': [lambda x: s2b(TYP.MAC, x)]},
    'show emac': {'cc': CC_READ, 'cmd': 0x0D},
    'show eui64': {'cc': CC_READ, 'cmd': 0x0E},
    'config lowpower on': {'cc': CC_WRIT, 'cmd': 0x0F},
    'config lowpower off': {'cc': CC_DELE, 'cmd': 0x0F},
    'show lowpower': {'cc': CC_READ, 'cmd': 0x0F},
    'config txpower': {'cc': CC_WRIT, 'cmd': 0x10, 'params': [lambda x: s2b(TYP.DEC, x, 1)]},
    'show txpower': {'cc': CC_READ, 'cmd': 0x10},
    'config panid': {'cc': CC_WRIT, 'cmd': 0x11, 'params': [lambda x: s2b(TYP.HEX, x)]},
    'show panid': {'cc': CC_READ, 'cmd': 0x11},
    'config channel': {'cc': CC_WRIT, 'cmd': 0x12, 'params': [lambda x: s2b(TYP.DEC, x, 1)]},
    'show channel': {'cc': CC_READ, 'cmd': 0x12},
    'config xpanid': {'cc': CC_WRIT, 'cmd': 0x13, 'params': [lambda x: s2b(TYP.HEX, x)]},
    # Moved here for sequential seek
    'show xpanfilt': {'cc': CC_READ, 'cmd': 0x1F},
    'show xpanid': {'cc': CC_READ, 'cmd': 0x13},
    'config netname': {'cc': CC_WRIT, 'cmd': 0x14, 'params': [lambda x: s2b(TYP.STR, x)]},
    'show netname': {'cc': CC_READ, 'cmd': 0x14},
    'config mkey': {'cc': CC_WRIT, 'cmd': 0x15, 'params': [lambda x: s2b(TYP.HEX, x)]},
    'show mkey': {'cc': CC_READ, 'cmd': 0x15},
    'config commcred': {'cc': CC_WRIT, 'cmd': 0x16, 'params': [lambda x: s2b(TYP.STR, x)]},
    'show commcred': {'cc': CC_READ, 'cmd': 0x16},
    'config joincred': {'cc': CC_WRIT, 'cmd': 0x17, 'params': [lambda x: s2b(TYP.STR, x)]},
    'show joincred': {'cc': CC_READ, 'cmd': 0x17},
    'config joiner add': {'cc': CC_WRIT, 'cmd': 0x18, 'params': [lambda x: s2b(TYP.MAC, x), lambda x: s2b(TYP.STR, x)]},
    'config joiner remove all': {'cc': CC_DELE, 'cmd': 0x18},
    'config joiner remove': {'cc': CC_DELE, 'cmd': 0x18, 'params': [lambda x: s2b(TYP.MAC, x)]},
    'show joiners': {'cc': CC_READ, 'cmd': 0x18},
    'config role': {'cc': CC_WRIT, 'cmd': 0x19, 'params': [lambda x: s2b(TYP.ROLE, x)]},
    'show role': {'cc': CC_READ, 'cmd': 0x19},
    'show rloc16': {'cc': CC_READ, 'cmd': 0x1A},
    'config comm on': {'cc': CC_WRIT, 'cmd': 0x1B},
    'config comm off': {'cc': CC_DELE, 'cmd': 0x1B},
    'config mlprefix': {'cc': CC_WRIT, 'cmd': 0x1C, 'params': [lambda x: s2b(TYP.ADDR, x)[:8]]},
    'show mlprefix': {'cc': CC_READ, 'cmd': 0x1C},
    'config maxchild': {'cc': CC_WRIT, 'cmd': 0x1D, 'params': [lambda x: s2b(TYP.DEC, x, 1)]},
    'show maxchild': {'cc': CC_READ, 'cmd': 0x1D},
    'config timeout': {'cc': CC_WRIT, 'cmd': 0x1E, 'params': [lambda x: s2b(TYP.DEC, x, 4)]},
    'show timeout': {'cc': CC_READ, 'cmd': 0x1E},
    'config xpanfilt add': {'cc': CC_WRIT, 'cmd': 0x1F, 'params': [lambda x: s2b(TYP.HEX, x)]},
    'config xpanfilt remove all': {'cc': CC_DELE, 'cmd': 0x1F},
    'config ipaddr add': {'cc': CC_WRIT, 'cmd': 0x20, 'params': [lambda x: s2b(TYP.ADDR, x)]},
    'config ipaddr remove': {'cc': CC_DELE, 'cmd': 0x20, 'params': [lambda x: s2b(TYP.ADDR, x)]},
    'show ipaddr': {'cc': CC_READ, 'cmd': 0x20},
    'config joinport': {'cc': CC_WRIT, 'cmd': 0x21, 'params': [lambda x: s2b(TYP.HEX, x)]},
    'show heui64': {'cc': CC_READ, 'cmd': 0x22},
    'config pollrate': {'cc': CC_WRIT, 'cmd': 0x23, 'params': [lambda x: s2b(TYP.DEC, x, 4)]},
    'show pollrate': {'cc': CC_READ, 'cmd': 0x23},
    'config outband': {'cc': CC_WRIT, 'cmd': 0x24},
    'config steering': {'cc': CC_WRIT, 'cmd': 0x25, 'params': [lambda x: s2b(TYP.STDATA, x)]},
    'config prefix add': {'cc': CC_WRIT, 'cmd': 0x26, 'params': [lambda x: s2b(TYP.ADDR, x), lambda x: s2b(TYP.DEC, x, 1), lambda x: s2b(TYP.HEX, x)]},
    'config prefix remove': {'cc': CC_DELE, 'cmd': 0x26, 'params': [lambda x: s2b(TYP.ADDR, x), lambda x: s2b(TYP.DEC, x, 1)]},
    'config route add': {'cc': CC_WRIT, 'cmd': 0x27, 'params': [lambda x: s2b(TYP.ADDR, x), lambda x: s2b(TYP.DEC, x, 1), lambda x: s2b(TYP.HEX, x)]},
    'config route remove': {'cc': CC_DELE, 'cmd': 0x27, 'params': [lambda x: s2b(TYP.ADDR, x), lambda x: s2b(TYP.DEC, x, 1)]},
    'config service add': {'cc': CC_WRIT, 'cmd': 0x28, 'params': [lambda x: s2b(TYP.DEC, x, 1), lambda x: s2b(TYP.STR, x), lambda x: s2b(TYP.STR, x)]},
    'config service remove': {'cc': CC_DELE, 'cmd': 0x28, 'params': [lambda x: s2b(TYP.DEC, x, 1), lambda x: s2b(TYP.STR, x)]},
    'show parent': {'cc': CC_READ, 'cmd': 0x29},
    'show routert': {'cc': CC_READ, 'cmd': 0x2A},
    'show ldrdata': {'cc': CC_READ, 'cmd': 0x2B},
    'show netdata': {'cc': CC_READ, 'cmd': 0x2C},
    'show stats': {'cc': CC_READ, 'cmd': 0x2D},
    'show childt': {'cc': CC_READ, 'cmd': 0x2E},
    'netcat': {'cc': CC_EXEC,'cmd': 0x2F,'params': [lambda x: s2b(TYP.DEC, x, 2), lambda x: s2b(TYP.DEC, x, 2), lambda x: s2b(TYP.ADDR, x), lambda x: s2b(TYP.HEX, x)]},
    'config hwmode': {'cc': CC_WRIT, 'cmd': 0x31, 'params': [lambda x: s2b(TYP.DEC, x, 1)]},
    'show hwmode': {'cc': CC_READ, 'cmd': 0x31},
    'config led on': {'cc': CC_WRIT, 'cmd': 0x32},
    'config led off': {'cc': CC_DELE, 'cmd': 0x32},
    'show led': {'cc': CC_READ, 'cmd': 0x32},
    'config vname': {'cc': CC_WRIT, 'cmd': 0x33, 'params': [lambda x: s2b(TYP.STR, x)]},
    'show vname': {'cc': CC_READ, 'cmd': 0x33},
    'config vmodel': {'cc': CC_WRIT, 'cmd': 0x34, 'params': [lambda x: s2b(TYP.STR, x)]},
    'show vmodel': {'cc': CC_READ, 'cmd': 0x34},
    'config vdata': {'cc': CC_WRIT, 'cmd': 0x35, 'params': [lambda x: s2b(TYP.STR, x)]},
    'show vdata': {'cc': CC_READ, 'cmd': 0x35},
    'config vswver': {'cc': CC_WRIT, 'cmd': 0x36, 'params': [lambda x: s2b(TYP.STR, x)]},
    'show vswver': {'cc': CC_READ, 'cmd': 0x36},
    'config actstamp': {'cc': CC_WRIT, 'cmd': 0x37, 'params': [lambda x: s2b(TYP.HEX, x)]},
    'show actstamp': {'cc': CC_READ, 'cmd': 0x37, 'params': [lambda x: s2b(TYP.HEX, x)]},
    'nping': {'cc': CC_EXEC, 'cmd': 0x38, 'params': [lambda x: s2b(TYP.STRN, x, 32), lambda x: s2b(TYP.DEC, x, 2)]},
    'nnetcat': {'cc': CC_EXEC,'cmd': 0x39,'params': [lambda x: s2b(TYP.DEC, x, 2), lambda x: s2b(TYP.DEC, x, 2), lambda x: s2b(TYP.STRN, x, 32), lambda x: s2b(TYP.HEX, x)]},
    'show services': {'cc': CC_READ, 'cmd': 0x3A},
    'config provurl': {'cc': CC_WRIT, 'cmd': 0x3B, 'params': [lambda x: s2b(TYP.STR, x)]},
    'show provurl': {'cc': CC_READ, 'cmd': 0x3C},
    'show commsid': {'cc': CC_READ, 'cmd': 0x3D},
    'exec pendget': {'cc': CC_EXEC, 'cmd': 0x3E, 'params': [lambda x: s2b(TYP.ADDR, x), lambda x: s2b(TYP.HEX, '0x' + x)], 'lastParamOptional': True},
    'exec pendset': {'cc': CC_EXEC, 'cmd': 0x3E, 'params': [lambda x: s2b(TYP.ADDR, x), lambda x: s2b(TYP.HEX, '0x' + x)]},
    'exec activeget': {'cc': CC_EXEC, 'cmd': 0x3F, 'params': [lambda x: s2b(TYP.ADDR, x), lambda x: s2b(TYP.HEX, '0x' + x)], 'lastParamOptional': True},
    'exec activeset': {'cc': CC_EXEC, 'cmd': 0x40, 'params': [lambda x: s2b(TYP.ADDR, x), lambda x: s2b(TYP.HEX, '0x' + x)]},
    'exec commget': {'cc': CC_EXEC, 'cmd': 0X41, 'params': [lambda x: s2b(TYP.ADDR, x), lambda x: s2b(TYP.HEX, '0x' + x)], 'lastParamOptional': True},
    'exec commset': {'cc': CC_EXEC, 'cmd': 0X42, 'params': [lambda x: s2b(TYP.ADDR, x), lambda x: s2b(TYP.HEX, '0x' + x)]},
    'exec panidqry': {'cc': CC_EXEC, 'cmd': 0x43, 'params': [lambda x: s2b(TYP.ADDR, x), lambda x: s2b(TYP.HEX, x), lambda x: s2b(TYP.HEX, x)]},

    # Thread 1.3 commands
    'config cslch': {'cc': CC_WRIT, 'cmd': 0x64, 'params': [lambda x: s2b(TYP.DEC, x, 1)]},
    'show cslch': {'cc': CC_READ, 'cmd': 0x64},
    'config csltout': {'cc': CC_WRIT, 'cmd': 0x65, 'params': [lambda x: s2b(TYP.DEC, x, 4)]},
    'show csltout': {'cc': CC_READ, 'cmd': 0x65},
    'config cslprd': {'cc': CC_WRIT, 'cmd': 0x66, 'params': [lambda x: s2b(TYP.DEC, x, 2)]},
    'show cslprd': {'cc': CC_READ, 'cmd': 0x66},

}



def text_to_kbi(txt_cmd):
    '''Transform a text command into a (type, code, payload) tuple'''
    ctype, cmd = None, None
    payload = bytearray()

    # Combine multiple whitespaces together
    txt_cmd = shlex.split(txt_cmd)

    for key in TEXT2CLI:
        if ' '.join(txt_cmd).startswith(key):
            # Get command definition
            cmd_def = TEXT2CLI.get(key)
            # Fill type and code
            ccode = cmd_def.get('cc', None)
            if ccode is not None:
                ctype = FT_CMD | ccode
            cmd = cmd_def.get('cmd', None)
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

    return ctype, cmd, payload


def b2s(type_, bytes_, size=None):
    '''Bytearray to string transformations'''

    if type_ is TYP.STR:
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
        macs = ''
        while bytes_:
            hex_mac = b2s(TYP.HEX, bytes_[:8]).replace('0x', '')
            macs += '-'.join(
                [
                    hex_mac[0:2],
                    hex_mac[2:4],
                    hex_mac[4:6],
                    hex_mac[6:8],
                    hex_mac[8:10],
                    hex_mac[10:12],
                    hex_mac[12:14],
                    hex_mac[14:16],
                ]
            ) + '\r\n'
            bytes_ = bytes_[8:]
        return macs
    elif type_ is TYP.ADDR:
        hex_addr = b2s(TYP.HEX, bytes_[:size])
        int_addr = int(hex_addr.replace('0x', '').rstrip('L').ljust(32, '0'),
                       16)
        return ipv6.long2ip(int_addr)
    elif type_ is TYP.ADDRL:
        states = {0: 'T', 1: 'R', 4: 'I'}
        addrs = ''
        while bytes_:
            addrs += '[%s] ' % states.get(bytes_[0])
            addrs += b2s(TYP.ADDR, bytes_[1:17], 16) + '\r\n'
            bytes_ = bytes_[17:]
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
            strftime('%H hours, %M minutes and %S seconds', gmtime(uptime)),
        )
        output += 'Current UTC Time : %s\r\n' % strftime('%H:%M:%S', gmtime(utc))
        output += 'MCU Temperature  : %d°C' % temperature
        return output
    elif type_ is TYP.SERV:
        meaning = {0x01: 'on', 0x00: 'off'}
        output = 'DHCP server: ' + meaning[bytes_[0]]
        output += '\nDNS server: ' + meaning[bytes_[1]]
        output += '\nNTP server: ' + meaning[bytes_[2]]
        return output


CLI2TEXT = {
    (FT_RSP | RC_VALUE, 0x01): ['thver', lambda x: b2s(TYP.DEC, x)],
    (FT_RSP | RC_VALUE, 0x02): ['uptime', lambda x: b2s(TYP.TIME, x)],
    (FT_RSP | RC_VALUE, 0x04): ['autojoin', lambda x: b2s(TYP.DEC, x)],
    (FT_RSP | RC_VALUE, 0x05): ['status', lambda x: b2s(TYP.STATUS, x)],
    (FT_RSP | RC_VALUE, 0x09): ['socket', lambda x: b2s(TYP.DEC, x)],
    (FT_RSP | RC_VALUE, 0x0A): ['swver', lambda x: b2s(TYP.STR, x)],
    (FT_RSP | RC_VALUE, 0x0B): ['hwver', lambda x: b2s(TYP.STR, x)],
    (FT_RSP | RC_VALUE, 0x0C): ['snum', lambda x: b2s(TYP.STR, x)],
    (FT_RSP | RC_VALUE, 0x0D): ['emac', lambda x: b2s(TYP.MAC, x)],
    (FT_RSP | RC_VALUE, 0x0E): ['eui64', lambda x: b2s(TYP.MAC, x)],
    (FT_RSP | RC_VALUE, 0x0F): ['lowpower', lambda x: b2s(TYP.DEC, x)],
    (FT_RSP | RC_VALUE, 0x10): ['txpower', lambda x: b2s(TYP.DEC, x)],
    (FT_RSP | RC_VALUE, 0x11): ['panid', lambda x: b2s(TYP.HEX, x)],
    (FT_RSP | RC_VALUE, 0x12): ['channel', lambda x: b2s(TYP.DEC, x)],
    (FT_RSP | RC_VALUE, 0x13): ['xpanid', lambda x: b2s(TYP.HEX, x)],
    (FT_RSP | RC_VALUE, 0x14): ['netname', lambda x: b2s(TYP.STR, x)],
    (FT_RSP | RC_VALUE, 0x15): ['mkey', lambda x: b2s(TYP.HEX, x)],
    (FT_RSP | RC_VALUE, 0x16): ['commcred', lambda x: b2s(TYP.STR, x)],
    (FT_RSP | RC_VALUE, 0x17): ['joincred', lambda x: b2s(TYP.STR, x)],
    (FT_RSP | RC_VALUE, 0x18): ['joiners', lambda x: b2s(TYP.MAC, x)],
    (FT_RSP | RC_VALUE, 0x19): ['role', lambda x: b2s(TYP.ROLE, x)],
    (FT_RSP | RC_VALUE, 0x1A): ['rloc16', lambda x: b2s(TYP.HEX, x)],
    (FT_RSP | RC_VALUE, 0x1C): ['mlprefix', lambda x: b2s(TYP.ADDR, x, 8)],
    (FT_RSP | RC_VALUE, 0x1D): ['maxchild', lambda x: b2s(TYP.DEC, x)],
    (FT_RSP | RC_VALUE, 0x1E): ['timeout', lambda x: b2s(TYP.DEC, x)],
    (FT_RSP | RC_VALUE, 0x1F): ['xpanfilt', lambda x: b2s(TYP.HEX, x)],
    (FT_RSP | RC_VALUE, 0x20): ['ipaddr', lambda x: b2s(TYP.ADDRL, x)],
    (FT_RSP | RC_VALUE, 0x22): ['heui64', lambda x: b2s(TYP.MAC, x)],
    (FT_RSP | RC_VALUE, 0x23): ['pollrate', lambda x: b2s(TYP.DEC, x)],
    (FT_RSP | RC_VALUE, 0x29): ['parent', lambda x: b2s(TYP.HEX, x)],
    (FT_RSP | RC_VALUE, 0x2A): ['routert', lambda x: b2s(TYP.HEX, x).replace('0x', '')],
    (FT_RSP | RC_VALUE, 0x2B): ['ldrdata', lambda x: b2s(TYP.HEX, x).replace('0x', '')],
    (FT_RSP | RC_VALUE, 0x2C): ['netdata', lambda x: b2s(TYP.HEX, x).replace('0x', '')],
    (FT_RSP | RC_VALUE, 0x2D): ['stats', lambda x: b2s(TYP.HEX, x).replace('0x', '')],
    (FT_RSP | RC_VALUE, 0x2E): ['childt', lambda x: b2s(TYP.HEX, x).replace('0x', '')],
    (FT_RSP | RC_VALUE, 0x31): ['hwmode', lambda x: b2s(TYP.DEC, x)],
    (FT_RSP | RC_VALUE, 0x32): ['led', lambda x: b2s(TYP.DEC, x)],
    (FT_RSP | RC_VALUE, 0x33): ['vname', lambda x: b2s(TYP.STR, x)],
    (FT_RSP | RC_VALUE, 0x34): ['vmodel', lambda x: b2s(TYP.STR, x)],
    (FT_RSP | RC_VALUE, 0x35): ['vdata', lambda x: b2s(TYP.STR, x)],
    (FT_RSP | RC_VALUE, 0x36): ['vswver', lambda x: b2s(TYP.STR, x)],
    (FT_RSP | RC_VALUE, 0x37): ['actstamp', lambda x: b2s(TYP.HEX, x)],
    (FT_RSP | RC_VALUE, 0x3A): ['services', lambda x: b2s(TYP.SERV, x)],
    (FT_RSP | RC_VALUE, 0x3C): ['commsid', lambda x: b2s(TYP.HEX, x)],
    (FT_RSP | RC_VALUE, 0x64): ['cslch', lambda x: b2s(TYP.DEC, x)],
    (FT_RSP | RC_VALUE, 0x65): ['csltout', lambda x: b2s(TYP.DEC, x)],
    (FT_RSP | RC_VALUE, 0x66): ['cslprd', lambda x: b2s(TYP.DEC, x)],
}


def kbi_to_text(ctype, cmd, payload):
    response_code = ctype & 0x0F
    # Empty response case
    if response_code == RC_OK and not payload:
        response = ''
    # Value response case
    elif response_code == RC_VALUE:
        rsp_func = CLI2TEXT.get((ctype, cmd), None)
        if rsp_func:
            response = rsp_func[1](payload).encode('latin_1').decode()
        else:
            response = 'Wrong value or parser not implemented'
    elif response_code == RC_BADPAR:
        response = 'Bad parameter'
    elif response_code == RC_BADCOM:
        response = 'Bad command'
    elif response_code == RC_NOTALL:
        response = 'Command not allowed'
    elif response_code == RC_MEMERR:
        response = 'Memory allocation error'
    elif response_code == RC_CFGERR:
        response = 'Configuration settings missing'
    elif response_code == RC_FWUERR:
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

    def __init__(self, txt_cmd, ctype=None, cmd=None, cpload=None):
        self.valid = False
        self.data = bytearray(5)

        if txt_cmd:
            cmd_type, cmd_cmd, cmd_payload = text_to_kbi(txt_cmd)
        else:
            cmd_type = ctype
            cmd_cmd = cmd
            cmd_payload = cpload

        if cmd_type is not None and cmd_cmd is not None:
            self.valid = True

            self.data += cmd_payload

            # Fill the header
            struct.pack_into('>H', self.data, 0, len(cmd_payload))
            struct.pack_into('>B', self.data, 2, cmd_type)
            struct.pack_into('>B', self.data, 3, cmd_cmd)
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
        string += '| %s%02x%s : %s%02x%s : %s%02x%s : %s%02x%s : %s%02x%s ' % (
            colorama.Fore.RED,
            self.data[0],
            colorama.Fore.RESET,
            colorama.Fore.RED,
            self.data[1],
            colorama.Fore.RESET,
            colorama.Fore.GREEN,
            self.data[2],
            colorama.Fore.RESET,
            colorama.Fore.YELLOW,
            self.data[3],
            colorama.Fore.RESET,
            colorama.Fore.BLUE,
            self.data[4],
            colorama.Fore.RESET,
        )
        for byte in self.data[5:]:
            string += ': %s%02x%s ' % (colorama.Fore.MAGENTA, byte, colorama.Fore.RESET)
        string += '|'
        return string


class KBIResponse(KBICommand):
    '''Representation of a Kirale Binary Interface response.'''

    def __init__(self, response, size):
        ''''size' is the result of the COBS decoder, could be a negative value
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
        if (self.get_type() & FT_NTF) == FT_NTF:
            return True
        return False

    def to_text(self):
        if self.is_notification():
            ntf_code = self.get_type() & 0x0F
            payload = self.get_payload()
            if ntf_code == NC_PINGR:
                return '# ping reply: saddr %s id %s sq %s - %s bytes' % (
                    b2s(TYP.ADDR, payload[0:16], 16),
                    b2s(TYP.DEC, payload[18:20], 2),
                    b2s(TYP.DEC, payload[20:22], 2),
                    b2s(TYP.DEC, payload[16:18], 2),
                )
            elif ntf_code == NC_PINGR_N:
                return '# ping reply: saddr %s [%s] id %s sq %s - %s bytes' % (
                    b2s(TYP.ADDR, payload[32:48], 16),
                    b2s(TYP.STR, payload[0:32]),
                    b2s(TYP.DEC, payload[50:52], 2),
                    b2s(TYP.DEC, payload[52:54], 2),
                    b2s(TYP.DEC, payload[48:50], 2),
                )
            elif ntf_code == NC_UDP:
                return '# udp rcv: saddr %s sport %s dport %s - %s bytes' % (
                    b2s(TYP.ADDR, payload[4:20], 16),
                    b2s(TYP.DEC, payload[2:4], 2),
                    b2s(TYP.DEC, payload[0:2], 2),
                    len(payload[20:]),
                )
            elif ntf_code == NC_UDP_N:
                return '# udp rcv: saddr %s [%s] sport %s dport %s - %s bytes' % (
                    b2s(TYP.ADDR, payload[36:52], 16),
                    b2s(TYP.STR, payload[4:35]),
                    b2s(TYP.DEC, payload[2:4], 2),
                    b2s(TYP.DEC, payload[0:2], 2),
                    len(payload[52:]),
                )
            elif ntf_code == NC_DSTUN:
                return '# dst unreachable: daddr %s' % (
                    b2s(TYP.ADDR, payload[0:16], 16)
                )
            else:
                return '# unknown notification'
        else:
            return KBICommand.to_text(self)
