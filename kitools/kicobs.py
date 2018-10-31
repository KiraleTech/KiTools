'''Kirale COBS implementation according to:
https://tools.ietf.org/html/draft-ietf-pppext-cobs-00'''

from itertools import groupby
from struct import unpack

import colorama


def _enc2str(encoded):
    '''Return encoded bytes array as a string'''
    string = '|'
    for byte in encoded:
        string += (
            ' %s%02x%s :' % (colorama.Fore.CYAN, byte, colorama.Fore.RESET))
    string += ('\b|')
    return string


class Encoder:
    '''Provides a method to COBS encode a bytearray.'''

    def __init__(self):
        self.out = bytearray()  # Output
        self.data = bytearray()  # Block of data
        self.zeros = bytearray()  # Block of zeros

    def _enc_step(self, code, dlen, zlen):
        self.out += bytearray([code]) + self.data[:dlen]
        self.data = self.data[dlen:]
        self.zeros = self.zeros[zlen:]

    def encode(self, data):
        '''Applies COBS to data and stores it'''
        blocks = groupby(data + bytearray(1), lambda x: x is 0)
        for block in blocks:
            # Block of data
            if not block[0]:
                self.data = bytearray(block[1])
            # Block of zeros
            else:
                self.zeros = bytearray(block[1])
                # The data bytes, no implicit trailing zero
                while len(self.data) >= 0xcf:
                    self._enc_step(0xd0, 0xd0 - 1, 0)
                # The data bytes, plus two trailing zeroes
                if len(self.zeros) > 1 and len(self.data) <= 0x1e:
                    self._enc_step(0xe0 + len(self.data), len(self.data), 2)
                # A run of (n-D0) zeroes
                while len(self.zeros) > 15 and len(self.data) is 0:
                    self._enc_step(0xdf, 0, 15)
                if len(self.zeros) > 2 and len(self.data) is 0:
                    self._enc_step(0xd0 + len(self.zeros), 0, len(self.zeros))
                # The data bytes, plus implicit trailing zero
                while self.zeros:
                    self._enc_step(len(self.data) + 1, len(self.data), 1)

    def get_data(self):
        '''Return the encoded data, with a starting 0'''
        return bytearray(1) + self.out

    def __str__(self):
        return _enc2str(self.out)


class Decoder:
    '''Provides a method to COBS decode byte for byte.'''

    def __init__(self):
        self.inc = bytearray()  # Input
        self.out = bytearray()  # Output
        self.remaining = 0  # Remaining bytes
        self.zeros = 0  # Zeros to append
        self.length = None  # Message length

    def decode(self, byte):
        '''Applies COBS decoding byte for byte. A decoding if finished
        when the return value is different from zero.'''
        ret = 0
        # Python 2 transformation
        if isinstance(byte, str):
            byte = bytearray([byte])[0]
        self.inc += bytearray([byte])

        # Analyze code
        if self.remaining is 0:
            # PPP error
            if byte >= 0xff:
                ret = -1
            # The data bytes, plus two trailing zeroes
            elif byte >= 0xe0:
                self.remaining = byte - 0xe0
                self.zeros = 2
            # A run of (n-D0) zeroes
            elif byte > 0xd2:
                self.zeros = byte - 0xd0
            # Unused
            elif byte > 0xd0:
                ret = -1
            # The data bytes, no implicit trailing zero
            elif byte is 0xd0:
                self.remaining = byte - 1
            # The data bytes, plus implicit trailing zero
            elif byte > 0x0:
                self.remaining = byte - 1
                self.zeros = 1
            # Restart reception
            else:
                self = Decoder()
        # Append data
        else:
            self.out += bytearray([byte])
            self.remaining -= 1

        # Append zeros
        if self.remaining is 0:
            self.out += bytearray(self.zeros)
            self.zeros = 0

        # Extract message length
        if self.length is None:
            if len(self.out) >= 2:
                self.length = unpack('>H', self.out[:2])[0] + 5
        # Check finish
        elif len(self.out) > self.length:
            ret = self.length
            self.out = self.out[:-1]

        return ret

    def get_data(self):
        '''Return the decoded data'''
        return self.out

    def __str__(self):
        return _enc2str(self.inc)
