'''DFU helper based on https://github.com/plietar/dfuse-tool'''

import argparse
import struct
import time

import usb.util

DFU_REQUEST_SEND = 0x21
DFU_REQUEST_RECEIVE = 0xa1

DFU_DETACH = 0x00
DFU_DOWNLOAD = 0x01
DFU_UPLOAD = 0x02
DFU_GETSTATUS = 0x03
DFU_CLRSTATUS = 0x04
DFU_GETSTATE = 0x05
DFU_ABORT = 0x06


class DfuDevice:
    def __init__(self, device):
        self.dev = device
        self.cfg = self.dev[0]
        self.intf = None
        self.cfg.set()

    def alternates(self):
        return [(self.get_string(intf.iInterface), intf) for intf in self.cfg]

    def get_string(self, index):
        return usb.util.get_string(self.dev, index)

    def set_alternate(self, intf):
        if isinstance(intf, tuple):
            self.intf = intf[1]
        else:
            self.intf = intf
        self.intf.set_altsetting()

    def control_msg(self, requestType, request, value, buffer):
        return self.dev.ctrl_transfer(requestType, request, value,
                                      self.intf.bInterfaceNumber, buffer)

    def detach(self, timeout):
        return self.control_msg(DFU_REQUEST_SEND, DFU_DETACH, timeout, None)

    def download(self, blockNum, data):
        return self.control_msg(DFU_REQUEST_SEND, DFU_DOWNLOAD, blockNum, data)

    def upload(self, blockNum, size):
        return self.control_msg(DFU_REQUEST_RECEIVE, DFU_UPLOAD, blockNum,
                                size)

    def get_status(self):
        status = self.control_msg(DFU_REQUEST_RECEIVE, DFU_GETSTATUS, 0, 6)
        return (status[0], status[4],
                status[1] + (status[2] << 8) + (status[3] << 16), status[5])

    def clear_status(self):
        self.control_msg(DFU_REQUEST_SEND, DFU_CLRSTATUS, 0, None)

    def get_state(self):
        return self.control_msg(DFU_REQUEST_RECEIVE, DFU_GETSTATE, 0, 1)[0]

    def write(self, block, data):
        return self.download(block, data)

    def leave(self):
        return self.download(0x0, [])  # Just send an empty data.

    def wait_while_state(self, state):
        if not isinstance(state, (list, tuple)):
            states = (state, )
        else:
            states = state

        status = self.get_status()

        while status[1] in states:
            status = self.get_status()
            time.sleep(status[2] / 1000)

        return status

    def __str__(self):
        return '\t0x%04x\t0x%04x\t%s\t%s\t%s' % (
            self.dev.idVendor, self.dev.idProduct,
            self.get_string(self.dev.iManufacturer),
            self.get_string(self.dev.iProduct),
            self.get_string(self.dev.iSerialNumber))


class KiDfuDevice(DfuDevice):
    '''Kirale DFU device'''

    KINOS_DFU_PID = 0x0000

    def is_boot(self):
        return self.dev.idProduct == self.KINOS_DFU_PID

    def _get_boot_ver(self):
        # Don't try to get boot ver from a runtime device
        if not self.is_boot():
            return ''
        # Clear left-over errors
        if self.get_status()[1] == DfuState.DFU_ERROR:
            self.clear_status()
        # Read version
        bytes_ver = self.upload(0, 2)
        return 'v%u.%u' % (bytes_ver[0], bytes_ver[1])

    def __str__(self):
        return '\t0x%04x\t0x%04x\t%s\t%s %s\t%s' % (
            self.dev.idVendor, self.dev.idProduct,
            self.get_string(self.dev.iManufacturer),
            self.get_string(self.dev.iProduct),
            self._get_boot_ver(),
            self.get_string(self.dev.iSerialNumber))


def parse(fmt, data, names):
    '''Return dict from data'''
    return dict(zip(names, struct.unpack(fmt, data)))


class DfuFile:
    '''DFU file'''

    def __init__(self, path):
        self.data = []
        self.dev_info = dict()

        try:
            dfufile = open(path, 'rb')
        except:
            raise argparse.ArgumentTypeError('Could not open file %r' % path)

        with dfufile:
            file_data = dfufile.read()
            self.data = file_data[:-16]
            suffix = parse("<HHHH3sBL", file_data[-16:],
                           ('fwVersion', 'pid', 'vid', 'dfuSpec', 'signature',
                            'length', 'crc'))
            if suffix['signature'] != b'UFD':
                raise argparse.ArgumentTypeError(
                    'File\'s suffix signature does not match')

            self.dev_info = dict(suffix)
            del self.dev_info['signature']
            del self.dev_info['length']
            del self.dev_info['crc']


class DfuState():
    APP_IDLE = 0x00
    APP_DETACH = 0x01
    DFU_IDLE = 0x02
    DFU_DOWNLOAD_SYNC = 0x03
    DFU_DOWNLOAD_BUSY = 0x04
    DFU_DOWNLOAD_IDLE = 0x05
    DFU_MANIFEST_SYNC = 0x06
    DFU_MANIFEST = 0x07
    DFU_MANIFEST_WAIT_RESET = 0x08
    DFU_UPLOAD_IDLE = 0x09
    DFU_ERROR = 0x0a


class DfuStatus:
    OK = 0x00
    ERROR_TARGET = 0x01
    ERROR_FILE = 0x02
    ERROR_WRITE = 0x03
    ERROR_ERASE = 0x04
    ERROR_CHECK_ERASED = 0x05
    ERROR_PROG = 0x06
    ERROR_VERIFY = 0x07
    ERROR_ADDRESS = 0x08
    ERROR_NOTDONE = 0x09
    ERROR_FIRMWARE = 0x0a
    ERROR_VENDOR = 0x0b
    ERROR_USBR = 0x0c
    ERROR_POR = 0x0d
    ERROR_UNKNOWN = 0x0e
    ERROR_STALLEDPKT = 0x0f
