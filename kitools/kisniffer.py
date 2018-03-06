'''Kirale Sniffer'''
from __future__ import print_function

import os
import platform
import struct
import subprocess
import threading
from time import time, strftime, localtime

from kitools import kiserial # pylint: disable=E0401

if platform.system() in 'Windows':
    import win32api
    import win32file
    import win32pipe

SW_VER = 'Sniffer'


class KiraleFrameHeader():  # pylint: disable=too-few-public-methods
    '''Kirale frame header representation
    |  4 bytes     | 2 bytes |   4 bytes     | Packet |
    | Magic number |  Length | Timestamp[us] | ...... |
    |   c11ffe72   |         |               |        |
    '''

    MAGIC_NUMBER = 0xC11FFE72
    FRAME_HDR_FMT = '>LHL'

    def __init__(self):
        self.bytes = bytearray(struct.Struct(self.FRAME_HDR_FMT).size)

    def add_byte(self, byte):
        '''Append a byte to the right of the header and return frame len
         and timestamp if the header is valid'''
        self.bytes.pop(0)
        self.bytes.append(byte)
        magic_number, frame_len, tstamp = struct.unpack_from(
            self.FRAME_HDR_FMT, self.bytes)
        if magic_number == self.MAGIC_NUMBER:
            return frame_len, tstamp
        return None, None

    def __str__(self):
        return ' '.join([hex(byte) for byte in self.bytes])


class KiSniffer:
    '''Kirale Sniffer class'''

    @staticmethod
    def is_sniffer(port_name):
        '''Check is there is a Kirale Sniffer in the given port'''
        serial_dev = kiserial.KiSerial(port_name)
        valid = serial_dev.is_valid()
        if valid:
            valid = KiSniffer.valid_version(serial_dev)
        del serial_dev
        return valid

    @staticmethod
    def valid_version(serial_dev):
        '''Determines if a KiSerial device has a valid sniffer firmware
        version'''
        if SW_VER not in serial_dev.ksh_cmd('show swver')[-1]:
            return False
        return True

    def __init__(self,
                 port_name,
                 serial_debug=kiserial.KiDebug(kiserial.KiDebug.KSH),
                 debug=False):

        self.debug = debug
        self.channel = 0
        self.handlers = []
        self.thread = None
        self.is_running = False
        self.usec = 0
        self.serial_dev = kiserial.KiSerial(port_name, debug=serial_debug)
        self.reset()

    def config_file_handler(self, pcap_file=None, pcap_folder=None):
        '''Set up a file handler to store the received frames'''
        if not pcap_file:
            if not pcap_folder:
                pcap_folder = os.getcwd()
            pcap_file = '%s\\Capture_%s_%s.pcapng' % (
                pcap_folder, self.serial_dev.port.name.split('/')[-1],
                strftime('%Y-%m-%d_%H-%M-%S', localtime(time())))
        self.handlers.append(FileHandler(pcap_file))

    def config_pipe_handler(self, ws_path):
        '''Set up a pipe handler to store the received frames'''
        if platform.system() in 'Windows':
            self.handlers.append(WinPipeHandler(ws_path))
        elif platform.system() in 'Linux':
            self.handlers.append(UnixFifoHandler(ws_path))

    def start(self, channel):
        '''Start capturing'''
        self.set_channel(channel)

        if self.channel:
            self.is_running = True
            self.serial_dev.ksh_cmd('ifup', no_response=True)
            self.thread = threading.Thread(target=self.receive)
            self.thread.daemon = True
            self.thread.start()
            return True
        elif self.debug:
            print(
                'Unable to initialize Kirale Sniffer on channel %d.' % channel)
        return False

    def stop(self):
        '''Stop capture'''
        self.is_running = False
        self.thread.join()
        self.serial_dev.flush_buffer()
        self.serial_dev.ksh_cmd('ifdown', no_response=True)
        self.serial_dev.flush_buffer()
        for handler in self.handlers:
            handler.stop()
        self.handlers = []

    def receive(self):
        '''Keep receiving and sending frames to the handlers'''
        header = KiraleFrameHeader()
        while self.is_running:
            byte = self.serial_dev.port.read(1)
            if not byte:
                continue
            frame_len, tstamp = header.add_byte(byte[0])
            if frame_len is not None:
                frame_data = self.serial_dev.port.read(frame_len)
                if len(frame_data) == frame_len:
                    self.usec += tstamp
                    frame = PCAPFrame(frame_data, self.usec)
                    for handler in self.handlers:
                        handler.handle(frame)


    def set_channel(self, channel):
        '''Set the channel if it is valid'''
        if not self.is_running:
            if channel in range(11, 27):
                self.channel = channel
                self.serial_dev.ksh_cmd('config channel %s' % channel)
            elif self.debug:
                print('Channel must be between 11 and 26.')
        elif self.debug:
            print('Channel setting while running not allowed.')

    def get_channel(self):
        '''Return current channel'''
        return self.channel

    def reset(self):
        '''Reset device'''
        status = self.serial_dev.ksh_cmd('show status', True)
        if status and status[0] == 'none':
            return
        self.serial_dev.ksh_cmd('clear')


class PCAPFrame:  # pylint: disable=too-few-public-methods
    '''PCAP frame representation according to Libpcap File Format'''

    def __init__(self, frame_data, usec):
        header = struct.pack(
            '>LLLL',
            int(usec / 1000000),  # ts_sec
            usec % 1000000,  # ts_usec
            len(frame_data),  # incl_len
            len(frame_data)  # orig_len
        )
        self.frame = header + frame_data

    def get_bytes(self):
        '''Return the full frame as bytearray'''
        return self.frame


PCAP_HDR = {
    'format': '>LHHlLLL',
    'magic_number': 0xa1b2c3d4,
    'version_major': 2,
    'version_minor': 4,
    'thiszone': 0,
    'sigfigs': 0,
    'snaplen': 0xffff,
    'network': 195  # 802.15.4
}

PCAP_HDR_BYTES = struct.pack(
    PCAP_HDR['format'], PCAP_HDR['magic_number'], PCAP_HDR['version_major'],
    PCAP_HDR['version_minor'], PCAP_HDR['thiszone'], PCAP_HDR['sigfigs'],
    PCAP_HDR['snaplen'], PCAP_HDR['network'])


class FileHandler:
    '''PCAP frame handler that saves capture data to a file.'''

    def __init__(self, file_name):
        self.file_ = open(file_name, 'wb')
        self.file_.write(PCAP_HDR_BYTES)

    def handle(self, frame):
        '''Write the frame to the file'''
        self.file_.write(frame.get_bytes())
        self.file_.flush()  # Interactive file update

    def stop(self):
        '''Close the file'''
        self.file_.close()


class WinPipeHandler:
    '''Windows handler for Wireshark pipe'''

    def __init__(self, ws_path):
        self.pipe = None
        self.ws_process = None

        pipe_name = 'Kirale%d' % int(time())
        self.pipe = win32pipe.CreateNamedPipe(
            r'\\.\pipe\%s' % pipe_name, win32pipe.PIPE_ACCESS_OUTBOUND,
            win32pipe.PIPE_TYPE_BYTE | win32pipe.PIPE_WAIT, 1, 65536, 65536,
            1000, None)
        wireshark_cmd = [ws_path, r'-i\\.\pipe\%s' % pipe_name, '-k']
        self.ws_process = subprocess.Popen(wireshark_cmd)
        win32pipe.ConnectNamedPipe(self.pipe, None)
        win32file.WriteFile(self.pipe, PCAP_HDR_BYTES)

    def handle(self, frame):
        '''Pass the frame bytes to the pipe'''
        try:
            win32file.WriteFile(self.pipe, frame.get_bytes())
        except Exception:  # pywintypes.error
            pass

    def stop(self):
        '''Stop the handler'''
        if win32file.FlushFileBuffers(self.pipe):
            if win32pipe.DisconnectNamedPipe(self.pipe):
                win32api.CloseHandle(self.pipe)
                self.ws_process.kill()
                self.ws_process.wait()


class UnixFifoHandler:
    '''Unix handler for Wireshark fifo'''

    def __init__(self, ws_path):
        fifo_name = '/tmp/Kirale%d' % int(time())
        os.mkfifo(fifo_name)
        # Lauch Wireshark
        wireshark_cmd = [ws_path, r'-i%s' % fifo_name]
        self.ws_process = subprocess.Popen(wireshark_cmd)
        # Wait until pipe is open by Wireshark to be able to open it in write mode
        fifo_fd = os.open(fifo_name, os.O_NONBLOCK | os.O_WRONLY)
        self.fifo = os.fdopen(fifo_fd, 'wb')
        self.fifo.write(PCAP_HDR_BYTES)

    def handle(self, frame):
        '''Pass the frame bytes to the fifo'''
        try:
            self.fifo.write(frame.get_bytes())
            self.fifo.flush()
        except Exception:
            pass

    def stop(self):
        '''Stop the handler'''
        self.fifo.close()
        self.ws_process.kill()
        self.ws_process.wait()