'''Kirale Sniffer'''
from __future__ import print_function

import datetime
import os
import platform
import struct
import threading
import time

from kitools import kiserial  # pylint: disable=E0401

if platform.system() in 'Windows':
    import win32api
    import win32file
    import win32pipe

SW_VER = 'Sniffer'


class KiraleFrameHeader:  # pylint: disable=too-few-public-methods
    '''Kirale frame header representation
    |  4 bytes     | 2 bytes |   4 bytes          | Packet |
    | Magic number |  Length | Timestamp[symbols] | ...... |
    |   c11ffe72   |         |                    |        |
    or
    |  4 bytes     | 2 bytes |   8 bytes          | Packet |
    | Magic number |  Length | Timestamp[symbols] | ...... |
    |   534e4946   |         |                    |        |
    or
    |  4 bytes     | 2 bytes | 1 byte | 1 byte |   6 bytes          | Packet |
    | Magic number |  Length |  RSSI  |  LQI   | Timestamp[symbols] | ...... |
    |   b8978c97   |         |        |        |                    |
    or
    |  4 bytes     | 2 bytes | 1 byte | 1 byte |   6 bytes          | Packet |
    | Magic number |  Length |  RSSI  |  LQI   | Timestamp[us]      | ...... |
    |   c0978c97   |         |        |        |                    |
    '''

    REPRS = [
        {'mgc': 0xC11FFE72, 'fmt': '>HL'}, 
        {'mgc': 0x534E4946, 'fmt': '>HQ'},
        {'mgc': 0xB8978C97, 'fmt': '>HQ'},
        {'mgc': 0xC0978C97, 'fmt': '>HQ'}
    ]

    def __init__(self):
        self.bytes = bytearray()
        self.mgc = None
        self.fmt = None
        self.ust = False

    def add_byte(self, byte):
        '''Append a byte to the right of the header and return frame len
         and timestamp if the header is valid'''
        self.bytes.append(byte)
        if len(self.bytes) == 4 and not self.fmt:
            for frame_type in self.REPRS:
                magic = struct.unpack_from('>L', self.bytes)[0]
                if magic == frame_type['mgc']:
                    self.mgc = frame_type['mgc']
                    self.fmt = frame_type['fmt']
                    return None, None, None, None
            self.bytes.pop(0)
        elif self.fmt and len(self.bytes) == (struct.Struct(self.fmt).size + 4):
            frame_len, tstamp = struct.unpack_from(self.fmt, self.bytes[4:])
            if (self.mgc not in [self.REPRS[2]['mgc'], self.REPRS[3]['mgc']]):
                # Old versions doesn't bring RSSI and LQI information
                rssi = 0
                lqi  = 0
            else:
                rssi   = ( tstamp >> 56 ) & 0xFF
                lqi    = ( tstamp >> 48 ) & 0x00FF
            tstamp = tstamp & 0x0000FFFFFFFFFFFF
            self.bytes = bytearray()
            self.fmt = None
            if (self.mgc in [self.REPRS[3]['mgc']]):
                self.ust = True
            return frame_len, tstamp, rssi, lqi
        return None, None, None, None

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

    def __init__(
        self,
        port_name,
        serial_debug=kiserial.KiDebug(kiserial.KiDebug.KSH),
        debug=False,
        link_type_tap=False
    ):
        self.debug = debug
        self.channel = 0
        self.handlers = []
        self.thread = None
        self.is_running = False
        self.init_ts = 0
        self.usec = 0
        self.link_type_tap = link_type_tap
        self.serial_dev = kiserial.KiSerial(port_name, debug=serial_debug)
        self.reset()

    def config_file_handler(self, pcap_file=None, pcap_folder=None):
        '''Set up a file handler to store the received frames'''
        if not pcap_file:
            if not pcap_folder:
                pcap_folder = os.getcwd()
            pcap_file = '%s\\Capture_%s_%s.pcapng' % (
                pcap_folder,
                self.serial_dev.port.name.split('/')[-1],
                time.strftime('%Y-%m-%d_%H-%M-%S', time.localtime(time.time())),
            )
        self.handlers.append(FileHandler(pcap_file, self.link_type_tap))

    def config_pipe_handler(self):
        '''Set up a pipe handler to store the received frames'''
        name = None
        system = platform.system()
        if system in 'Windows':
            name = r'\\.\pipe\Kirale%s' % int(time.time())
            handler = WinPipeHandler(name, self.link_type_tap)
        elif system in 'Linux' or system in 'Darwin':
            name = '/tmp/Kirale%d' % int(time.time())
            handler = UnixFifoHandler(name, self.link_type_tap)
        
        if name:
            self.handlers.append(handler)
        return name

    def start(self, channel):
        '''Start capturing'''
        now = datetime.datetime.now()
        self.init_ts = time.mktime(now.timetuple()) * 1000000 + now.microsecond

        for handle in self.handlers:
            handle.start()

        self.set_channel(channel)

        if self.channel:
            self.is_running = True
            self.serial_dev.ksh_cmd('ifup', no_response=True)
            self.thread = threading.Thread(target=self.receive)
            self.thread.daemon = True
            self.thread.start()
            return True
        elif self.debug:
            print('Unable to initialize Kirale Sniffer on channel %d.' % channel)
        return False

    def stop(self):
        '''Stop capture'''
        self.is_running = False
        self.thread.join()
        self.serial_dev.ksh_cmd('ifdown', no_response=True)
        time.sleep(0.5)  # Allow for last packet before flushing
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
            frame_len, tstamp, rssi, lqi = header.add_byte(byte[0])
            if frame_len is not None:
                frame_data = self.serial_dev.port.read(frame_len)
                if len(frame_data) == frame_len:
                    if not header.ust:
                        self.usec = self.init_ts + tstamp * 16  # Timestamp in symbols
                    else:
                        self.usec = self.init_ts + tstamp       # Timestamp in us                        
                    frame = PCAPFrame(
                        frame_data, self.link_type_tap, self.usec, rssi, lqi, self.channel
                    )
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
        status = self.serial_dev.ksh_cmd('show status', kiserial.KiDebug.NONE, True)
        if status and status[0] == 'none':
            return
        self.serial_dev.ksh_cmd('clear')

    def close(self):
        '''Stop capture'''
        self.serial_dev.ksh_cmd('ifdown', no_response=True)


class PCAPFrame:  # pylint: disable=too-few-public-methods
    '''PCAP frame representation according to Libpcap File Format'''
    '''
    IEEE 802.15.4 TAP Packet
        The IEEE 802.15.4 TAP Packet consists of the TAP Header, zero or more 
        TLV fields, the PHY payload (PSDU), and optional FCS bytes. All data 
        fields are encoded in little-endian byte order.
    IEEE 802.15.4 TAP Header (BBH)
         0               1               2               3
         0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        |     version   |  reserved (0) |           length              |
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        |                           TAP TLVs                            :
        :                        variable length                        |
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        |                             ...                               :
        :                    IEEE 802.15.4 PHY Payload                  :
        :                    [+ FCS per FCS Type TLV]                   :
        :                             ...                               |
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            - version - currently only version 0 defined
            - reserved - must be set to 0
            - length - total length of header and TLVs in octets
        
        Length is a minimum of 4 octets and must be a multiple of 4. Addition of 
        new TLVs does not and must not require incrementing the version number.

    IEEE 802.15.4 TAP TLV Types
        FCS Type (HHI)
            Identifies the FCS type following the PHY Payload. 
            FCS type none (0) is optional if no FCS is present.
             0               1               2               3
             0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |       Type = FCS_TYPE (0)     |           length = 1          |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |    FCS type   |                   padding (0)                 |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            The FCS type is one of
                - 0 = None,
                - 1 = 16-bit CRC,
                - 2 = 32-bit CRC.

        Receive Signal Strength (HHf)
            The received signal strength in dBm as a IEEE-754 floating point number.
             0               1               2               3
             0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |           Type = RSS (1)      |           length = 4          |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |                           RSS in dBm                          |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

        Link Quality Indicator (HHI)
            The Link Quality Indicator (LQI) measurement is a characterization of 
            the strength and/or quality of the received packet. 
            See IEEE 802.15.4-2015 10.2.6 Link quality indicator.
             0               1               2               3
             0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |          Type = LQI (10)      |           length = 1          |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |       LQI     |                  padding (0)                  |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

        Channel Assignment
            Channel assignments are defined through a combination of channel numbers 
            and channel pages. See IEEE 802.15.4-2015 10.1.2 Channel assignments.
             0               1               2               3
             0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            | Type = CHANNEL_ASSIGNMENT (3) |           length = 3          |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |          Channel number       |  Channel page |    padding    |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    '''

    def __init__(self, frame_data, link_type_tap, usec, rssi, lqi, channel):
        if link_type_tap:
            len_tap = 4 + 4 * 8
        else:
            len_tap = 0
        header_libpacp = struct.pack(
            '>LLLL',
            int(usec / 1000000),            # ts_sec
            int(usec % 1000000),            # ts_usec
            int(len(frame_data) + len_tap), # incl_len
            int(len(frame_data) + len_tap), # orig_len
        )
        if link_type_tap:
            header_15_4_tap = struct.pack('<BBH', 0, 0, len_tap)
            # FCS TLV
            tlvs_15_4_tap = struct.pack('<HHI', 0, 1, 1)
            # RSS TLV
            tlvs_15_4_tap += struct.pack('<HHf', 1, 4, float(self._convert_uint8_to_int8(rssi))) 
            # LQI TLV
            tlvs_15_4_tap += struct.pack('<HHI', 10, 1, lqi)
            # Channel TLV
            tlvs_15_4_tap += struct.pack('<HHHH', 3, 3, channel, 0)
            self.frame = header_libpacp + header_15_4_tap + tlvs_15_4_tap + frame_data
        else:
            self.frame = header_libpacp + frame_data

    def get_bytes(self):
        '''Return the full frame as bytearray'''
        return self.frame

    @staticmethod
    def _convert_uint8_to_int8(num):
        if num > 127:
            return (256 - num) * (-1)
        else:
            return num


PCAP_HDR = {
    'format': '>LHHlLLL',
    'magic_number': 0xA1B2C3D4,
    'version_major': 2,
    'version_minor': 4,
    'thiszone': 0,
    'sigfigs': 0,
    'snaplen': 0xFFFF,
    'link_type_1': 195,  # 802.15.4
    'link_type_2': 283,  # IEEE 802.15.4 TAP
}

PCAP_HDR_BYTES_1 = struct.pack(
    PCAP_HDR['format'],
    PCAP_HDR['magic_number'],
    PCAP_HDR['version_major'],
    PCAP_HDR['version_minor'],
    PCAP_HDR['thiszone'],
    PCAP_HDR['sigfigs'],
    PCAP_HDR['snaplen'],
    PCAP_HDR['link_type_1'],
)

PCAP_HDR_BYTES_2 = struct.pack(
    PCAP_HDR['format'],
    PCAP_HDR['magic_number'],
    PCAP_HDR['version_major'],
    PCAP_HDR['version_minor'],
    PCAP_HDR['thiszone'],
    PCAP_HDR['sigfigs'],
    PCAP_HDR['snaplen'],
    PCAP_HDR['link_type_2'],
)

class FileHandler:
    '''PCAP frame handler that saves capture data to a file.'''

    def __init__(self, file_name, link_type_tap):
        self.file_ = open(file_name, 'wb')
        self.link_type_tap = link_type_tap

    def start(self):
        '''Write file header'''
        if not self.link_type_tap:
            self.file_.write(PCAP_HDR_BYTES_1)
        else:
            self.file_.write(PCAP_HDR_BYTES_2)

    def handle(self, frame):
        '''Write the frame to the file'''
        self.file_.write(frame.get_bytes())
        self.file_.flush()  # Interactive file update

    def stop(self):
        '''Close the file'''
        self.file_.close()


class WinPipeHandler:
    '''Windows handler for Wireshark pipe'''

    def __init__(self, name, link_type_tap):
        self.pipe = win32pipe.CreateNamedPipe(
            name,
            win32pipe.PIPE_ACCESS_OUTBOUND,
            win32pipe.PIPE_TYPE_BYTE | win32pipe.PIPE_WAIT,
            1,
            65536,
            65536,
            1000,
            None,
        )
        self.link_type_tap = link_type_tap

    def start(self):
        '''Start the handler'''
        win32pipe.ConnectNamedPipe(self.pipe, None)
        if not self.link_type_tap:
            win32file.WriteFile(self.pipe, PCAP_HDR_BYTES_1)
        else:
            win32file.WriteFile(self.pipe, PCAP_HDR_BYTES_2)            

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


class UnixFifoHandler:
    '''Unix handler for Wireshark fifo'''

    def __init__(self, name, link_type_tap):
        self.name = name
        self.link_type_tap = link_type_tap
        os.mkfifo(self.name)

    def start(self):
        '''Start the handler'''
        # Wait until pipe is open by Wireshark to be able to open it in write mode
        try:
            fifo_fd = os.open(self.name, os.O_NONBLOCK | os.O_WRONLY)
            self.fifo = os.fdopen(fifo_fd, 'wb')
            if not self.link_type_tap:
                self.fifo.write(PCAP_HDR_BYTES_1)
            else:
                self.fifo.write(PCAP_HDR_BYTES_2)                
        except OSError:
            time.sleep(0.1)
            self.start()

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
