'''Kirale Serial communications'''
import sys
from itertools import repeat
from threading import Thread
from time import clock, sleep

import serial
from serial.tools.list_ports import comports
from colorama import init as colorama_init
from colorama import Back, Fore, Style

from kitools import kicmds
from kitools import kicobs

if sys.version_info > (3, 0):
    import queue
else:
    import Queue as queue

KSHPROMPT = 'kinos@local:~$ '


class KiDebug:
    '''Used by KiSerial to show different information in stdout.
    Options: NONE, KSH, KBI, LOGS, DEBUG'''
    NONE = 0
    KSH = 1
    KBI = 2
    LOGS = 3
    DEBUG = 4

    def __init__(self, *args):
        self._options = []
        if self.KSH in args:
            self._options.append(self.KSH)
        if self.KBI in args:
            self._options.append(self.KBI)
        if self.LOGS in args:
            self._options.append(self.LOGS)
        if self.DEBUG in args:
            self._options.append(self.DEBUG)

    def print_(self, option, txt):
        '''Print the text if the ooption is enabled'''
        if option in self._options:
            if option == self.LOGS:
                txt = Fore.BLACK + Back.CYAN + txt + Style.RESET_ALL
                sleep(0.05) #  Try to avoid stdout concurrency problems
            sys.stdout.write(str(txt) + '\n') #  Otherwise print makes two calls

    def has_option(self, option):
        '''Return True if the current instance has the option activated'''
        return option in self._options


class KiSerial:
    '''Class used for serial communications with a Kirale device'''

    KBI_MODE = 'KBI'
    KSH_MODE = 'KSH'
    KBI_ERRORS = {-1: ' COBS error.', -2: ' Read timeout.'}

    def __init__(self, port_name, baud=115200, debug=KiDebug()):
        self.name = port_name
        self.hex_mac = ''
        self.debug = KiDebug()
        self.bright = False

        # Determine whether the device is attached via USB or UART
        self.mode = self.KBI_MODE
        for dev in serial.tools.list_ports.grep('VID:PID=2DEF:'):
            if port_name in dev:
                self.mode = self.KSH_MODE
                self.logs = []
                break

        # Initialize serial
        try:
            self.port = KiSerial.get_kirale_port(port_name, baud)
        except (ValueError, serial.SerialException):
            self.port = None

        if self.port:
            colorama_init()
            self.debug = debug
            self.run = True
            self.start()

    def start(self):
        '''Other needed init operations'''
        if self.is_valid():
            self.port.timeout = 3
            self.port.writeTimeout = 3

    def close(self):
        '''Optional closing operations'''
        pass

    @staticmethod
    def get_kirale_port(name, baud):
        '''Return a Serial object with the required parameters'''
        driver_error = 'A device attached to the system is not functioning.'
        try:
            return serial.Serial(name, baudrate=baud, timeout=0.2)
        except serial.serialutil.SerialException as exc:
            if driver_error in str(exc):
                # Retry in case of Windows driver problems
                return KiSerial.get_kirale_port(name, baud)
            else:
                raise exc

    def is_valid(self):
        '''Determine if the device is a valid Kirale device'''
        if self.port:
            snum = self.ksh_cmd('show snum') or ['']
            if snum[0].startswith('KT'):
                return True
        return False

    def is_active(self):
        '''Check if the device has been disconnected'''
        try:
            self.port.inWaiting()
        except (OSError, serial.SerialException):
            return False
        return True

    def set_mac(self, hex_mac):
        '''Set the device's mac'''
        self.hex_mac = hex_mac

    def bright_logs(self):
        '''Set device as DUT'''
        self.bright = True

    def flush_buffer(self):
        '''Flush input and output buffers of the serial device'''
        if sys.version_info > (3, 0):
            self.port.reset_output_buffer()
            self.port.reset_input_buffer()
        else:
            self.port.flushOutput()
            self.port.flushInput()

    def kbi_cmd(self, cmd):
        '''Send and receive a KBI command'''
        # Print command
        self.debug.print_(KiDebug.KBI, cmd)
        # Encode
        enc_cmd = kicobs.Encoder()
        enc_cmd.encode(cmd.get_data())
        self.debug.print_(KiDebug.KBI, enc_cmd)
        # Send to KiNOS
        self.flush_buffer()
        cmd_start = clock()
        self.port.write(enc_cmd.get_data())
        # Receive response
        decoded = kicobs.Decoder()
        size = 0
        while size is 0:
            byte = self.port.read(1)
            if not byte:
                size = -2  # Read timeout
                break
            # Python 2 transformation
            if isinstance(byte, str):
                byte = bytearray([byte])
            size = decoded.decode(byte[0])
        elapsed = clock() - cmd_start
        # Print response
        self.debug.print_(KiDebug.KBI, decoded)
        # Check
        kbi_rsp = kicmds.KBIResponse(decoded.get_data(), size)
        if kbi_rsp.is_valid():
            self.debug.print_(KiDebug.KBI, kbi_rsp)
            return kbi_rsp, elapsed
        else:
            error = self.KBI_ERRORS.get(size, ' Decode error.')
            self.debug.print_(KiDebug.KBI, error)
        return None, 0

    def usb_cmd(self, cmd, no_response=False):
        '''Send a command via USB CDC'''
        cmd_out = bytearray()
        response = []

        cmd_start = clock()
        self.port.write((cmd + '\r').encode('latin_1'))
        if no_response:
            elapsed = clock() - cmd_start
            return response, elapsed
        while KSHPROMPT.encode('latin_1') not in cmd_out:
            char = self.port.read(1)
            if not char:
                self.debug.print_(KiDebug.DEBUG, ' Read timeout.')
                break  # Read timeout
            rest = self.port.read(self.port.in_waiting)
            cmd_out += char + rest
        elapsed = clock() - cmd_start
        cmd_out = cmd_out.decode('latin_1').replace(KSHPROMPT, '').splitlines()
        for line in cmd_out:
            if line and line[0] == '#':
                self.logs.append(line)
                self.debug.print_(KiDebug.LOGS, line)
            else:
                response.append(line)
        return response, elapsed

    def ksh_cmd(self, txt_cmd, debug_level=None, no_response=False):
        '''Send a text command'''
        cmd_out = []
        # Save debug setting and stop debug
        if debug_level is not None:
            debug = self.debug
            self.debug = KiDebug(debug_level)
        # Print command
        if txt_cmd:
            self.debug.print_(KiDebug.KSH, self.ksh2str(txt_cmd, color=Fore.GREEN))
        elapsed = 0
        try:
            # UART command
            if self.mode is self.KBI_MODE:
                cmd_out = ['Syntax error']
                kbi_req = kicmds.KBICommand(txt_cmd)
                if kbi_req.is_valid():
                    kbi_rsp, elapsed = self.kbi_cmd(kbi_req)
                    cmd_out = ['Response code not matching']
                    if kbi_rsp is None:
                        # Perform one retry in case of COBS error/timeout
                        sleep(0.1)
                        kbi_rsp, elapsed = self.kbi_cmd(kbi_req)
                    if kbi_rsp is None:
                        cmd_out = ['Read timeout']
                    elif kbi_rsp.get_code() is kbi_req.get_code():
                        cmd_out = kbi_rsp.to_text().splitlines()
            # USB command
            else:
                cmd_out, elapsed = self.usb_cmd(
                    txt_cmd, no_response=no_response)
        except (serial.SerialException, serial.SerialTimeoutException):
            cmd_out = ['Serial problem']
        # Print the response
        for line in cmd_out:
            self.debug.print_(KiDebug.KSH,
                              self.ksh2str(
                                  line.rstrip('\r\n'), color=Fore.YELLOW))
        # Print elapsed time
        self.debug.print_(KiDebug.DEBUG,
                          ' [Elapsed %u us]' % int(elapsed * 1000000))
        # Restore debug setting
        if debug_level is not None:
            self.debug = debug
        return cmd_out

    def wait_for(self, key, value, inverse=False):
        '''Keep sending the command "show <key>" until <value> is found
        in the response or 120 seconds have passed'''
        vset = set(value)
        for _ in repeat(None, 120):
            rset = set(self.ksh_cmd('show %s' % key, debug_level=KiDebug.NONE))
            # Finish if value is found in the response
            if not inverse and not rset.isdisjoint(vset):
                break
            # Finish if value is not found in the response
            if inverse and rset.isdisjoint(vset):
                break
            sleep(1)

    def start_logs(self, level='all', module='all'):
        '''Enable device logs for required level and module'''
        self.logs = []
        self.ksh_cmd('debug module %s' % module, debug_level=KiDebug.LOGS)
        self.ksh_cmd('debug level %s' % level, debug_level=KiDebug.LOGS)

    def get_logs(self, wait=0):
        '''Stop device logs and return them'''
        for _ in repeat(None, wait):
            self.ksh_cmd('', debug_level=KiDebug.LOGS)
            sleep(1)
        self.ksh_cmd('debug module none', debug_level=KiDebug.LOGS)
        self.ksh_cmd('debug level none', debug_level=KiDebug.LOGS)
        self.flush_buffer()
        return self.logs

    def ksh2str(self, cmd, color=Fore.GREEN):
        '''Colored print of the command'''
        port = Fore.CYAN
        mac = Fore.MAGENTA
        if self.bright:
            color += Style.BRIGHT
            port += Style.BRIGHT
            mac += Style.BRIGHT
        string = ('%s%-5s%s|%s%s%s> %s%s%s' %
                  (port, self.name.split('/')[-1], Style.RESET_ALL, mac,
                   self.hex_mac, Style.RESET_ALL, color, cmd, Style.RESET_ALL))
        return string

class KiSerialTh(KiSerial):
    '''This extension class makese use of threading to be able to catch logs
    and notifications in real time.'''

    def start(self):
        self.read_queue = queue.Queue()
        self.write_queue = queue.Queue()
        self.read_thread = Thread(target=self._reader)
        self.write_thread = Thread(target=self._writer)
        # Daemon mode is useful if device is removed without closing
        self.read_thread.daemon = True
        self.write_thread.daemon = True
        self.read_thread.start()
        self.write_thread.start()

    def close(self):
        '''Need to be called in order to stop the threads'''
        if self.port:
            self.run = False
            self.write_queue.put(None)
            self.read_thread.join()
            self.write_thread.join()
            self.port.close()

    def _reader(self):
        decoded = kicobs.Decoder()
        log_line = ''
        received_chars = ''
        log_start = False

        while self.run:
            data = self.port.read(self.port.inWaiting() or 1)
            # KBI
            if self.mode is self.KBI_MODE:
                for byte in data:
                    size = decoded.decode(byte)
                    if size is not 0:
                        self.debug.print_(KiDebug.KBI, decoded)
                        kbi_rsp = kicmds.KBIResponse(decoded.get_data(), size)
                        self.debug.print_(KiDebug.KBI, kbi_rsp)
                        if kbi_rsp.is_valid():
                            if kbi_rsp.is_notification():
                                self.debug.print_(KiDebug.LOGS, kbi_rsp.to_text())
                            else:
                                self.read_queue.put(kbi_rsp)
                        else:
                            error = self.KBI_ERRORS.get(size, ' Decode error.')
                            self.debug.print_(KiDebug.KBI, error)
                            self.read_queue.put(None)
                        decoded = kicobs.Decoder()
            # KSH
            else:
                for char in data.decode('latin_1'):
                    if char is '#':
                        log_start = True
                    if log_start:
                        if char is '\n':
                            log_start = False
                            self.logs.append(log_line)
                            self.debug.print_(KiDebug.LOGS, log_line)
                            log_line = ''
                        else:
                            log_line += char
                    else:
                        received_chars += char
                if KSHPROMPT in received_chars:
                    response = received_chars.replace(KSHPROMPT, '').splitlines()
                    self.read_queue.put(response)
                    received_chars = ''

    def _writer(self):
        while self.run:
            sleep(0.2)
            cmd = self.write_queue.get()
            if not cmd:
                return
            # KBI
            if self.mode is self.KBI_MODE:
                self.debug.print_(KiDebug.KBI, cmd)
                enc_cmd = kicobs.Encoder()
                enc_cmd.encode(cmd.get_data())
                self.debug.print_(KiDebug.KBI, enc_cmd)
                data = enc_cmd.get_data()
                self.flush_buffer()
            # KSH
            else:
                data = (cmd['cmd'] + '\r').encode('latin_1')
                if cmd['no_response']:
                    self.read_queue.put([])
            self.port.write(data)

    def ksh_cmd(self, txt_cmd, debug_level=None, no_response=False):
        '''Send a text command'''
        cmd_out = []

        # Save debug setting and stop debug
        if debug_level is not None:
            debug = self.debug
            self.debug = KiDebug(debug_level)

        # Print command
        self.debug.print_(KiDebug.KSH, self.ksh2str(txt_cmd, color=Fore.GREEN))

        cmd_start = clock()
        try:
            # KBI
            if self.mode is self.KBI_MODE:
                cmd_out = ['Syntax error']
                kbi_req = kicmds.KBICommand(txt_cmd)
                if kbi_req.is_valid():
                    self.write_queue.put(kbi_req)
                    kbi_rsp = self.read_queue.get(block=True, timeout=3)
                    cmd_out = ['Response code not matching']
                    if kbi_rsp is None:
                        # Perform one retry in case of COBS error/timeout
                        sleep(0.1)
                        self.write_queue.put(kbi_req)
                        kbi_rsp = self.read_queue.get(block=True, timeout=3)
                    elif kbi_rsp.get_code() is kbi_req.get_code():
                        cmd_out = kbi_rsp.to_text().splitlines()
            # KSH
            else:
                self.write_queue.put({
                    'cmd': txt_cmd,
                    'no_response': no_response
                })
                cmd_out = self.read_queue.get(block=True, timeout=3)
        except (serial.SerialException, serial.SerialTimeoutException):
            cmd_out = ['Serial problem']
        except queue.Empty:
            cmd_out = ['Read timeout']
        elapsed = clock() - cmd_start

        # Print the response
        for line in cmd_out:
            self.debug.print_(KiDebug.KSH,
                              self.ksh2str(
                                  line.rstrip('\r\n'), color=Fore.YELLOW))

        # Print elapsed time
        self.debug.print_(KiDebug.DEBUG,
                          ' [Elapsed %u us]' % int(elapsed * 1000000))

        # Restore debug setting
        if debug_level is not None:
            self.debug = debug

        return cmd_out

    def get_logs(self, wait=0):
        '''Stop device logs and return them'''
        sleep(wait)
        self.ksh_cmd('debug module none', debug_level=KiDebug.LOGS)
        self.ksh_cmd('debug level none', debug_level=KiDebug.LOGS)
        return self.logs


class KiDevice:
    '''A Kirale device descriptor useful for device selection'''

    def __init__(self, port, desc, snum, swver, mode):
        self.port = port
        self.desc = desc
        self.snum = snum
        self.swver = swver
        self.mode = mode

    def __str__(self):
        return '%-14s%-5s%-30s%-36s%s' % (self.port, self.mode, self.swver,
                                          self.snum, self.desc)


def find_devices(has_snum=None, has_br=None, has_uart=None):
    '''Find connected Kirale devices and return a list of KiDevice objects'''
    devices = []
    for port, desc, _ in comports():
        device = KiSerial(port)
        if device.is_valid():
            snum = device.ksh_cmd('show snum')[-1]
            swver = device.ksh_cmd('show swver')[-1]
            # Serial number filter
            if has_snum is not None:
                if snum != has_snum:
                    continue
            # Border router filter
            if has_br is not None:
                is_br = 'hwmode' in ''.join(device.ksh_cmd('config'))
                if has_br != is_br:
                    continue
            # UART filter
            if has_uart is not None:
                if has_uart != (device.mode == device.KBI_MODE):
                    continue
            devices.append(KiDevice(port, desc, snum, swver, device.mode))
        del device
    return devices
