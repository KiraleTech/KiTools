'''Kirale tool for serial interfacing KiNOS devices'''
from __future__ import print_function

import argparse
import codecs
import os
import platform
import subprocess
import sys
from threading import Thread
from time import sleep

import colorama
from kitools import kidfu, kifwu, kiserial, kisniffer, __version__

if platform.system() in 'Windows':
    WS_PATH = 'C:\\Program Files (x86)\\Wireshark\\Wireshark-gtk.exe'
else:
    WS_PATH = '/usr/bin/tshark'

LOGO = '\
****************************************************************************\n\
**                              Kirale Tool                               **\n\
****************************************************************************\n\
'


def _get_device():
    '''Ask user to choose a port among the availalbe connected
    Kirale devices'''
    print('Scanning ports...', end='')
    kirale_devs = kiserial.find_devices()
    if kirale_devs:
        print('\rAvailable Kirale devices:')
        for num, dev in enumerate(kirale_devs):
            print(
                '%s%d%s:  %s' % (colorama.Fore.GREEN, num + 1, colorama.Fore.RESET, dev)
            )
        # Don't ask the user if there is only one option
        if len(kirale_devs) == 1:
            return kirale_devs[0].port
        # Ask the user for port selection
        index = 0
        while index not in range(1, len(kirale_devs) + 1):
            typed = kifwu.try_input('Enter port index: ')
            if typed.isdigit():
                index = int(typed)
        return kirale_devs[index - 1].port
    sys.exit('No Kirale devices available.')
    return None


def get_sniffer_channel():
    '''Get a valid channel from input'''
    channel = 0
    while channel not in range(11, 27):
        num = kifwu.try_input('Enter the 802.15.4 capture channel:')
        if num.isdigit():
            channel = int(num)
    return channel


def check_port(device):
    '''Periodically check if the device is connected.
    Finish when disconnection is detected'''
    while device.is_active():
        sleep(0.1)
    print(
        '\n%sConnection with the port was lost.%s'
        % (colorama.Fore.RED, colorama.Fore.RESET)
    )


def port_loop(device):
    '''Terminal simulation.'''
    while True:
        command = kifwu.try_input('%s@%s>' % (device.mode, device.name.split('/')[-1]))
        if command:
            response = device.ksh_cmd(command)
            if response:
                for line in response:
                    colored = '%s%s\n' % (colorama.Fore.CYAN, line.rstrip('\n'))
                    print(colored, end='')
            if 'reset' in command:
                del device
                return


def capture(sniffer, channel):
    '''Capture loop.'''
    sniffer.start(channel)
    print('Capture started on channel %u.' % channel)
    while True:
        sleep(0.1)


def main():
    '''Parse input and start threads'''
    parser = argparse.ArgumentParser(
        prog='KiTools',
        description='Serial interface to the KiNOS KBI, KSH, DFU and Sniffer',
    )
    parser.add_argument(
        '--version', action='version', version='%(prog)s ' + __version__
    )
    parser.add_argument('--port', required=False, type=str, help='serial device to use')
    parser.add_argument(
        '--channel',
        required=False,
        type=int,
        choices=range(11, 27),
        help='sniffer channel (802.15.4)',
    )
    parser.add_argument(
        '--live',
        required=False,
        action='store_true',
        help='launch a Wireshark live capture',
    )
    parser.add_argument(
        '--file',
        required=False,
        type=str,
        default=None,
        help='sniffer capture output file OR Wireshark path when used with --live',
    )
    parser.add_argument(
        '--debug',
        required=False,
        type=int,
        choices=range(0, 5),
        default=0,
        help='show more program output',
    )
    parser.add_argument(
        '--flashdfu',
        required=False,
        type=lambda x: kidfu.DfuFile(x),
        default=None,
        help='provide a DFU file to flash all the connected Kirale devices using DFU protocol',
    )
    parser.add_argument(
        '--flashkbi',
        required=False,
        type=lambda x: kidfu.DfuFile(x),
        default=None,
        help='provide a DFU file to flash all the connected Kirale devices using KBI protocol',
    )
    args = parser.parse_args()

    # Configure output encoding
    if platform.system() not in 'Windows':
        if sys.version_info[:3] < (3,0):
            sys.stdout = codecs.getwriter('utf-8')(sys.stdout)
        elif sys.version_info[:3] < (3,7):
            sys.stdout = codecs.getwriter('utf-8')(sys.stdout.detach())
        else:
            sys.stdout.reconfigure(encoding='utf-8')

    # Print logo
    colorama.deinit()
    colorama.init()
    print(colorama.Fore.BLUE + colorama.Style.BRIGHT + LOGO + colorama.Style.RESET_ALL)

    # Flash DFU file if provided
    if args.flashdfu:
        kifwu.dfu_find_and_flash(args.flashdfu)
        sys.exit('Program finished.')
    if args.flashkbi:
        kifwu.kbi_find_and_flash(args.flashkbi)
        sys.exit('Program finished.')

    # Configure serial port
    if not args.port:
        args.port = _get_device()

    # Threads
    threads = []
    # Sniffer thread
    if kisniffer.KiSniffer.is_sniffer(args.port):
        if not args.channel:
            args.channel = get_sniffer_channel()
        sniffer = kisniffer.KiSniffer(
            port_name=args.port, debug=kiserial.KiDebug(args.debug)
        )
        # Live capture
        if args.live:
            if not args.file:
                args.file = WS_PATH
            while not os.path.exists(args.file):
                args.file = input('Enter a valid path for Wireshark: ')
            name = sniffer.config_pipe_handler()
            wireshark_cmd = [args.file, '-i%s' % name, '-k']
            ws_process = subprocess.Popen(wireshark_cmd)
        # File capture
        else:
            sniffer.config_file_handler(pcap_file=args.file)

        threads.append(Thread(target=capture, args=[sniffer, args.channel]))
        device = sniffer.serial_dev
    # Terminal thread
    else:
        device = kiserial.KiSerialTh(port_name=args.port)
        if not device.is_valid():
            sys.exit('No valid Kirale serial devices found.')
        device.debug = kiserial.KiDebug(kiserial.KiDebug.LOGS, args.debug)
        threads.append(Thread(target=port_loop, args=[device]))

    threads.append(Thread(target=check_port, args=[device]))
    for thread in threads:
        thread.daemon = True
        thread.start()

    while True:
        try:
            sleep(0.5)  # Not to keep the processor busy
            for thread in threads:
                if not thread.is_alive():
                    sys.exit('Program finished.')
        except (KeyboardInterrupt, EOFError):
            device.close()
            if args.live:
                ws_process.kill()
                ws_process.wait()
            sys.exit('\nProgram finished by user.')


if __name__ == '__main__':
    main()
