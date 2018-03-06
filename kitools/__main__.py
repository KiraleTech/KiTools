'''Kirale tool for serial interfacing KiNOS devices'''
from __future__ import print_function

import argparse
import os
import platform
import sys
from threading import Thread
from time import sleep

from colorama import init as colorama_init
from colorama import Fore, Style

from kitools import kidfu
from kitools import kifwu
from kitools import kiserial
from kitools import kisniffer

if platform.system() in 'Windows':
    WS_PATH = 'C:\\Program Files (x86)\\Wireshark\\Wireshark-gtk.exe'
else:
    WS_PATH = '/usr/bin/tshark'

LOGO = ('\
****************************************************************************\n\
**                              Kirale Tool                               **\n\
****************************************************************************\n\
')


def _get_device():
    '''Ask user to choose a port among the availalbe connected
    Kirale devices'''
    print('Scanning ports...', end='')
    kirale_devs = kiserial.find_devices()
    if kirale_devs:
        print('\rAvailable Kirale devices:')
        for num, dev in enumerate(kirale_devs):
            print('%s%d%s:  %s' % (Fore.GREEN, num + 1, Fore.RESET, dev))
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
    print('\n%sConnection with the port was lost.%s' % (Fore.RED, Fore.RESET))


def port_loop(device):
    '''Terminal simulation.'''
    while True:
        command = kifwu.try_input('%s@%s>' % (
            device.mode, device.name.split('/')[-1]))
        if command:
            response = device.ksh_cmd(command)
            if response:
                for line in response:
                    sys.stdout.write('%s%s\n' % (Fore.CYAN, line.rstrip('\n')))
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
        prog='kitool',
        description='Serial interface to the KiNOS KBI, KSH, DFU and Sniffer')
    parser.add_argument('--version', action='version', version='%(prog)s 1.1')
    parser.add_argument(
        '--port', required=False, type=str, help='serial device to use')
    parser.add_argument(
        '--channel',
        required=False,
        type=int,
        choices=range(11, 27),
        help='sniffer channel (802.15.4)')
    parser.add_argument(
        '--live',
        required=False,
        action='store_true',
        help='launch a Wireshark live capture')
    parser.add_argument(
        '--file',
        required=False,
        type=str,
        default=None,
        help='sniffer capture output file OR Wireshark path when used with --live')
    parser.add_argument(
        '--debug',
        required=False,
        type=int,
        choices=range(0, 5),
        default=0,
        help='show more program output')
    parser.add_argument(
        '--flashdfu',
        required=False,
        type=lambda x: kidfu.DfuFile(x),
        default=None,
        help='provide a DFU file to flash all the connected Kirale devices using DFU protocol'
    )
    parser.add_argument(
        '--flashkbi',
        required=False,
        type=lambda x: kidfu.DfuFile(x),
        default=None,
        help='provide a DFU file to flash all the connected Kirale devices using KBI protocol'
    )
    args = parser.parse_args()

    # Print logo
    #colorama_init(autoreset=True, convert=True)
    colorama_init()
    print(Fore.BLUE + Style.BRIGHT + LOGO + Style.RESET_ALL)

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
            port_name=args.port, debug=kiserial.KiDebug(args.debug))
        # Live capture
        if args.live:
            if not args.file:
                args.file = WS_PATH
            while not os.path.exists(args.file):
                args.file = input('Enter a valid path for Wireshark: ')
            sniffer.config_pipe_handler(ws_path=args.file)
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
            sleep(1)  # Not to keep the processor busy
            for thread in threads:
                if not thread.is_alive():
                    sys.exit('Program finished.')
        except (KeyboardInterrupt, EOFError):
            device.close()
            sys.exit('\nProgram finished by user.')


if __name__ == '__main__':
    main()
