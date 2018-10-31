'''Kirale firmware update functions'''
from __future__ import print_function

import os
import sys
import struct
import platform
from itertools import repeat
from time import localtime, sleep, strftime, time
from threading import Thread

import colorama
import usb.core
import usb.util
from tqdm import tqdm

from kitools import kiserial
from kitools import kidfu
from kitools import kicmds

import usb.backend.libusb1 as libusb1
BACKEND = None

if sys.version_info > (3, 0):
    import queue as queue_
else:
    import Queue as queue_

# Set the libusb path
if platform.system() in 'Windows':
    LIBUSB_PATH = os.path.dirname(sys.argv[0])
    if '32bit' in str(platform.architecture()):
        LIBUSB_PATH += '\\libusb\\MS32\\libusb-1.0.dll'
    else:
        LIBUSB_PATH += '\\libusb\\MS64\\libusb-1.0.dll'

KIRALE_VID = 0x2def


def try_input(txt=None):
    '''Normal input but catching the keyboard interruption'''
    sys.stdout.write(
        '%s%s%s%s%s ' % (colorama.Style.BRIGHT, colorama.Back.BLUE,
                         colorama.Fore.WHITE, txt, colorama.Style.RESET_ALL))
    try:
        if sys.version_info > (3, 0):
            typed = input().strip()
        else:
            typed = raw_input().strip()  # pylint: disable=E0602
    except (KeyboardInterrupt, EOFError):
        sys.exit('Program finished by the user.')
    return typed


def colorize(msg, color):
    '''Return the message colorized'''
    return '%s%s%s' % (color, msg, colorama.Fore.RESET)


def sys_exit(msg):
    '''Exit with a red message'''
    sys.exit(colorize(msg, colorama.Fore.RED))


def get_usb_devices():
    '''Return a list of connected Kirale USB devices'''
    return usb.core.find(idVendor=KIRALE_VID, find_all=True, backend=BACKEND)


def get_dfu_devices():
    '''Return a list of connected Kirale DFU devices'''
    dfus = []

    for dev in get_usb_devices():
        # Detach kernel driver
        if platform.system() not in 'Windows':
            for config in dev:
                for i in range(config.bNumInterfaces):
                    if dev.is_kernel_driver_active(i):
                        dev.detach_kernel_driver(i)
        # Initialize DFU devices
        try:
            dfus.append(kidfu.KiDfuDevice(dev))
        except:  # usb.core.USBError, NotImplementedError:
            pass

    return dfus


def dfu_find_and_flash(dfu_file):
    '''Flash a DFU file'''
    # Initialize backend
    global BACKEND
    if platform.system() in 'Windows':
        BACKEND = libusb1.get_backend(find_library=lambda x: LIBUSB_PATH)
    else:
        BACKEND = libusb1.get_backend()
    if not BACKEND:
        sys_exit('No USB library found.')

    # Count DFU devices
    dfus = get_dfu_devices()
    num_dfus = len(dfus)

    # Detach KiNOS running devices
    run_dfus = [dfu for dfu in dfus if not dfu.is_boot()]
    if run_dfus:
        print(
            '\nThe following %d run-time devices where found:' % len(run_dfus))
        for dfu in run_dfus:
            print(dfu)
        try_input('Press Enter to detach them all.')
        print('Detaching devices...')
        for dfu in dfus:
            if not dfu.is_boot():
                try:
                    dfu.detach(0)
                except usb.core.USBError:
                    pass
            usb.util.dispose_resources(dfu.dev)
        # Wait until all devices are detached
        sleep(2 + 0.1 * num_dfus)

    # Flash DFU mode devices
    dfus = [dfu for dfu in get_dfu_devices() if dfu.is_boot()]
    if len(dfus) < num_dfus:
        sys_exit('Expecting at least %d DFU devices, found %d.' % (num_dfus,
                                                                   len(dfus)))
    if not dfus:
        sys_exit('No Kirale DFU devices found.')

    print('\nThe following %d DFU devices were found:' % len(dfus))
    for dfu in dfus:
        print(dfu)
    try_input('Press Enter to flash them all.')
    parallel_program(dfu_flash, dfus, dfu_file)
    for dfu in dfus:
        usb.util.dispose_resources(dfu.dev)

    # Wait until all devices are in runtime
    print(
        '\nPlease wait for all the devices to return to run-time mode...',
        end='')
    for _ in repeat(None, 12):
        sleep(1)
        print('.', end='')
        if len(list(get_usb_devices())) == num_dfus:
            print('')
            return
    sys_exit('\nSome of the devices were not properly flashed.')


def dfu_flash(dfu, dfu_file, queue, pos=0):
    '''Flash a list of DFU devices with the given file'''
    snum = dfu.get_string(dfu.dev.iSerialNumber)
    # Clear left-over errors
    if dfu.get_status()[1] == kidfu.DfuState.DFU_ERROR:
        dfu.clear_status()
    # Flash
    blocks = [
        dfu_file.data[i:i + 64] for i in range(0, len(dfu_file.data), 64)
    ]
    for bnum, block in enumerate(
            tqdm(
                blocks,
                unit='block',
                miniters=1,
                desc=colorize(snum, colorama.Fore.CYAN),
                position=pos,
                dynamic_ncols=True,
                leave=True)):
        try:
            dfu.write(bnum, block)
            status = dfu.wait_while_state(kidfu.DfuState.DFU_DOWNLOAD_BUSY)
            if status[1] != kidfu.DfuState.DFU_DOWNLOAD_IDLE:
                queue.put('%s: Error %d' % (snum, status[1]))
                return
        except usb.core.USBError:
            queue.put('%s: USB error' % snum)
            return
    dfu.leave()
    status = dfu.get_status()
    if status[1] == kidfu.DfuState.DFU_MANIFEST_SYNC:
        queue.put('%s: OK' % snum)
        return
    queue.put('%s: Error finish' % snum)


def kbi_find_and_flash(dfu_file):
    '''Flash a DFU file'''
    # Count DFU devices
    kidevs = kiserial.find_devices(has_uart=True)

    # Flash bootloader running devices
    if kidevs:
        print('\nFound the following KBI devices:')
        for dev in kidevs:
            print('  %s' % dev)
        try_input('Press Enter to flash them all.')
    else:
        sys_exit('No KBI devices found.')

    # Program the devices
    parallel_program(kbi_flash, kidevs, dfu_file)


def kbi_flash(kidev, dfu_file, queue, pos=0):
    '''Flash a list of KBI devices with the given file'''
    try:
        dev = kiserial.KiSerial(kidev.port)
        # Flash
        blocks = [
            dfu_file.data[i:i + 64] for i in range(0, len(dfu_file.data), 64)
        ]
        for bnum, block in enumerate(
                tqdm(
                    blocks,
                    unit='block',
                    miniters=1,
                    desc=colorize(kidev.snum, colorama.Fore.CYAN),
                    position=pos,
                    dynamic_ncols=True,
                    leave=True)):
            # Payload is the block number plus the data
            payload = struct.pack('>H', bnum) + block
            # Keep sending the same block until the response matches
            retries = 5
            while retries:
                kbi_req = kicmds.KBICommand(None, 0x40, 0x2f, payload)
                kbi_rsp, _ = dev.kbi_cmd(kbi_req)
                if kbi_rsp.is_valid():
                    # Protocol error, finish
                    if kbi_rsp.get_type() is 0x87:
                        queue.put('%s: FWU error' % kidev.snum)
                        return
                    # Received block number
                    if kbi_rsp.get_payload() is not None:
                        recv_bnum = struct.unpack('>H',
                                                  kbi_rsp.get_payload()[:2])[0]
                    # Block sent successfully
                    if kbi_rsp.get_type() is 0x81 and kbi_rsp.get_code(
                    ) is 0x2f and recv_bnum == bnum:
                        break
                # Give some time to resend the block
                sleep(5)
                retries -= 1
            if not retries:
                queue.put('%s: Could not send block #%u after 5 retries.' %
                          (kidev.snum, bnum))
                return
        # All went good, reset the device
        dev.ksh_cmd('reset')
        queue.put('%s: OK' % kidev.snum)
    except:
        queue.put('%s: Serial error' % kidev.snum)


def parallel_program(flash_func, devices, dfu_file):
    '''Parallel programming'''
    start = time()
    queue = queue_.Queue()
    threads = []
    results = []
    tqdm.monitor_interval = 0

    for pos, dev in enumerate(devices):
        threads.append(
            Thread(target=flash_func, args=[dev, dfu_file, queue, pos]))
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
        results.append(queue.get())
    print('\n' * len(devices))
    print(
        colorize(
            'Elapsed: %s' % strftime("%M m %S s", localtime(time() - start)),
            colorama.Fore.YELLOW))
    for result in results:
        print('\t' + result)
    print('Flashed %s of %d devices.' % (colorize(
        len([r for r in results if 'OK' in r]), colorama.Fore.GREEN),
                                         len(results)))
