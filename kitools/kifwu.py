'''Kirale firmware update functions'''

import sys
import struct
import platform
from time import localtime, sleep, strftime, time
from threading import Thread

import usb.core
from tqdm import tqdm

from colorama import Back, Fore, Style

from kitools import kiserial
from kitools import kidfu
from kitools import kicmds

if platform.system() in 'Windows':
    import usb.backend.libusb0 as libusb
else:
    import usb.backend.libusb1 as libusb

if sys.version_info > (3, 0):
    import queue as queue_
else:
    import Queue as queue_

KIRALE_VID = 0x2def


def try_input(txt=None):
    '''Normal input but catching the keyboard interruption'''
    sys.stdout.write(
        '%s%s%s%s%s ' % (Style.BRIGHT, Back.BLUE, Fore.WHITE, txt,
                         Style.RESET_ALL))
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
    return '%s%s%s' % (color, msg, Fore.RESET)


def sys_exit(msg):
    '''Exit with a red message'''
    sys.exit(colorize(msg, Fore.RED))


def get_dfu_devices():
    '''Return a list of connected Kirale DFU devices'''
    dfus = []
    try:
        backend = libusb.get_backend()
    except:
        sys_exit('No USB library found.')
    devs = usb.core.find(idVendor=KIRALE_VID, find_all=True, backend=backend)

    for dev in devs:
        # Detach kernel driver
        if platform.system() not in 'Windows':
            for config in dev:
                for i in range(config.bNumInterfaces):
                    if dev.is_kernel_driver_active(i):
                        dev.detach_kernel_driver(i)
        # Initialize DFU devices
        try:
            dfu = kidfu.KiDfuDevice(dev)
            for _, dev_alt in dfu.alternates():
                if (dev_alt.configuration == 0
                        and dev_alt.bInterfaceNumber == 0
                        and dev_alt.bAlternateSetting == 0):
                    dfu.set_alternate(dev_alt)
                    dfus.append(dfu)
        except usb.core.USBError:
            pass

    return dfus


def dfu_find_and_flash(dfu_file):
    '''Flash a DFU file'''
    # Count DFU devices
    dfus = get_dfu_devices()
    num_dfus = len(dfus)

    # Detach KiNOS running devices
    run_dfus = [dfu for dfu in dfus if not dfu.is_boot()]
    if run_dfus:
        print('\nThe following run-time devices where found:')
        for dfu in run_dfus:
            print(dfu)
        try_input('Press Enter to detach them all...')
        for dfu in run_dfus:
            dfu.detach(0)
        # Wait until all devices are detached
        dfus = []
        while len(dfus) != num_dfus:
            sleep(1)
            dfus = get_dfu_devices()

    # Flash bootloader running devices
    if dfus:
        print('\nThe following DFU devices were found:')
        for dfu in dfus:
            print(dfu)
        try_input('Press Enter to flash them all...')
    else:
        sys_exit('No Kirale DFU devices found.')

    # Program the devices
    parallel_program(dfu_flash, dfus, dfu_file)

    # TODO: Wait until all devices are in runtime


def dfu_flash(dfu, dfu_file, queue, pos=0):
    '''Flash a list of DFU devices with the given file'''
    snum = dfu.get_string(dfu.dev.iSerialNumber)
    try:
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
                    desc=colorize(snum, Fore.CYAN),
                    position=pos,
                    dynamic_ncols=True,
                    leave=False)):
            dfu.write(bnum, block)
            status = dfu.wait_while_state(kidfu.DfuState.DFU_DOWNLOAD_BUSY)
            if status[1] != kidfu.DfuState.DFU_DOWNLOAD_IDLE:
                queue.put('%s: Error %d' % (snum, status[1]))
                return
        dfu.leave()
        status = dfu.get_status()
        if status[1] == kidfu.DfuState.DFU_MANIFEST_SYNC:
            queue.put('%s: OK' % snum)
            return
        queue.put('%s: Error finish' % snum)
    except usb.core.USBError:
        queue.put('%s: USB error' % snum)


def kbi_find_and_flash(dfu_file):
    '''Flash a DFU file'''
    # Count DFU devices
    kidevs = kiserial.find_devices(has_uart=True)

    # Flash bootloader running devices
    if kidevs:
        print('\nFound the following KBI devices:')
        for dev in kidevs:
            print('  %s' % dev)
        try_input('Press Enter to flash them all...')
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
                    desc=colorize(kidev.snum, Fore.CYAN),
                    position=pos,
                    dynamic_ncols=True,
                    leave=False)):
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
    for pos, dev in enumerate(devices):
        threads.append(
            Thread(target=flash_func, args=[dev, dfu_file, queue, pos]))
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
        results.append(queue.get())
    print(
        colorize(
            '\nElapsed: %s' % strftime("%M m %S s", localtime(time() - start)),
            Fore.YELLOW))
    for result in results:
        print('\t' + result)
    print('Flashed %s of %d devices.' %
          (colorize(len([r for r in results if 'OK' in r]), Fore.GREEN),
           len(results)))