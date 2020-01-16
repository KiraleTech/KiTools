'''Kirale firmware update functions'''
from __future__ import print_function

import itertools
import os
import platform
import struct
import sys
import time
from threading import Thread

import colorama
import tqdm
import usb.backend.libusb1 as libusb1
import usb.core
import usb.util
from kitools import kicmds, kidfu, kiserial

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

KIRALE_VID = 0x2DEF
MAX_PARALLEL_DEVICES = 18


def try_input(txt=None):
    '''Normal input but catching the keyboard interruption'''
    sys.stdout.write(
        '%s%s%s%s%s '
        % (
            colorama.Style.BRIGHT,
            colorama.Back.BLUE,
            colorama.Fore.WHITE,
            txt,
            colorama.Style.RESET_ALL,
        )
    )
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


def backend_init():
    # Initialize backend
    global BACKEND
    if platform.system() in 'Windows':
        BACKEND = libusb1.get_backend(find_library=lambda x: LIBUSB_PATH)
    else:
        BACKEND = libusb1.get_backend()
    if not BACKEND:
        sys_exit('No USB library found.')


def get_usb_devices():
    '''Return a list of connected Kirale USB devices'''
    return usb.core.find(idVendor=KIRALE_VID, find_all=True, backend=BACKEND)


def get_dfu_devices(size, is_boot=False, timeout=15, required=True):
    '''Return a list of connected Kirale DFU devices'''

    devs = []
    for _ in itertools.repeat(None, timeout):
        devs = []
        for dev in get_usb_devices():
            if is_boot and dev.idProduct == kidfu.KINOS_DFU_PID:
                devs.append(dev)
            elif not is_boot and dev.idProduct != kidfu.KINOS_DFU_PID:
                devs.append(dev)
            else:
                usb.util.dispose_resources(dev)

        if len(devs) >= size:
            break
        for dev in devs:
            usb.util.dispose_resources(dev)
        print('.', end='')
        time.sleep(1)
    print('')

    if required:
        # Initialize DFU devices
        dfus = []
        for dev in devs:
            # Detach kernel driver
            if platform.system() not in 'Windows':
                for config in dev:
                    for i in range(config.bNumInterfaces):
                        try:
                            if dev.is_kernel_driver_active(i):
                                dev.detach_kernel_driver(i)
                        except:
                            pass
            dfus.append(kidfu.KiDfuDevice(dev))
        return dfus


def dfu_find_and_flash(dfu_file, unattended=False):
    '''Flash a DFU file'''

    backend_init()

    # Find run-time Kirale devices
    run_dfus = get_dfu_devices(0, is_boot=False)
    if run_dfus:
        print('List of %d run-time devices:' % len(run_dfus))

        # Detach KiNOS running devices
        for dfu in run_dfus:
            try:
                print(dfu)
                dfu.detach(0)
            except usb.core.USBError:
                pass
            usb.util.dispose_resources(dfu.dev)

        # Wait until all devices are detached
        print('\nWaiting for the devices to detach.', end='')

    boot_dfus = get_dfu_devices(len(run_dfus), is_boot=True)
    print('List of %d DFU devices:' % len(boot_dfus))

    # Print list
    if not boot_dfus:
        return
    for dfu in boot_dfus:
        print(dfu)
        usb.util.dispose_resources(dfu.dev)
    if not unattended:
        try_input('\nPress enter to flash all the listed devices.\n')

    # Flash DFU mode devices
    start = time.time()
    results = []
    dfus = get_dfu_devices(len(boot_dfus), is_boot=True)
    while dfus:
        print('Remaining %d devices. ' % len(dfus), end='')
        batch = dfus[:MAX_PARALLEL_DEVICES]
        print('Flashing a batch of %d devices...' % len(batch))
        results += parallel_program(dfu_flash, batch, dfu_file)
        for dfu in batch:
            usb.util.dispose_resources(dfu.dev)
        dfus = dfus[MAX_PARALLEL_DEVICES:]

    flash_summary(results, start)

    # Wait until all devices are in runtime
    print('\nWaiting for the devices to apply the new firmware.', end='')
    dfus = get_dfu_devices(len(boot_dfus), is_boot=False, required=False)


def flash_summary(results, start):
    print(
        colorize(
            'Elapsed: %s'
            % time.strftime("%M m %S s", time.localtime(time.time() - start)),
            colorama.Fore.YELLOW,
        )
    )
    for result in results:
        print('\t' + result)
    print(
        'Flashed %s of %d devices.'
        % (
            colorize(len([r for r in results if 'OK' in r]), colorama.Fore.GREEN),
            len(results),
        )
    )


def dfu_flash(dfu, dfu_file, queue, pos=0):
    '''Flash a list of DFU devices with the given file'''
    snum = dfu.get_string(dfu.dev.iSerialNumber)
    # Clear left-over errors
    if dfu.get_status()[1] == kidfu.DfuState.DFU_ERROR:
        dfu.clear_status()
    # Flash
    blocks = [dfu_file.data[i : i + 64] for i in range(0, len(dfu_file.data), 64)]
    for bnum, block in enumerate(
        tqdm.tqdm(
            blocks,
            unit='block',
            miniters=1,
            desc=colorize(snum, colorama.Fore.CYAN),
            position=pos,
            dynamic_ncols=True,
            leave=True,
        )
    ):
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
    start = time.time()
    results = parallel_program(kbi_flash, kidevs, dfu_file)
    flash_summary(results, start)


def kbi_flash(kidev, dfu_file, queue, pos=0):
    '''Flash a list of KBI devices with the given file'''
    ctype = kicmds.FT_CMD
    ccode = kicmds.CMD_FW_UP
    crsp_val = kicmds.FT_RSP | kicmds.RC_VALUE
    crsp_err = kicmds.FT_RSP | kicmds.RC_FWUERR
    try:
        dev = kiserial.KiSerial(kidev.port)
        # Flash
        blocks = [dfu_file.data[i : i + 64] for i in range(0, len(dfu_file.data), 64)]
        for bnum, block in enumerate(
            tqdm.tqdm(
                blocks,
                unit='block',
                miniters=1,
                desc=colorize(kidev.snum, colorama.Fore.CYAN),
                position=pos,
                dynamic_ncols=True,
                leave=True,
            )
        ):
            # Payload is the block number plus the data
            payload = struct.pack('>H', bnum) + block
            # Keep sending the same block until the response matches
            retries = 5
            while retries:
                kbi_req = kicmds.KBICommand(None, ctype, ccode, payload)
                kbi_rsp, _ = dev.kbi_cmd(kbi_req)
                if kbi_rsp.is_valid():
                    rtype = kbi_rsp.get_type()
                    rcode = kbi_rsp.get_code()
                    rpload = kbi_rsp.get_payload()
                    # Protocol error, finish
                    if rtype == crsp_err:
                        queue.put('%s: FWU error' % kidev.snum)
                        return
                    elif rtype == crsp_val and len(rpload) >= 2:
                        # Received block number
                        recv_bnum = struct.unpack('>H', rpload[:2])[0]
                        # Block sent successfully
                        if rcode == ccode and recv_bnum == bnum:
                            break
                # Give some time to resend the block
                time.sleep(5)
                retries -= 1
            if not retries:
                queue.put(
                    '%s: Could not send block #%u after 5 retries.' % (kidev.snum, bnum)
                )
                return
        # All went good, reset the device
        dev.ksh_cmd('reset')
        queue.put('%s: OK' % kidev.snum)
    except:
        queue.put('%s: Serial error' % kidev.snum)


def parallel_program(flash_func, devices, dfu_file):
    '''Parallel programming'''
    queue = queue_.Queue()
    threads = []
    results = []
    tqdm.tqdm.monitor_interval = 0

    for pos, dev in enumerate(devices):
        threads.append(Thread(target=flash_func, args=[dev, dfu_file, queue, pos]))
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
        results.append(queue.get())
    print('\n' * len(devices))
    return results
