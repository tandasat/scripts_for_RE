#!/usr/bin/python
################################################################################
# The MIT License (MIT)
#
# Copyright (c) 2013 tandasat
#
# Permission is hereby granted, free of charge, to any person obtaining a copy of
# this software and associated documentation files (the "Software"), to deal in
# the Software without restriction, including without limitation the rights to
# use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
# the Software, and to permit persons to whom the Software is furnished to do so,
# subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
# FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
# COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
# IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
# CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
################################################################################
"""Decodes a given 32-Bit Windows Device I/O control code

Author: Satoshi Tanda

Description:
    Decodes Windows Device I/O control code into DeviceType, FunctionCode,
    AccessType and MethodType.

Usage:
    $ python this.py <ioctl_code>

Args:
    ioctl_code: device I/O control code in hexadecimal.

Example:
    > python win_ioctl.py 0x220086
    Device   : FILE_DEVICE_UNKNOWN (0x22)
    Function : 0x21
    Method   : METHOD_OUT_DIRECT (2)
    Access   : FILE_ANY_ACCESS (0)
"""

import sys
import os


def decode(ioctl_code):
    access_names = [
        'FILE_ANY_ACCESS',
        'FILE_READ_ACCESS',
        'FILE_WRITE_ACCESS',
        'FILE_READ_ACCESS | FILE_WRITE_ACCESS',
    ]
    method_names = [
        'METHOD_BUFFERED',
        'METHOD_IN_DIRECT',
        'METHOD_OUT_DIRECT',
        'METHOD_NEITHER',
    ]
    device_name_unknown = '<UNKNOWN>'
    device_names = [
        device_name_unknown,               # 0x00000000
        'FILE_DEVICE_BEEP',                # 0x00000001
        'FILE_DEVICE_CD_ROM',              # 0x00000002
        'FILE_DEVICE_CD_ROM_FILE_SYSTEM',  # 0x00000003
        'FILE_DEVICE_CONTROLLER',          # 0x00000004
        'FILE_DEVICE_DATALINK',            # 0x00000005
        'FILE_DEVICE_DFS',                 # 0x00000006
        'FILE_DEVICE_DISK',                # 0x00000007
        'FILE_DEVICE_DISK_FILE_SYSTEM',    # 0x00000008
        'FILE_DEVICE_FILE_SYSTEM',         # 0x00000009
        'FILE_DEVICE_INPORT_PORT',         # 0x0000000a
        'FILE_DEVICE_KEYBOARD',            # 0x0000000b
        'FILE_DEVICE_MAILSLOT',            # 0x0000000c
        'FILE_DEVICE_MIDI_IN',             # 0x0000000d
        'FILE_DEVICE_MIDI_OUT',            # 0x0000000e
        'FILE_DEVICE_MOUSE',               # 0x0000000f
        'FILE_DEVICE_MULTI_UNC_PROVIDER',  # 0x00000010
        'FILE_DEVICE_NAMED_PIPE',          # 0x00000011
        'FILE_DEVICE_NETWORK',             # 0x00000012
        'FILE_DEVICE_NETWORK_BROWSER',     # 0x00000013
        'FILE_DEVICE_NETWORK_FILE_SYSTEM', # 0x00000014
        'FILE_DEVICE_NULL',                # 0x00000015
        'FILE_DEVICE_PARALLEL_PORT',       # 0x00000016
        'FILE_DEVICE_PHYSICAL_NETCARD',    # 0x00000017
        'FILE_DEVICE_PRINTER',             # 0x00000018
        'FILE_DEVICE_SCANNER',             # 0x00000019
        'FILE_DEVICE_SERIAL_MOUSE_PORT',   # 0x0000001a
        'FILE_DEVICE_SERIAL_PORT',         # 0x0000001b
        'FILE_DEVICE_SCREEN',              # 0x0000001c
        'FILE_DEVICE_SOUND',               # 0x0000001d
        'FILE_DEVICE_STREAMS',             # 0x0000001e
        'FILE_DEVICE_TAPE',                # 0x0000001f
        'FILE_DEVICE_TAPE_FILE_SYSTEM',    # 0x00000020
        'FILE_DEVICE_TRANSPORT',           # 0x00000021
        'FILE_DEVICE_UNKNOWN',             # 0x00000022
        'FILE_DEVICE_VIDEO',               # 0x00000023
        'FILE_DEVICE_VIRTUAL_DISK',        # 0x00000024
        'FILE_DEVICE_WAVE_IN',             # 0x00000025
        'FILE_DEVICE_WAVE_OUT',            # 0x00000026
        'FILE_DEVICE_8042_PORT',           # 0x00000027
        'FILE_DEVICE_NETWORK_REDIRECTOR',  # 0x00000028
        'FILE_DEVICE_BATTERY',             # 0x00000029
        'FILE_DEVICE_BUS_EXTENDER',        # 0x0000002a
        'FILE_DEVICE_MODEM',               # 0x0000002b
        'FILE_DEVICE_VDM',                 # 0x0000002c
        'FILE_DEVICE_MASS_STORAGE',        # 0x0000002d
        'FILE_DEVICE_SMB',                 # 0x0000002e
        'FILE_DEVICE_KS',                  # 0x0000002f
        'FILE_DEVICE_CHANGER',             # 0x00000030
        'FILE_DEVICE_SMARTCARD',           # 0x00000031
        'FILE_DEVICE_ACPI',                # 0x00000032
        'FILE_DEVICE_DVD',                 # 0x00000033
        'FILE_DEVICE_FULLSCREEN_VIDEO',    # 0x00000034
        'FILE_DEVICE_DFS_FILE_SYSTEM',     # 0x00000035
        'FILE_DEVICE_DFS_VOLUME',          # 0x00000036
        'FILE_DEVICE_SERENUM',             # 0x00000037
        'FILE_DEVICE_TERMSRV',             # 0x00000038
        'FILE_DEVICE_KSEC',                # 0x00000039
        'FILE_DEVICE_FIPS',                # 0x0000003A
        'FILE_DEVICE_INFINIBAND',          # 0x0000003B
        device_name_unknown,               # 0x0000003C
        device_name_unknown,               # 0x0000003D
        'FILE_DEVICE_VMBUS',               # 0x0000003E
        'FILE_DEVICE_CRYPT_PROVIDER',      # 0x0000003F
        'FILE_DEVICE_WPD',                 # 0x00000040
        'FILE_DEVICE_BLUETOOTH',           # 0x00000041
        'FILE_DEVICE_MT_COMPOSITE',        # 0x00000042
        'FILE_DEVICE_MT_TRANSPORT',        # 0x00000043
        'FILE_DEVICE_BIOMETRIC',           # 0x00000044
        'FILE_DEVICE_PMI',                 # 0x00000045
    ]

    # Parse IOCTL code
    device   = (ioctl_code >> 16) & 0xffff
    access   = (ioctl_code >> 14) & 3
    function = (ioctl_code >> 2)  & 0xfff
    method   = ioctl_code & 3

    if device >= len(device_names):
        device_name = device_name_unknown
    else:
        device_name = device_names[device]

    print 'Device   : %s (0x%X)' % (device_name, device)
    print 'Function : 0x%X' % (function)
    print 'Method   : %s (%d)' % (method_names[method], method)
    print 'Access   : %s (%d)' % (access_names[access], access)
    return


if __name__ == '__main__':
    if len(sys.argv) != 2:
        help(os.path.splitext(os.path.basename(sys.argv[0]))[0])
        exit()

    decode(int(sys.argv[1], 16))

