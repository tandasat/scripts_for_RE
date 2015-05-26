#!/usr/bin/python
#
# Launches a suspended process.
#
# Author: Satoshi Tanda
#
################################################################################
# The MIT License (MIT)
#
# Copyright (c) 2015 tandasat
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
'''
Description:
    Launches a specified process with the CREATE_SUSPENDED flag. It can be used
    to examine an initial stage of the process. Noth that you may want to use
    %windir%\Sysnative to start a 64 bit process from a 32 bit python process.
'''
import sys
from ctypes import *

WORD = c_ushort
DWORD = c_ulong
LPBYTE = POINTER(c_ubyte)
LPTSTR = POINTER(c_char)
HANDLE = c_void_p


class STARTUPINFO(Structure):
    _fields_ = [
        ('cb', DWORD),
        ('lpReserved', LPTSTR),
        ('lpDesktop', LPTSTR),
        ('lpTitle', LPTSTR),
        ('dwX', DWORD),
        ('dwY', DWORD),
        ('dwXSize', DWORD),
        ('dwYSize', DWORD),
        ('dwXCountChars', DWORD),
        ('dwYCountChars', DWORD),
        ('dwFillAttribute', DWORD),
        ('dwFlags', DWORD),
        ('wShowWindow', WORD),
        ('cbReserved2', WORD),
        ('lpReserved2', LPBYTE),
        ('hStdInput', HANDLE),
        ('hStdOutput', HANDLE),
        ('hStdError', HANDLE),
    ]


class PROCESS_INFORMATION(Structure):
    _fields_ = [
        ('hProcess', HANDLE),
        ('hThread', HANDLE),
        ('dwProcessId', DWORD),
        ('dwThreadId', DWORD),
    ]


def main():
    if len(sys.argv) != 2:
        print 'Launches a suspended process.'
        print '  > python {} <command_line>'.format(sys.argv[0])
        return
    exe_file = sys.argv[1]

    kernel32 = windll.kernel32
    CREATE_NEW_CONSOLE = 0x00000010
    CREATE_SUSPENDED = 0x00000004
    creation_flags = CREATE_NEW_CONSOLE | CREATE_SUSPENDED

    startupinfo = STARTUPINFO()
    processinfo = PROCESS_INFORMATION()
    startupinfo.cb = sizeof(startupinfo)
    print '[*] Starting: {}'.format(exe_file)
    if kernel32.CreateProcessA(
            None, exe_file, None, None, None, creation_flags, None, None,
            byref(startupinfo), byref(processinfo)):
        print '[+] Process started as PID: {}'.format(processinfo.dwProcessId)
        kernel32.CloseHandle(processinfo.hProcess)
        kernel32.CloseHandle(processinfo.hThread)
    else:
        print '[-] CreateProcessA failed with an error: 0x{:08x}'.format(
            kernel32.GetLastError())


if __name__ == '__main__':
    main()
