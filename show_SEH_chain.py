#!/usr/bin/python
#
# (IDA Pro Only) Shows SEH chains (stack and handlers) for all threads.
#
# Author: Satoshi Tanda
#
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
from idc import *
from idaapi import *
from idautils import *


def GetFsBase(tid):
    idc.SelectThread(tid)
    return idaapi.dbg_get_thread_sreg_base(tid, cpu.fs)


def GetExceptionChain(tid):
    fs_base = GetFsBase(tid)
    exc_rr = Dword(fs_base)
    result = []
    while exc_rr != 0xffffffff:
        prev    = Dword(exc_rr)
        handler = Dword(exc_rr + 4)
        print '%6d %08X %08X' % (tid, exc_rr + 4, handler)
        exc_rr  = prev
        result.append(handler)
    return result


def main():
    print 'TID    Address  Handler'
    curr_tid = idc.GetCurrentThreadId()
    result = {}
    for tid in idautils.Threads():
        result[tid] = GetExceptionChain(tid)
    idc.SelectThread(curr_tid)


if __name__=='__main__':
    main()

