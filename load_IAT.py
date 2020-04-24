#!/usr/bin/python
#
# Loads an output of a 'dps' command and apply it to the IDB file.
#
# Author: Satoshi Tanda
#
################################################################################
# The MIT License (MIT)
#
# Copyright (c) 2015-2016 tandasat
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
import re


def main():
    path = AskFile(0, '*.*', 'Select a dumped IAT file.')
    if not path:
        return
    for line in open(path, 'r'):
        line = line.replace('`', '')            # take out ' if exists
        # parse an address
        if re.match('^[0-9a-f]{8} ', line):
            # 32bit
            addr = line[0:9]
            symbol = line[19:]
            bytewise = 4
            optype =  FF_DWRD
        elif re.match('^[0-9a-f]{16} ', line):
            # 64bit
            addr = line[0:17]
            symbol = line[27:]
            bytewise = 8
            optype =  FF_QWRD
        else:
            continue
        if re.match('^.+!.+$', symbol) is None:
            continue
        addr = int(addr, 16)
        _, api = symbol.rstrip().split('!')   # only needs a function name

        # Remove garbage to make IDA understand API's signature

        # Discard after space (source code path)
        api = api.split(' ')[0]
        # Fix for ExitProcess often gets a wrong name
        if api.endswith('FSPErrorMessages::CMessageMapper::StaticCleanup+0xc'):
            api = api.replace('FSPErrorMessages::CMessageMapper::StaticCleanup+0xc', 'ExitProcess')
        # Fix for kernelbase.dll related stub functions
        if api.endswith('Implementation'):
            api = api.replace('Implementation', '')
        elif api.endswith('Stub'):
            api = api.replace('Stub', '')
        # IDA does not like +
        api = api.replace('+', '_')
        print(hex(addr), api)

        # Set a data type on the IDB
        MakeUnknown(addr, bytewise, DOUNK_EXPAND)
        MakeData(addr, optype, bytewise, 0)
        if MakeNameEx(addr, api, SN_CHECK | SN_NOWARN) == 1:
            continue
        # Try to name it as <name>_N up to _99
        for i in range(100):
            if MakeNameEx(addr, api + '_' + str(i), SN_CHECK | SN_NOWARN) == 1:
                break
            if i == 99:
                MakeName(addr, api)   # Display an error message
    print (
        'Load an appropriate FLIRT signature if it is not applied yet.\n'
        'Then, use [Options] > [General] > [Analysis] > [Reanalyze program] to'
        ' reflect those API signatures.'
    )

if __name__ == '__main__':
    main()
