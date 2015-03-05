#!/usr/bin/python
#
# Loads an output of a 'dps' command and apply it to the IDB file.
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
import re


def main():
    path = AskFile(0, '*.*', 'Select a dumped IAT file.')
    if not path:
        return
    for line in open(path, 'r'):
        addr = line[0:9]
        symbol = line[19:]
        if re.match('^[0-9a-f]{8} $', addr) is None or symbol == '':
            continue
        addr = int(addr, 16)
        _, api = symbol.rstrip().split('!')
        # Remove garbage make IDA understand API's signature
        api = api.split(' ')[0]
        if api.endswith('Implementation'):
            api = api.replace('Implementation', '')
        elif api.endswith('Stub'):
            api = api.replace('Stub', '')
        print hex(addr), api
        MakeUnknown(addr, 4, DOUNK_EXPAND)
        MakeData(addr, FF_DWRD, 4, 0)
        if MakeNameEx(addr, api, SN_CHECK | SN_NOWARN) == 1:
            continue
        # Try to name it as <name>_N up to _9
        for i in range(10):
            if MakeNameEx(addr, api + '_' + str(i), SN_CHECK | SN_NOWARN) == 1:
                break
            if i == 9:
                MakeName(addr, api)   # Display an error message
    print (
        'Load an appropriate FLIRT signature if IDA is not applied it yet.\n'
        'Then, use [Options] > [General] > [Analysis] > [Reanalyze program] to'
        ' reflect API signatures.'
    )

if __name__ == '__main__':
    main()
