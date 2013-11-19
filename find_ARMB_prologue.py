#!/usr/bin/python
#
# (IDA Pro Only) Finds function-prologue-like byte sequences for ARMB.
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


def main():
    # For each segment
    for segment_begin_ea in Segments():
        segment_end_ea = SegEnd(segment_begin_ea)
        # For each instruction
        for ea in Heads(segment_begin_ea, segment_end_ea):
            code = Word(ea)
            if code == 0xe92d:  # STMFD   SP!, {...}
                print '0x%08X .. %-20s %s' \
                    % (ea, GetFunctionName(ea), GetDisasm(ea))


if __name__=='__main__':
    main()

