#!/usr/bin/python
#
# (IDA Only) Highlights all function call instructions in a given binary file.
#
# Author: Satoshi Tanda
#
###############################################################################
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
###############################################################################
from idc import *
from idaapi import *
from idautils import *


def main():
    processor_name = GetCharPrm(INF_PROCNAME)
    if processor_name == 'metapc':
        call_instruction = 'call'
    elif processor_name == 'ARM':
        call_instruction = 'BL'
    else:
        print 'Unsupported processor type: %s' % (processor_name)
        return
    # For each segment
    for segment_begin_ea in Segments():
        segment_end_ea = SegEnd(segment_begin_ea)
        # For each instruction
        last_page = 0
        for ea in list(Heads(segment_begin_ea, segment_end_ea)):
            # Print log if a processing page changed
            current_page = (ea & 0xffffffffffff0000)
            if last_page != current_page:
                last_page = current_page
                print('Processing 0x%016X (Range of "%s" is 0x%016X - 0x%016X)' %
                      (last_page, SegName(current_page), segment_begin_ea,
                       segment_end_ea)
                      )
            # Set color if this instruction is CALL
            disasm = GetDisasm(ea)
            if disasm[:len(call_instruction)] == call_instruction:
                SetColor(ea, CIC_ITEM, 0xd8bfd8)


if __name__ == '__main__':
    main()
