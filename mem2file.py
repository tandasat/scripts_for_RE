#!/usr/bin/python
#
# Modifies the give raw PE memory dump file to load it with IDA properly.
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
    Loads a raw memory dump file represents a PE image and modifies its header
    values for allowing IDA to populate data into the exact same location as on
    process memory.
'''
import os
import sys
import pefile
import binascii


def main():
    if len(sys.argv) != 2 and len(sys.argv) != 3:
        print('Fix a raw memory PE file to load it with IDA.')
        print('  > python {} <input_file> [output_file]'.format(sys.argv[0]))
        return
    input_file_path = sys.argv[1]
    if len(sys.argv) == 3:
        output_file_path = sys.argv[2]
    else:
        name, extension = os.path.splitext(input_file_path)
        output_file_path = name + '_fixed' + extension
    pe = pefile.PE(input_file_path)
    # Invalidate the import directory rather than leaving it as is and letting
    # IDA interpret it. It will not work out.
    imp_dir = pe.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY[
        'IMAGE_DIRECTORY_ENTRY_IMPORT']]
    if imp_dir.VirtualAddress != 0:
        print('Import Directory RVA : {:08x} => 0'.format(
            imp_dir.VirtualAddress))
        imp_dir.VirtualAddress = 0
    # Fix the section headers.
    index = 1
    for section in pe.sections:
        new_raw_size = max(section.SizeOfRawData, section.Misc_VirtualSize)
        print('Section {} : \'{}\' {}'.format(
            index, section.Name, binascii.hexlify(section.Name)))
        print('  SizeOfRawData   : {:08x} => {:08x}'.format(
            section.SizeOfRawData, new_raw_size))
        print('  PointerToRawData: {:08x} => {:08x}'.format(
            section.PointerToRawData, section.VirtualAddress))
        section.SizeOfRawData = new_raw_size
        section.PointerToRawData = section.VirtualAddress
        index += 1
    pe.write(filename=output_file_path)


if __name__ == '__main__':
    main()
