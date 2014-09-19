#!/usr/bin/python
#
# Provides __ROR4__, __ROR8__, __ROL4__ and __ROL8__ functions.
#
# Author: Satoshi Tanda
#
################################################################################
# The MIT License (MIT)
#
# Copyright (c) 2014 tandasat
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
def _rol(val, bits, bit_size):
    return (val << bits % bit_size) & (2 ** bit_size - 1) | \
           ((val & (2 ** bit_size - 1)) >> (bit_size - (bits % bit_size)))

def _ror(val, bits, bit_size):
    return ((val & (2 ** bit_size - 1)) >> bits % bit_size) | \
           (val << (bit_size - (bits % bit_size)) & (2 ** bit_size - 1))

__ROR4__ = lambda val, bits: _ror(val, bits, 32)
__ROR8__ = lambda val, bits: _ror(val, bits, 64)
__ROL4__ = lambda val, bits: _rol(val, bits, 32)
__ROL8__ = lambda val, bits: _rol(val, bits, 64)

print('__ROR4__, __ROR8__, __ROL4__ and __ROL8__ were defined.')
print('Try this in the Python interpreter:')
print('hex(__ROR8__(0xD624722D3A28E80F, 0xD6))')

