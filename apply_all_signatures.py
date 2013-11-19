#!/usr/bin/python
#
# (IDA Pro Only) Applies all FLIRT signatures in a <IDA DIR>/sig directory.
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
    sig_dir = os.path.join(os.path.dirname(sys.executable), 'sig')
    for name in os.listdir(sig_dir): 
        if name[-4:] == '.sig': ApplySig(name)


if __name__=='__main__':
    main()

