#!/usr/bin/python
"""(IDA Pro Only) Merges a given function with the next function

Author: Satoshi Tanda

Description:
    Merges a given function with the next function by extending the end.

Usage:
    Load the script via [File] > [Script file...]
    or
    Call merge_functions function with or without parameters from the Python
    CLI window.

Example:
    Python>merge_functions(0x00468D6E)
    The end of 'sub_468D68' was extended to 0x00468DB1
"""

LICENSE = """
The MIT License (MIT)

Copyright (c) 2014 tandasat

Permission is hereby granted, free of charge, to any person obtaining a copy of
this software and associated documentation files (the "Software"), to deal in
the Software without restriction, including without limitation the rights to
use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
the Software, and to permit persons to whom the Software is furnished to do so,
subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
"""
from idc import *
from idaapi import *
from idautils import *


def merge_functions(top_func_ea=None):
    """Merges a given function with the next function."""
    if not top_func_ea:
        prompt = ('Please input any address ' +
                  'belongs to the function to be extended.')
        top_func_ea = idc.AskAddr(idaapi.get_screen_ea(), prompt)
    if top_func_ea == idc.BADADDR or not top_func_ea:
        return
    next_func = idaapi.get_next_func(top_func_ea)
    next_func_name = idc.GetFunctionName(next_func.startEA)
    name = idc.GetFunctionName(top_func_ea)
    if next_func_name[:4] != 'sub_':
        prompt = (
            "A function '" + name + "' will be merged with a next function '" +
            next_func_name + "'.\nDo you want to continue?")
        if idc.AskYN(0, prompt) != 1:
            return
    end_ea = idaapi.get_next_func(top_func_ea).endEA
    idc.DelFunction(idaapi.get_next_func(top_func_ea).startEA)
    idc.SetFunctionEnd(top_func_ea, end_ea)
    print "'%s' was extended to 0x%08X" % (name, end_ea)
    idc.Jump(end_ea - 1)


if __name__ == '__main__':
    merge_functions()
