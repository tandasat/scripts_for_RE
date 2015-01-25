#!/usr/bin/python
#
# Locates SEH try blocks, exception filters and handlers for Windows RT files.
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


class RuntimeFuncton(object):
    '''Represents RUNTIME_FUNCTION'''
    def __init__(self, address):
        self.begin_address = Dword(address) + idaapi.get_imagebase()
        self.unwind_info = Dword(address + 4)

    def _get_flag(self):
        return self.unwind_info & 3

    def _get_content(self):
        return self.unwind_info & ~3

    def get_xdata(self):
        # A pdata entry has xata when a Flag field is zero.
        if self._get_flag():
            return None
        name = Name(self.begin_address & ~1)
        xdata_addr = (self._get_content() + idaapi.get_imagebase())
        return XdataRecord(name, xdata_addr)


class XdataRecord(object):
    '''Represents an xdata record'''
    def __init__(self, name, address):
        self.begin_address = address
        MakeDword(address)
        if name[:4] == 'sub_':
            name = '_' + name      # make it _sub_ when original was sub_
        MakeName(address, name + '_xdata')

    def get_exp_handler_info(self):
        xdata_header = Dword(self.begin_address)
        # Check an X field to determine if it has exception information
        if (xdata_header & 0x00100000) == 0:
            return None

        print('%08x : %s' % (self.begin_address, Name(self.begin_address)))
        # Check if either EpilogueCount field or CodeWords field has value
        if xdata_header & 0xFF800000:
            # Use 1st word
            epilogue_count = (xdata_header & 0x0F800000) >> 23
            code_words = (xdata_header & 0xF0000000) >> 28
            offset = self.begin_address + 4
        else:
            # It has an extra header; use 2nd word
            xdata_header_ex = Dword(self.begin_address + 4)
            MakeDword(self.begin_address + 4)
            epilogue_count = (xdata_header_ex & 0x0000FFFF)
            code_words = (xdata_header_ex & 0x00FF0000) >> 16
            offset = self.begin_address + 8
        # Consider EpilogueCount when an E field is zero.
        if (xdata_header & 0x00200000) == 0 and epilogue_count != 0:
            MakeDword(offset)
            MakeArray(offset, epilogue_count)
            offset += epilogue_count * 4
        addr = offset + code_words * 4
        MakeByte(offset)                            # skip Unwind Opcodes
        MakeArray(offset, code_words * 4)
        return ExceptionHandlerInformation(addr)    # get Exception Info


class ExceptionHandlerInformation(object):
    '''Represents Exception Handler Information (a.k.a, SCOPE_TABLE)'''
    def __init__(self, address):
        self.address = address
        self.exp_handler = Dword(address) + idaapi.get_imagebase()
        self.number_of_scope_entries = Dword(address + 4)
        self.address_of_scope_entries = address + 8
        self.scope_entries = []
        # Some handlers have huge values such as 0xffffffe9 and are not
        # supported.
        if self.number_of_scope_entries > 0xff000000:
            return
        for i in range(0, self.number_of_scope_entries):
            self.scope_entries.append(
                ScopeEntry(self.address_of_scope_entries + i * 16))

    def apply_to_database(self):
        _make_references(self.address, self.exp_handler, 'Handler ')
        MakeDword(self.address + 4)
        # Since nested SEH blocks show up first in the table, this reversing
        # makes comments prettier like this:
        # __try{ // outside SEH
        # __try{ // nested SEH
        # } // nested SEH
        # } // outside SEH
        for entry in reversed(self.scope_entries):
            entry.apply_to_database()


class ScopeEntry(object):
    '''Represents an entry of SCOPE_TABLE'''
    def __init__(self, address):
        if Dword(address + 8) == 1:
            # Filter may have 1 in it. This is invalid and this code handle it
            # as __try/__except but without a valid except filter information.
            self.entry = TryInvalidExceptEntry(address)
        elif Dword(address + 12) == 0:
            # It is __try/__finally when Target has no value.
            self.entry = TryFinallyEntry(address)
        else:
            # It is __try/__except when Filter and Target have valid values.
            self.entry = TryExceptEntry(address)

    def apply_to_database(self):
        self.entry.apply_to_database()


class SEHEntry(object):
    '''Implements common things for an SEH SCOPE_TABLE'''
    def __init__(self, address):
        self.address = address
        self.begin = Dword(address) + idaapi.get_imagebase()
        self.end = Dword(address + 4) + idaapi.get_imagebase()

    def apply_to_database(self):
        _make_references(self.address, self.begin, '__try { ')
        _make_references(self.address + 4, self.end, '} //try ')


class TryExceptEntryBase(SEHEntry):
    '''Implements common things for a __try/__except style SCOPE_TABLE'''
    def __init__(self, address):
        super(TryExceptEntryBase, self).__init__(address)

    def apply_to_database(self, target, handler=None):
        super(TryExceptEntryBase, self).apply_to_database()
        if handler:
            except_str = '{:08X}'.format(handler & ~1)
        else:
            except_str = 'INVALID'
        _append_comment(
            self.begin,
            '__try {{ till {:08X} }} __except( {:s} ) {{ {:08X} }}'.format(
                self.end & ~1,
                except_str,
                target & ~1))
        _append_comment(
            self.end,
            '}} // from {:08X}'.format(
                self.begin & ~1))
        _append_comment(
            target,
            '__try {{ from {:08X} }} __except( {:s} ) {{ here }}'.format(
                self.begin & ~1,
                except_str))


class TryExceptEntry(TryExceptEntryBase):
    '''Represents a __try/__except style SCOPE_TABLE'''
    def __init__(self, address):
        super(TryExceptEntry, self).__init__(address)
        self.handler = Dword(address + 8) + idaapi.get_imagebase()
        self.target = Dword(address + 12) + idaapi.get_imagebase()

    def apply_to_database(self):
        super(TryExceptEntry, self).apply_to_database(
            self.target, self.handler)
        _make_references(self.address + 8, self.handler, 'Filter  ')
        _make_references(self.address + 12, self.target, 'ExpBody ')
        _append_comment(
            self.handler,
            '__try {{ {:08X} }} __except(here) {{ {:08X} }}'.format(
                self.begin & ~1,
                self.target & ~1))


class TryInvalidExceptEntry(TryExceptEntryBase):
    '''Represents a __try/__except style SCOPE_TABLE w/ invalid filter'''
    def __init__(self, address):
        super(TryInvalidExceptEntry, self).__init__(address)
        self.target = Dword(address + 12) + idaapi.get_imagebase()

    def apply_to_database(self):
        super(TryInvalidExceptEntry, self).apply_to_database(self.target)
        MakeDword(self.address + 8)
        _make_references(self.address + 12, self.target, 'ExpBody ')


class TryFinallyEntry(SEHEntry):
    '''Represents a __try/__finally style SCOPE_TABLE'''
    def __init__(self, address):
        super(TryFinallyEntry, self).__init__(address)
        self.handler = Dword(address + 8) + idaapi.get_imagebase()

    def apply_to_database(self):
        super(TryFinallyEntry, self).apply_to_database()
        _make_references(self.address + 8, self.handler, 'Finally ')
        MakeDword(self.address + 12)
        _append_comment(
            self.begin,
            '__try {{ till {:08X} }} __finally {{ {:08X} }}'.format(
                self.end & ~1,
                self.handler & ~1))
        _append_comment(
            self.end,
            '}} // from {:08X}'.format(
                self.begin & ~1))
        _append_comment(
            self.handler,
            '__try {{ {:08X} }} __finally {{ here }}'.format(
                self.begin & ~1))


def _append_comment(address, comment):
    old_comment = Comment(address & ~1)
    if old_comment == comment:     # ignore duplicates
        return
    elif old_comment:
        old_comment += '\n'
    else:
        old_comment = ''
    MakeComm(address & ~1, old_comment + comment)


def _make_references(from_address, to_address, comment):
    MakeDword(from_address)
    add_dref(from_address, to_address, XREF_USER | dr_O)
    name = Name(to_address & ~1)
    if name == '':
        name = '{:08X}'.format(to_address)
    _append_comment(from_address, comment + ': ' + name)


def main():
    # Enumerates .pdata section until
    segments = idaapi.get_segm_by_name('.pdata')
    address = segments.startEA
    segment_end = segments.endEA
    while address < segment_end:
        if Dword(address) == 0:
            break
        # try to get exception info from RUNTIME_FUNCTION and apply it
        runtime_function = RuntimeFuncton(address)
        xdata = runtime_function.get_xdata()
        if xdata:
            exception_info = xdata.get_exp_handler_info()
            if exception_info:
                exception_info.apply_to_database()
        address += 8        # size of RUNTIME_FUNCTION


if __name__ == '__main__':
    main()
