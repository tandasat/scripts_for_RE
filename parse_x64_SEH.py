#!/usr/bin/python
#
# Locates SEH try blocks, exception filters and handlers for x64 Windows files.
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
        self.unwind_info = Dword(address + 8)
        MakeStructEx(address, -1, 'RUNTIME_FUNCTION')

    def get_unwind_info(self):
        name = Name(self.begin_address)
        return UnwindInfo(name, self.unwind_info + idaapi.get_imagebase())


class UnwindInfo(object):
    '''Represents UNWIND_INFO'''
    _UNW_FLAG_NHANDLER = 0
    _UNW_FLAG_EHANDLER = 1
    _UNW_FLAG_UHANDLER = 2
    _UNW_FLAG_CHAININFO = 4

    def __init__(self, name, address):
        self.begin_address = address
        if name == '':
            name = '_loc_{:016X}'.format(address)
        name += '_unwind_info'
        if MakeNameEx(address, name, SN_CHECK | SN_NOWARN) == 0:
            MakeNameEx(address, '_' + name, SN_CHECK | SN_NOWARN)
        MakeStructEx(address, -1, 'UNWIND_INFO')

    def _has_exception_handler(self):
        flag = Byte(self.begin_address) >> 3
        if flag & self._UNW_FLAG_CHAININFO:
            return False
        return (
            flag & self._UNW_FLAG_EHANDLER or
            flag & self._UNW_FLAG_UHANDLER
        )

    def get_exp_handler_info(self):
        code_count = Byte(self.begin_address + 2)
        for i in range(0, code_count):
            MakeStructEx(self.begin_address + 4 + (i * 2), -1, 'UNWIND_CODE')
        if not self._has_exception_handler():
            return
        print('%016X : %s' % (self.begin_address, Name(self.begin_address)))
        addr = self.begin_address + 4 + code_count * 2
        addr += (addr % 4)      # 4 bytes aligned (0->0, 2->4, 4->4, ...)
        return ExceptionHandlerInformation(addr)    # get Exception Info


class ExceptionHandlerInformation(object):
    '''Represents Exception Handler Information (a.k.a, SCOPE_TABLE)'''
    def __init__(self, address):
        self.address = address
        self.exp_handler = Dword(address) + idaapi.get_imagebase()
        self.number_of_scope_entries = Dword(address + 4)
        self.address_of_scope_entries = address + 8
        self.scope_entries = []
        # Only some handlers' date formats are supported.
        if not self._is_suppoeted_handler(Name(self.exp_handler)):
            return
        for i in range(0, self.number_of_scope_entries):
            self.scope_entries.append(
                ScopeEntry(self.address_of_scope_entries + i * 16))

    def _is_suppoeted_handler(self, handler_name):
        SUPPORTED_HANDLER_NAMES = [
            '__GSHandlerCheck_SEH',
            '__C_specific_handler',
        ]
        for name in SUPPORTED_HANDLER_NAMES:
            if handler_name.startswith(name):
                return True
        return False

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

    def apply_to_database(self, target, handler):
        super(TryExceptEntryBase, self).apply_to_database()
        _append_comment(
            self.begin,
            '__try {{ // till {:016X} }} __except( {:016X} ) {{ {:016X} }}'.format(
                self.end,
                handler,
                target))
        _append_comment(
            self.end,
            '}} // from {:016X}'.format(
                self.begin))
        _append_comment(
            target,
            '__except( {:016X} ) {{ here }} // __try {{ {:016X}-{:016X} }}'.format(
                handler,
                self.begin,
                self.end))


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
            '__except( here ) {{ {:016X} }} // __try {{ {:016X}-{:016X} }}'.format(
                self.target,
                self.begin,
                self.end))


class TryInvalidExceptEntry(TryExceptEntryBase):
    '''Represents a __try/__except style SCOPE_TABLE w/ invalid filter'''
    def __init__(self, address):
        super(TryInvalidExceptEntry, self).__init__(address)
        self.target = Dword(address + 12) + idaapi.get_imagebase()

    def apply_to_database(self):
        pass    # An invalid handler will never be called


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
            '__try {{ // till {:016X} }} __finally {{ {:016X} }}'.format(
                self.end,
                self.handler))
        _append_comment(
            self.end,
            '}} // from {:016X}'.format(
                self.begin))
        _append_comment(
            self.handler,
            '__finally {{ here }} // __try {{ {:016X}-{:016X} }}'.format(
                self.begin,
                self.end))


def _append_comment(address, comment):
    old_comment = Comment(address)
    if old_comment == comment:     # ignore duplicates
        return
    elif old_comment:
        old_comment += '\n'
    else:
        old_comment = ''
    MakeComm(address, old_comment + comment)


def _make_references(from_address, to_address, comment):
    MakeDword(from_address)
    add_dref(from_address, to_address, XREF_USER | dr_O)
    name = Name(to_address)
    if name == '':
        name = '{:016X}'.format(to_address)
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
        unwind_info = runtime_function.get_unwind_info()
        if unwind_info:
            exception_info = unwind_info.get_exp_handler_info()
            if exception_info:
                exception_info.apply_to_database()
        address += 12        # size of RUNTIME_FUNCTION


if __name__ == '__main__':
    main()
