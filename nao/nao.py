#!/usr/bin/env python2.7
# coding: UTF-8

"""
We referred to the following code
http://www.hexblog.com/?p=119
"""

import idaapi
import idautils
import idc
import struct
import eliminate


class AsmColorizer(object):

    def is_id(self, ch):
        return ch == '_' or ch.isalpha() or '0' <= ch <= '9'

    def get_identifier(self, line, x, e):
        i = x
        is_digit = line[i].isdigit()
        while i < e:
            ch = line[i]
            if not self.is_id(ch):
                if ch != '.' or not is_digit:
                    break
            i += 1
        return (i, line[x:i])

    def get_quoted_string(self, line, x, e):
        quote = line[x]
        i = x + 1
        while i < e:
            ch = line[i]
            if ch == '\\' and line[i + 1] == quote:
                i += 1
            elif ch == quote:
                i += 1  # also take the quote
                break
            i += 1
        return (i, line[x:i])

    def colorize(self, lines):
        slines = lines.split('\n')
        for line in slines:
            line = line.rstrip()
            if not line:
                self.add_line()
                continue
            x = 0
            e = len(line)
            s = ''
            while x < e:
                ch = line[x]
                # String?
                if ch == "'" or ch == '"':
                    x, w = self.get_quoted_string(line, x, e)
                    s += self.as_string(w)
                # Tab?
                elif ch == '\t':
                    s += ' ' * 4
                    x += 1
                # Comment?
                elif ch == ';':
                    s += self.as_comment(line[x:])
                    # Done with this line
                    break
                elif ch == '.' and x + 1 < e:
                    x, w = self.get_identifier(line, x + 1, e)
                    s += self.as_directive(ch + w)
                # Identifiers?
                elif self.is_id(ch):
                    x, w = self.get_identifier(line, x, e)
                    # Number?
                    if ch.isdigit():
                        s += self.as_num(w)
                    # Other identifier
                    else:
                        s += self.as_id(w)
                # Output as is
                else:
                    s += ch
                    x += 1
            self.add_line(s)

class JumpHandler(idaapi.action_handler_t):
    def __init__(self, view):
        idaapi.action_handler_t.__init__(self)
        self.view = view

    def activate(self, ctx):
        self.view.jump()
        return 1

    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS

class PluginUI(idaapi.simplecustviewer_t, AsmColorizer):

    def Create(self):
        ea = ScreenEA()
        if not idaapi.simplecustviewer_t.Create(self, '%s - Nao' % (idc.GetFunctionName(ea))):
            return False
        self.instruction_list = idautils.GetInstructionList()
        self.instruction_list.extend(['ret'])
        self.register_list = idautils.GetRegisterList()
        self.register_list.extend(['r8l', 'r9l', 'r10l', 'r11l', 'r12l', 'r13l', 'r14l', 'r15l',
                                   'r8w', 'r9w', 'r10w', 'r11w', 'r12w', 'r13w', 'r14w', 'r15w',
                                   'r8d', 'r9d', 'r10d', 'r11d', 'r12d', 'r13d', 'r14d', 'r15d',
                                   'eax', 'ebx', 'ecx', 'edx', 'edi', 'esi', 'ebp', 'esp', 
                                   'rax', 'rbx', 'rcx', 'rdx', 'rdi', 'rsi', 'rbp', 'rsp'])

        f = idaapi.get_func(ea)
        self.fc = idaapi.FlowChart(f)
        self.block_list = []
        for block in self.fc:
            self.block_list.append(format(block.startEA, 'x').upper())

        self.load(ea)

        action_desc = idaapi.action_desc_t(
            'nao:jump',     # The action name.
            'Jump',         # The action text.
            JumpHandler(self),  # The action handler.
            '',             # Optional: the action shortcut
            '',             # Optional: the action tooltip (available in menus/toolbar)
            )               # Optional: the action icon (shows when in menus/toolbars) use numbers 1-255
        idaapi.register_action(action_desc)
        idaapi.attach_action_to_popup(self.GetWidget(), None, 'nao:jump', None)
        return True

    def jump(self):
        str_addr = self.GetCurrentWord(0).lstrip('loc_')
        for i in xrange(self.Count()):
            search_addr = self.GetLine(i)[0].rsplit(':')[0].replace('\x01\x0c', '').replace('\x02\x0c', '')
            if str_addr == search_addr:
                self.Jump(i, 0, 0)

    def load(self, ea):
        if not self.eliminate_deadcode(ea):
            self.Close()
            return False
        return True

    def eliminate_deadcode(self, ea):
        instruction_list = []
        address_list = list(FuncItems(ea))
        lines = ''
        for i, row_begin_addr in enumerate(address_list):
            disasm = GetDisasm(row_begin_addr)
            lines += disasm + '\n'
            try:
                next_row_begin_addr = address_list[i + 1]
                size = next_row_begin_addr - row_begin_addr
                if size < 0:  # when row_begin_addr is end basic block
                    row_end_addr = FindFuncEnd(row_begin_addr)
                    size = row_end_addr - row_begin_addr

            except IndexError:  # when next_row_begin_addr is not found
                last_row_begin_addr = row_begin_addr
                last_row_end_addr = FindFuncEnd(last_row_begin_addr)
                size = last_row_end_addr - last_row_begin_addr

            row_opcode = ''
            for i in range(size):
                int_opcode = GetOriginalByte(row_begin_addr + i)
                opcode = struct.pack('B', int_opcode)
                row_opcode += opcode

            instruction_list.append([row_begin_addr, row_opcode, disasm])

        checked_instruction_list = eliminate.check_deadcode(instruction_list)
        lines = ''
        for i in checked_instruction_list:
            address = i[0]
            opcode = i[1]
            disasm = i[2]
            if not opcode.startswith(b'\x90'):  # check dead code
                lines += str(format(address, 'x')).upper() + ':    ' + disasm + '\n'

        self.ClearLines()
        self.colorize(lines)

        return True

    def add_line(self, s=None):
        if not s:
            s = ''

        target = s.rsplit(':')[0].replace('\x01\x0c', '').replace('\x02\x0c', '')
        if target in self.block_list:
            self.AddLine('----------------------------------------------------------------')
            if idc.Name(int(target, 16)) != '':
                self.AddLine(idc.Name(int(target, 16)))
        self.AddLine(s)

    def as_comment(self, s):
        return idaapi.COLSTR(s, idaapi.SCOLOR_RPTCMT)

    def as_id(self, s):
        t = s.lower()
        if t in self.register_list:
            return idaapi.COLSTR(s, idaapi.SCOLOR_REG)
        elif t in self.instruction_list:
            return idaapi.COLSTR(s, idaapi.SCOLOR_INSN)
        else:
            return s

    def as_string(self, s):
        return idaapi.COLSTR(s, idaapi.SCOLOR_STRING)

    def as_num(self, s):
        return idaapi.COLSTR(s, idaapi.SCOLOR_NUMBER)

    def as_directive(self, s):
        return idaapi.COLSTR(s, idaapi.SCOLOR_KEYWORD)


class nao_t(idaapi.plugin_t):

    flags = 0
    comment = "Eliminate dead code"
    help = ''
    wanted_name = 'Nao'
    wanted_hotkey = 'Shift-D'

    def init(self):
        return idaapi.PLUGIN_KEEP

    def term(self):
        return None

    def run(self, arg):
        view = PluginUI()
        view.Create()
        view.Show()
        print('eliminated!!')

def PLUGIN_ENTRY():
    return nao_t()
