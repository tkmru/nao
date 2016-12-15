import idaapi
import idautils
import idc
import os
import binascii
import eliminate


class asm_colorizer_t(object):
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
            if ch == '\\' and line[i+1] == quote:
                i += 1
            elif ch == quote:
                i += 1 # also take the quote
                break
            i += 1
        return (i, line[x:i])

    def colorize(self, lines):
        slines = lines.split("\n")
        for line in slines:
            line = line.rstrip()
            if not line:
                self.add_line()
                continue
            x = 0
            e = len(line)
            s = ""
            while x < e:
                ch = line[x]
                # String?
                if ch == '"' or ch == "'":
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


class asmview_t(idaapi.simplecustviewer_t, asm_colorizer_t):
    def Create(self):
        # Create the customview
        ea = ScreenEA()
        # Create the customview
        if not idaapi.simplecustviewer_t.Create(self, "%s - dead code eliminate" % (idc.GetFunctionName(ScreenEA()))):
            return False
        self.instruction_list = idautils.GetInstructionList()
        self.instruction_list.extend(["ret"])
        self.register_list    = idautils.GetRegisterList()
        self.register_list.extend(["eax", "ebx", "ecx", "edx", "edi", "esi", "ebp", "esp"])

        f = idaapi.get_func(ScreenEA())
        self.fc = idaapi.FlowChart(f)
        self.block_list = []
        for block in self.fc:
            self.block_list.append(format(block.startEA,'x').upper())

        self.reload_file(ea)

        self.id_jmp = self.AddPopupMenu("Jump")

        return True


    def jump(self):
        str_addr = self.GetCurrentWord(0).lstrip('loc_')
        for i in xrange(self.Count()):
            search_addr = self.GetLine(i)[0].rsplit(":")[0].replace("\x01\x0c","").replace("\x02\x0c","")
            if str_addr == search_addr:
                self.Jump(i,0,0)

    def reload_file(self, ea):
        if not self.colorize_file(ea):
            self.Close()
            return False
        return True

    def colorize_file(self, ea):
        instruction_list = []
        address_list = list(FuncItems(ea))
        lines = ""
        for i, row_begin_addr in enumerate(address_list):
            disasm = GetDisasm(row_begin_addr)
            lines += disasm + "\n"
            try:
                size = address_list[i+1] - row_begin_addr

            except IndexError:
                last_row_begin_addr = row_begin_addr
                last_row_end_addr = FindFuncEnd(last_row_begin_addr)
                size = last_row_end_addr - last_row_begin_addr

            row_opcode = ''
            for i in range(size):
                int_opcode = GetOriginalByte(row_begin_addr + i)
                opcode = binascii.a2b_hex(hex(int_opcode)[2:].zfill(2))
                row_opcode += opcode

            instruction_list.append([row_begin_addr, row_opcode, disasm])

        checked_instruction_list = eliminate.check_deadcode(instruction_list)
        lines = ''
        for i in checked_instruction_list:
            if b'\x90' != i[1][0]: # eliminate deadcode
                lines += str(format(i[0], 'x')).upper() + ":    " + i[2] + '\n'

        self.ClearLines()
        self.colorize(lines)

        return True

    def add_line(self, s=None):
        if not s:
            s = ""

        target = s.rsplit(":")[0].replace("\x01\x0c","").replace("\x02\x0c","")
        if target in self.block_list:
            self.AddLine("----------------------------------------------------------------")
            if idc.Name(int(target, 16))!= '':
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

    def OnPopupMenu(self, menu_id):
        """
        A context (or popup) menu item was executed.
        @param menu_id: ID previously registered with AddPopupMenu()
        @return: Boolean
        """
        if self.id_jmp == menu_id:
            return self.jump()
        return False

    def OnKeydown(self, vkey, shift):
        """
        User pressed a key
        @param vkey: Virtual key code
        @param shift: Shift flag
        @return Boolean. True if you handled the event

        # ESCAPE
        if vkey == 27:
            self.Close()
        elif vkey == ord('H'):
            lineno = self.GetLineNo()
            if lineno is not None:
                line, fg, bg = self.GetLine(lineno)
                if line and line[0] != idaapi.SCOLOR_INV:
                    s = idaapi.SCOLOR_INV + line + idaapi.SCOLOR_INV
                    self.EditLine(lineno, s, fg, bg)
                    self.Refresh()
        elif vkey == ord('C'):
            self.ClearLines()
            self.Refresh()
        elif vkey == ord('S'):
            print "Selection (x1, y1, x2, y2) = ", self.GetSelection()
        elif vkey == ord('I'):
            print "Position (line, x, y) = ", self.GetPos(mouse = 0)
        else:
            return False
        """
        return True


def main():
    def cb():
        view = asmview_t()
        #if not view.Create():
        #    return
        view.Create()
        view.Show()

    #cb()    #if you want create deadcode_eliminate view, call cb() in main()
    ex_addmenu_item_ctx = idaapi.add_menu_item("Edit/", "dead code eliminate", "Shift-D", 0, cb, ())
    if ex_addmenu_item_ctx is None:
        print("Failed to add menu!")
        #del ex_addmenu_item_ctx
    else:
        print("Menu added successfully.")
        return True

    return view

view = main()
