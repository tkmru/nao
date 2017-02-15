#!/usr/bin/env python2.7
# coding: UTF-8

from unicorn import *
from unicorn.x86_const import *
import copy

def check_deadcode(instruction_list):
    begin_address = instruction_list[0][0]
    all_opcodes = make_opcodes(instruction_list)

    # ready to unicorn
    emu = Uc(UC_ARCH_X86, UC_MODE_32)
    page_address = begin_address - begin_address % 0x1000
    emu.mem_map(page_address, 0x400000)  # map 4MB for this emulation

    try:
        origin_registers = emulate(emu, begin_address, all_opcodes)
        judged_instruction_list = judge(emu, instruction_list, origin_registers)
        return judged_instruction_list

    except UcError:
        return instruction_list



def check_exceptional_ins(disasm):
    exceptional_instruction_list = ["call", "leave", "ret", "offset", "cmp", "jnz", "jz",
                     "jne", "je", "test"]
    
    for ins in exceptional_instruction_list:
        if ins in disasm:
            return True
    return False

def make_opcodes(instruction_list):
    all_opcodes = ''
    for i in instruction_list:
        opcode = i[1]
        disasm = i[2]
        
        if check_exceptional_ins(disasm) == False:    
            all_opcodes += opcode
        
        else:
            all_opcodes += b'\x90' * len(opcode)

    return all_opcodes


def judge(emu, instruction_list, origin_registers):
    length = len(instruction_list)
    begin_address = instruction_list[0][0]
    for i in xrange(length):
        disasm = instruction_list[i][2]
        opcode = instruction_list[i][1]

        # ls enable to emulate?, not already found ?
        if (check_exceptional_ins(disasm) == False) and (opcode[0] != b'\x90'):
            replaced_instruction_list = copy.deepcopy(instruction_list)
            target_opcode_length = len(opcode)
            replaced_instruction_list[i][1] = b'\x90' * target_opcode_length  # replace to NOP
            replaced_opcodes = make_opcodes(replaced_instruction_list)
            try:
                registers = emulate(emu, begin_address, replaced_opcodes)
                if origin_registers == registers:
                    return judge(emu, replaced_instruction_list, origin_registers)

            except UcError:
                del emu
                emu = Uc(UC_ARCH_X86, UC_MODE_32)
                page_address = begin_address - begin_address % 0x1000
                emu.mem_map(page_address, 0x400000)  # map 4MB for this emulation

    del emu
    return instruction_list


def emulate(emu, begin_address, opcodes):
    emu.mem_write(begin_address, opcodes)

    # initialize stack
    emu.reg_write(UC_X86_REG_ESP, begin_address + 0x200000)
    emu.reg_write(UC_X86_REG_EBP, begin_address + 0x200100)

    # initialize registers
    emu.reg_write(UC_X86_REG_EAX, 0x1234)
    emu.reg_write(UC_X86_REG_EBX, 0x1234)
    emu.reg_write(UC_X86_REG_ECX, 0x1234)
    emu.reg_write(UC_X86_REG_EDX, 0x1234)
    emu.reg_write(UC_X86_REG_EDI, 0x1234)
    emu.reg_write(UC_X86_REG_ESI, 0x1234)

    # initialize flags
    emu.reg_write(UC_X86_REG_EFLAGS, 0x0)

    emu.emu_start(begin_address, begin_address + len(opcodes))

    r_eax = emu.reg_read(UC_X86_REG_EAX)
    r_ebx = emu.reg_read(UC_X86_REG_EBX)
    r_ecx = emu.reg_read(UC_X86_REG_ECX)
    r_edx = emu.reg_read(UC_X86_REG_EDX)
    r_edi = emu.reg_read(UC_X86_REG_EDI)
    r_esi = emu.reg_read(UC_X86_REG_ESI)
    r_esp = emu.reg_read(UC_X86_REG_ESP)
    r_ebp = emu.reg_read(UC_X86_REG_EBP)

    return r_eax, r_ebx, r_ecx, r_edx, r_edi, r_esi, r_esp, r_ebp
