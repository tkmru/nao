from unicorn import *
from unicorn.x86_const import *
from functools import wraps
import copy
import sys
import time
import Queue


def check_deadcode(instruction_list):
    sys.setrecursionlimit(1000)
    begin_address = instruction_list[0][0]
    all_opcodes = make_opcodes(instruction_list)

    try:
        start_time = time.time()

        mu = Uc(UC_ARCH_X86, UC_MODE_32)
        page_address = begin_address - begin_address % 0x1000
        mu.mem_map(page_address, 0x800000)  # map 8MB for this emulation
        origin_registers = emulate(mu, begin_address, all_opcodes, 10000)
        # del mu
        #mu = Uc(UC_ARCH_X86, UC_MODE_32)
        #page_address = begin_address - begin_address % 0x1000
        #mu.mem_map(page_address, 0x800000)  # map 8MB for this emulation
        origin_registers = emulate(mu, begin_address, all_opcodes, 10000)

        elapsed_time_sec = time.time() - start_time
        elapsed_time_microsec = int(1000 * 1000 * elapsed_time_sec)
        return instruction_list # judge(mu, instruction_list, origin_registers, elapsed_time_microsec)

    except UcError as e:
        return instruction_list


def make_opcodes(instruction_list):
    all_opcodes = ''
    for i in instruction_list:
        opcode = i[1]
        disasm = i[2]
        if ('call' != disasm[:4]) and ('leave' != disasm[:5]) and ('ret' != disasm[:3]) and \
           ('cmp' != disasm[:3]) and ('[' not in disasm) and (']' not in disasm):
            all_opcodes += opcode
        else:
            all_opcodes += b'\x90' * len(opcode)

    return all_opcodes


def judge(mu, instruction_list, origin_registers, limit_time_microsec):
    length = len(instruction_list)
    begin_address = instruction_list[0][0]
    for i in xrange(length):
        opcode = instruction_list[i][1]
        disasm = instruction_list[i][2]

        # ls enable to emulate?, not already found ?
        if ('call' != disasm[:4]) and ('leave' != disasm[:5]) and ('ret' != disasm[:3]) and \
           ('cmp' != disasm[:3]) and (opcode[0] != b'\x90') and ('[' not in disasm) and (']' not in disasm):
            replaced_instruction_list = copy.deepcopy(instruction_list)
            target_opcode_length = len(opcode)
            replaced_instruction_list[i][1] = b'\x90' * target_opcode_length  # replace to NOP
            replaced_opcodes = make_opcodes(replaced_instruction_list)
            try:
                registers = emulate(mu, begin_address, replaced_opcodes)#, 10000) # limit_time_microsec)
                #if origin_registers == registers:
                #    return judge(mu, replaced_instruction_list, origin_registers, limit_time_microsec)

            except UcError as e:
                print e

    return instruction_list


def emulate(mu, begin_address, opcodes, timeout_microsec=0):
    mu.mem_write(begin_address, opcodes)

    # initialize stack
    mu.reg_write(UC_X86_REG_ESP, begin_address + 0x400000)
    mu.reg_write(UC_X86_REG_EBP, begin_address + 0x400100)

    # initialize registers
    mu.reg_write(UC_X86_REG_EAX, 0x1234)
    mu.reg_write(UC_X86_REG_EBX, 0x1234)
    mu.reg_write(UC_X86_REG_ECX, 0x1234)
    mu.reg_write(UC_X86_REG_EDX, 0x1234)
    mu.reg_write(UC_X86_REG_EDI, 0x1234)
    mu.reg_write(UC_X86_REG_ESI, 0x1234)

    # initialize flags
    mu.reg_write(UC_X86_REG_EFLAGS, 0x0)

    mu.emu_start(begin_address, begin_address + len(opcodes), timeout_microsec)

    r_eax = mu.reg_read(UC_X86_REG_EAX)
    r_ebx = mu.reg_read(UC_X86_REG_EBX)
    r_ecx = mu.reg_read(UC_X86_REG_ECX)
    r_edx = mu.reg_read(UC_X86_REG_EDX)
    r_edi = mu.reg_read(UC_X86_REG_EDI)
    r_esi = mu.reg_read(UC_X86_REG_ESI)
    r_esp = mu.reg_read(UC_X86_REG_ESP)
    r_ebp = mu.reg_read(UC_X86_REG_EBP)

    return r_eax, r_ebx, r_ecx, r_edx, r_edi, r_esi, r_esp, r_ebp


def thread_emulate(begin_address, opcodes, queue):
    register = emulate(begin_address, opcodes)
    queue.put(register)
