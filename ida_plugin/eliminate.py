from unicorn import *
from unicorn.x86_const import *


def check_deadcode(instruction_list):
    begin_address = instruction_list[0][0]
    all_opcodes = ''

    for i in instruction_list[0:-4]:
        if ('offset' not in i[2]) and ('call' not in i[2]) and ('ret' not in i[2]):
            all_opcodes += i[1]

    origin_regs = emulate(begin_address, all_opcodes)

    return instruction_list

def emulate(begin_address, opcodes):
    mu = Uc(UC_ARCH_X86, UC_MODE_32)
    page_address = begin_address - begin_address % 0x1000
    mu.mem_map(page_address, 4 * 1024 * 1024) # map 4MB for this emulation
    mu.mem_write(begin_address, opcodes)

    # initialize stack
    mu.reg_write(UC_X86_REG_ESP, ADDRESS + 0x200000)
    # initialize flags
    mu.reg_write(UC_X86_REG_EFLAGS, 0x0)

    mu.emu_start(begin_address, begin_address + len(opcodes))

    r_eax = mu.reg_read(UC_X86_REG_EAX)
    r_ebx = mu.reg_read(UC_X86_REG_EBX)
    r_ecx = mu.reg_read(UC_X86_REG_ECX)
    r_edx = mu.reg_read(UC_X86_REG_EDX)
    r_edi = mu.reg_read(UC_X86_REG_EDI)
    r_esi = mu.reg_read(UC_X86_REG_ESI)
    r_esp = mu.reg_read(UC_X86_REG_ESP)
    r_ebp = mu.reg_read(UC_X86_REG_EBP)
    r_eflags = mu.reg_read(UC_X86_REG_EFLAGS)

    return r_eax, r_ebx, r_ecx, r_edx, r_edi, r_esi, r_esp, r_ebp, r_eflags
