from capstone import Cs, CS_ARCH_X86, CS_MODE_64
from unicorn import *
from unicorn.x86_const import *

mu = Uc(UC_ARCH_X86, UC_MODE_64)
cs = Cs(CS_ARCH_X86, CS_MODE_64)
stackaddr = 0x3000000
stack_size = 0x4000
mu.mem_map(stackaddr, stack_size)
mu.reg_write(UC_X86_REG_RSP, stackaddr + stack_size - 8 - 0x200)
mu.reg_write(UC_X86_REG_EBP, stackaddr + stack_size - 8)


global r8_vals
r8_vals = []
global imm_vals
imm_vals = []
def hook_code(mu, address, size, user_data):
    global imm_vals
    global r8_vals
    mem = mu.mem_read(address, size)
    d = next(cs.disasm(mem, address))

    
    if d.mnemonic == "cmp":
        if "r8" in d.op_str:
            temp = d.op_str[3:]
            temp = temp.strip()
            if "0x" in temp:
                temp = temp[2:]
            imm_vals.append(int(temp,16))

    if d.mnemonic == "xor":
        if "r8" in d.op_str and "r8, r8" not in d.op_str and "r8 + rdx" not in d.op_str :
            temp = d.op_str[3:]
            temp = temp.strip()
            if "0x" in temp:
                temp = temp[2:]

            r8_vals.append(int(temp,16))
    if d.mnemonic == "jmp" and "r10" in d.op_str:
        next_address = mu.reg_read(UC_X86_REG_RIP) + size
        mu.reg_write(UC_X86_REG_RIP, next_address)
        
text_addr = 0x7FF7576A1000
oep = 0x7FF7576A1000 
endaddr = 0x7FF7576A9000

with open('bin', 'rb') as f:
    code = f.read()

mu.mem_map(text_addr,0x1000000)
mu.mem_write(text_addr,code)

mu.mem_write(0x3000000, b'\0' * 0x100)

mu.reg_write(UC_X86_REG_RIP,oep)
mu.reg_write(UC_X86_REG_RCX, 0x0)
mu.reg_write(UC_X86_REG_R12, stackaddr)
mu.hook_add(UC_HOOK_CODE, hook_code)

try:
    mu.emu_start(oep,endaddr)
except UcError as e:
    print("Error: %s" % e)
    print("at : %s" % hex(mu.reg_read(UC_X86_REG_RIP)))
    result = [chr(a ^ b) for a, b in zip(r8_vals, imm_vals)]

    flag = ''.join(map(str, result))
    print(flag)
