import struct
with open("vmcode.bin","rb") as f:
    vmcode = f.read()

def u16(data):
    return struct.unpack('<H', data)[0]

ops = {
    0x01: "mov_imm_reg",  
    0x02: "mov_reg_reg",   
    0x10: "mov_mem_reg",   
    0x11: "mov_reg_mem",   
    0x20: "add",           
    0x21: "sub",         
    0x22: "mul",          
    0x23: "test",        
    0x40: "input",        
    0x50: "jmp",          
    0x51: "je",          
    0x52: "jne",          
    0x60: "flag_ok",       
    0x61: "flag_fail",     
    0xFF: "halt",         
}

def disasm(vmcode,ip):
    opcode = vmcode[ip]
    insn = ops[opcode]
    new_ip = ip+1
    if insn == "add" or insn == "sub" or insn == "mul":
        dest = vmcode[ip+1]
        s1 = vmcode[ip+2]
        s2 = vmcode[ip+3]
        print(f"{insn} reg{dest}, reg{s1} reg{s2}")
        new_ip += 3
    elif insn == "test":
        s1 = vmcode[ip+1]
        print(f"{insn} reg{s1} reg{s1}")
        new_ip += 1
    elif insn == "jmp" or insn == "je" or insn == "jne":
        target = u16(vmcode[ip+1:ip+3])
        print(f"{insn} {target}")
        new_ip += 2
    elif insn == "flag_fail" or insn == "flag_ok" or insn == "halt":
        print(f"{insn}")
    elif insn == "input":
        s1 = u16(vmcode[ip+1:ip+3])
        print(f"fgets(mem[{s1}])")
        new_ip += 2
    elif insn == "mov_imm_reg":
        s1 = vmcode[ip+1]
        assert s1 < 16
        imm = u16(vmcode[ip+2:ip+4])
        print(f"mov reg{s1}, {imm}")
        new_ip += 3
    elif insn == "mov_reg_reg":
        s1 = vmcode[ip+1]
        s2 = vmcode[ip+2]
        assert s1 < 16
        assert s2 < 16
        print(f"mov reg{s1} reg{s2}")
        new_ip += 2
    elif insn == "mov_mem_reg":
        s1 = vmcode[ip+1]
        assert s1 < 16
        s2 = u16(vmcode[ip+2:ip+4])
        print(f"mov reg{s1} mem[{s2}]")
        new_ip += 3
    elif insn == "mov_reg_mem":
        s1 = u16(vmcode[ip+1:ip+3])
        s2 = vmcode[ip+3]
        print(f"mov mem[{s1}] reg{s2}")
        new_ip += 3
    return new_ip
        
ip = 0
while True:     
    ip = disasm(vmcode,ip)