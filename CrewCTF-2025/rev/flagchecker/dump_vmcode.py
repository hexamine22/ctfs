from libdebug import *
from pwn import *
d = debugger("./flagchecker",aslr=False)
d.run()
dec_end = d.breakpoint(0x5555555584A5)
vm_bytes = []
d.cont()

while True:
    if d.regs.rip == dec_end.address: 
        vm_bytes.append(d.regs.al)
        d.regs.rip = 0x555555556020
    if len(vm_bytes) == 0xABE0:
        break
    d.cont()
with open("vmcode.bin","wb") as f:
    f.write(bytes(vm_bytes))