import re 
from pwn import *
with open("vault.wasm","rb") as f:
    data = bytearray(f.read())

code = data[0x70:0x158e]

p1 = re.compile(b'\x41.\x10\x00', re.DOTALL)
p2 = re.compile(b'\x41..\x10\x00', re.DOTALL)


def parity(number):
    result = 0
    while number != 0:
        result ^= number & 1
        number >>= 1
    return result

m1 = [m.start() for m in p1.finditer(code)]
m2 = [m.start() for m in p2.finditer(code)]

for f in m1:
    v = code[f+1]
    v = parity(v)
    code[f+1] = v
    code[f+2:f+4] = b"\x01\x01"

for f in m2:
    v = u16(code[f+1:f+3])
    v = parity(v)
    if v == 0:
        v= 1
    else:
        v=0
    
    code[f+1] = v
    code[f+2:f+5] = b"\x01\x01\x01"

data[0x70:0x158e] = code
with open("vault-out.wasm","wb") as f:
    f.write(data)