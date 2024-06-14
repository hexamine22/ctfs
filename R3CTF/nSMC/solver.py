from Crypto.Cipher import Blowfish
from Crypto.Cipher import AES
from Crypto.Cipher import DES
import idaapi, idc, idautils


def rc4(key: bytes, data: bytes) -> bytes:
    x = 0
    box = list(range(256))
    for i in range(256):
        x = (x + box[i] + key[i % len(key)]) % 256
        box[i], box[x] = box[x], box[i]
    x = 0
    y = 0
    out = bytearray()
    for char in data:
        x = (x + 1) % 256
        y = (y + box[x]) % 256
        box[x], box[y] = box[y], box[x]
        out.append(char ^ box[(box[x] + box[y]) % 256])
    return bytes(out)

def xor(data, key):
    result = bytearray() 
    for i in range(1024):
        result.append((data[i] ^ key[i % 16]))
    return bytes(result) 

def undefine_all(start_ea, end_ea):
    for ea in range(start_ea, end_ea, 1):
        idaapi.del_items(ea, idaapi.DELIT_SIMPLE, 1)
        
def get_func_names(func_addr):
    function = ida_funcs.get_func(func_addr)
    func_end = idc.prev_head(function.end_ea)
    cur_ptr = func_addr
    func_names = []
    while(cur_ptr != func_end):
        cur_ptr = idc.next_head(cur_ptr)
        if idc.print_insn_mnem(cur_ptr) == "call":
            func_names.append(idc.get_func_name(idc.get_operand_value(cur_ptr, 0)))
    return func_names
    
        
def analyze(func_addr):
    function = ida_funcs.get_func(func_addr)
    func_end = idc.prev_head(function.end_ea)
    cur_ptr = func_addr
    call_args = []
    addresses_to_be_analyzed = []
    while(cur_ptr != func_end):
        if idc.print_insn_mnem(cur_ptr) == "call":
            #check for strncmp call
            if idc.get_func_name(idc.get_operand_value(cur_ptr, 0)) == ".strncmp":
                #extract the call addr and the arguments
                args = []
                cur_ptr = idc.next_head(cur_ptr)
                while(idc.print_insn_mnem(cur_ptr) != "call"):
                    cur_ptr = idc.next_head(cur_ptr)
                    if idc.print_insn_mnem(cur_ptr) == "lea":
                        arg = idc.get_operand_value(cur_ptr, 1)
                        args.append(arg)
                call_addr = idc.get_operand_value(cur_ptr,0)
                args.append(call_addr)
                call_args.append(args)
        cur_ptr = idc.next_head(cur_ptr)
    for args in call_args:
        if len(args) != 4:
            print("error")
            input()
        addr = args[3]
        func_names = get_func_names(addr)
        enc = ida_bytes.get_bytes(args[2],1024)
        if b"\x55\x48\x89\xE5\x48\x83\xEC" == enc[:7]:
            #already decrypted
            continue
        dec = None
        if ".EVP_aes_128_cbc" in func_names:
            iv = ida_bytes.get_bytes(args[0],16)
            key = ida_bytes.get_bytes(args[1],16)
            cipher = AES.new(key, AES.MODE_CBC, iv=iv)
            dec = cipher.decrypt(enc)
        elif ".EVP_aes_192_cbc" in func_names:
            iv = ida_bytes.get_bytes(args[0],16)
            key = ida_bytes.get_bytes(args[1],24)
            cipher = AES.new(key, AES.MODE_CBC, iv=iv)
            dec = cipher.decrypt(enc)
        elif ".EVP_aes_256_cbc" in func_names:
            iv = ida_bytes.get_bytes(args[0],16)
            key = ida_bytes.get_bytes(args[1],32)
            cipher= AES.new(key, AES.MODE_CBC, iv=iv)
            dec = cipher.decrypt(enc)
        elif ".EVP_des_cbc" in func_names:
            iv = ida_bytes.get_bytes(args[0],8)
            key = ida_bytes.get_bytes(args[1],8)
            cipher = DES.new(key, DES.MODE_CBC, iv=iv)
            dec = cipher.decrypt(enc)
        elif ".EVP_bf_cbc" in func_names:
            iv = ida_bytes.get_bytes(args[0],8)
            key = ida_bytes.get_bytes(args[1],16)
            cipher = Blowfish.new(key, Blowfish.MODE_CBC, iv=iv)
            dec = cipher.decrypt(enc)
        elif b"\x55\x48\x89\xE5\x48\x81\xEC\xC8\x04\x00\x00\x48\x89\xBD\xD8\xFA\xFF\xFF\x48\x89\xB5\xD0\xFA\xFF\xFF\x48\x89\x95\xC8\xFA\xFF\xFF" == ida_bytes.get_bytes(addr,32):
            key = ida_bytes.get_bytes(args[1],16)
            dec = rc4(key,enc)
        elif b"\x55\x48\x89\xE5\x48\x89\x7D\xE8\x48\x89\x75\xE0\x48\x89\x55\xD8\xC7\x45\xFC\x00\x00\x00\x00" == ida_bytes.get_bytes(addr,23):
            key = ida_bytes.get_bytes(args[1],16)
            dec = xor(enc,key)
        if dec != None:
            addresses_to_be_analyzed.append(args[2])
            idaapi.patch_bytes(args[2],dec)
            undefine_all(args[2], args[2]+0x400)
            ida_funcs.add_func(args[2])
            dec = None
            bf = False
        else:
            print(f"error at 0x{addr:X}")
    if addresses_to_be_analyzed != None:
        for addr in addresses_to_be_analyzed:
            print(hex(addr))
            analyze(addr)    