import idc,idautils,ida_bytes
cond_jump_insts={'jo':bytearray(b'\x0f\x80'),'jno':bytearray(b'\x0f\x81'),'js':bytearray(b'\x0f\x88'),'jns':bytearray(b'\x0f\x89'),'je':bytearray(b'\x0f\x84'),'jz':bytearray(b'\x0f\x84'),'jne':bytearray(b'\x0f\x85'),'jnz':bytearray(b'\x0f\x85'),'jb':bytearray(b'\x0f\x82'),'jnae':bytearray(b'\x0f\x82'),'jae':bytearray(b'\x0f\x83'),'jnb':bytearray(b'\x0f\x83'),'jbe':bytearray(b'\x0f\x86'),'jna':bytearray(b'\x0f\x86'),'ja':bytearray(b'\x0f\x87'),'jnbe':bytearray(b'\x0f\x87'),'jl':bytearray(b'\x0f\x8c'),'jnge':bytearray(b'\x0f\x8c'),'jge':bytearray(b'\x0f\x8d'),'jnl':bytearray(b'\x0f\x8d'),'jle':bytearray(b'\x0f\x8e'),'jng':bytearray(b'\x0f\x8e'),'jg':bytearray(b'\x0f\x8f'),'jnle':bytearray(b'\x0f\x8f'),'jp':bytearray(b'\x0f\x8a'),'jpe':bytearray(b'\x0f\x8a'),'jnp':bytearray(b'\x0f\x8b'),'jpo':bytearray(b'\x0f\x8b')}


def assembleJump(target, ea, cond=None):
    if cond:
        size = 6
        inst = cond_jump_insts["j"+cond]
    else:
        size = 5
        inst = b"\xE9"
    offset = (target - (ea + size)).to_bytes(4, 'little', signed=True)
    return inst + offset

for seg in idautils.Segments():
    ea = idc.get_segm_start(seg); end = idc.get_segm_end(seg)
    while ea < end:
        mnem = idc.print_insn_mnem(ea).lower()
        if idc.print_insn_mnem(ea)=="lea" and idc.print_operand(ea,0)=="rcx":
            ea1=ea; tru=idc.get_operand_value(ea1,1)
            ea2=idc.next_head(ea1)
            if idc.print_insn_mnem(ea2)!="lea" or idc.print_operand(ea2,0)!="rax":
                ea=idc.next_head(ea);continue
            fal=idc.get_operand_value(ea2,1)
            ea3=idc.next_head(ea2)
            mnem=idc.print_insn_mnem(ea3).lower()
            if not mnem.startswith("cmov"): ea=idc.next_head(ea);continue
            cond= mnem[4:]
            if "j"+cond not in cond_jump_insts: ea=idc.next_head(ea);continue
            ea4=idc.next_head(ea3)
            if idc.print_insn_mnem(ea4)!="jmp" or idc.print_operand(ea4,0)!="rax":
                ea=idc.next_head(ea);continue
            ea5 = idc.next_head(ea4)
            ida_bytes.patch_bytes(ea1,b"\x90"*(ea5-ea1))
            true_jump = bytes(assembleJump(tru,ea1,cond))
            fal_jump = bytes(assembleJump(fal,len(true_jump) + ea1))
            ida_bytes.patch_bytes(ea1,true_jump+fal_jump)
        elif mnem == "lea" and idc.print_operand(ea,0)=="rax":
            target = idc.get_operand_value(ea,1)
            ea1=ea
            ea2=idc.next_head(ea1)
            if idc.print_insn_mnem(ea2)=="jmp" and idc.print_operand(ea2,0)=="rax":
                ea3=idc.next_head(ea2)
                ida_bytes.patch_bytes(ea1,b"\x90"*(ea3-ea1))
                jmp = assembleJump(target,ea1)
                ida_bytes.patch_bytes(ea1, bytes(jmp))

        ea=idc.next_head(ea)