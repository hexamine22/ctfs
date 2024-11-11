from z3 import *


s = Solver()

regs = [0] * 15

Flag = [BitVec(f"f{i}",8) for i in range(40)]




def rotr(value, shift):
    shift = shift % 32  
    return (value >> shift) | (value << (32 - shift)) & 0xFFFFFFFF

def rotl(value, shift):
    shift = shift % 32  
    return (value << shift) | (value >> (32 - shift)) & 0xFFFFFFFF

max_bits = 32


def insn_t(opcode,op0,op1,Flag,regs):
    if opcode == 0:
        regs[op0] = ZeroExt(24, Flag[op1])
    elif opcode == 1:
        regs[op0] = op1 & 0xFFFFFFFF
    elif opcode == 2:
        regs[op0] ^= op1 & 0xFFFFFFFF
    elif opcode == 3:
        regs[op0] ^= regs[op1] & 0xFFFFFFFF
    elif opcode == 4:
        regs[op0] |= op1 & 0xFFFFFFFF
    elif opcode == 5:
        regs[op0] |= regs[op1] & 0xFFFFFFFF
    elif opcode == 6:
        regs[op0] &= op1 & 0xFFFFFFFF
    elif opcode == 7:
        regs[op0] &= regs[op1] & 0xFFFFFFFF
    elif opcode == 8:
        regs[op0] = (regs[op0] + op1) & 0xFFFFFFFF
    elif opcode == 9:
        regs[op0] = (regs[op0] + regs[op1]) & 0xFFFFFFFF
    elif opcode == 10:
        regs[op0] = (regs[op0] - op1) & 0xFFFFFFFF
    elif opcode == 11:
        regs[op0] = (regs[op0] - regs[op1]) & 0xFFFFFFFF
    elif opcode == 12:
        regs[op0] = (regs[op0] * op1) & 0xFFFFFFFF
    elif opcode == 13:
        regs[op0] = (regs[op0] * regs[op1]) & 0xFFFFFFFF
    elif opcode == 14:
        return
    elif opcode == 15:
        return
    elif opcode == 16:
        regs[op0] = rotr(regs[op0], op1) 
  
    elif opcode == 17:
        regs[op0] = rotr(regs[op0], regs[op1]) 

    elif opcode == 18:
        regs[op0] = rotl(regs[op0], op1) 

    elif opcode == 19:
        regs[op0] = rotl(regs[op0], regs[op1])

    elif opcode == 20:
        regs[op0] = regs[op1] 
    elif opcode == 21:
        regs[op0] = 0 
    elif opcode == 22:
        regs[op0] = (regs[op0] >> op1) & 0xFFFFFFFF
    elif opcode == 23:
        regs[op0] = (regs[op0] >> regs[op1]) & 0xFFFFFFFF
            
    elif opcode == 24:
        regs[op0] = (regs[op0] << op1) & 0xFFFFFFFF
            
    elif opcode == 25:
        regs[op0] = (regs[op0] << regs[op1]) & 0xFFFFFFFF
    return

exec("""insn_t(12, 13, 10,Flag,regs); insn_t(21, 0, 0,Flag,regs); insn_t(0, 13, 13,Flag,regs); insn_t(0, 14, 0,Flag,regs); insn_t(15, 11, 12,Flag,regs); insn_t(24, 14, 0,Flag,regs); insn_t(5, 0, 14,Flag,regs); insn_t(0, 14, 1,Flag,regs); insn_t(7, 11, 11,Flag,regs); insn_t(24, 14, 8,Flag,regs); insn_t(5, 0, 14,Flag,regs); insn_t(0, 14, 2,Flag,regs); insn_t(2, 10, 11,Flag,regs); insn_t(24, 14, 16,Flag,regs); insn_t(18, 12, 11,Flag,regs); insn_t(5, 0, 14,Flag,regs); insn_t(0, 14, 3,Flag,regs); insn_t(0, 11, 11,Flag,regs); insn_t(24, 14, 24,Flag,regs); insn_t(13, 10, 10,Flag,regs); insn_t(5, 0, 14,Flag,regs); insn_t(2, 11, 13,Flag,regs); insn_t(21, 1, 0,Flag,regs); insn_t(0, 14, 4,Flag,regs); insn_t(24, 14, 0,Flag,regs); insn_t(5, 1, 14,Flag,regs); insn_t(6, 11, 12,Flag,regs); insn_t(0, 14, 5,Flag,regs); insn_t(8, 10, 10,Flag,regs); insn_t(24, 14, 8,Flag,regs); insn_t(11, 12, 11,Flag,regs); insn_t(5, 1, 14,Flag,regs); insn_t(0, 14, 6,Flag,regs); insn_t(0, 12, 10,Flag,regs); insn_t(24, 14, 16,Flag,regs); insn_t(9, 10, 13,Flag,regs); insn_t(5, 1, 14,Flag,regs); insn_t(0, 14, 7,Flag,regs); insn_t(13, 12, 12,Flag,regs); insn_t(24, 14, 24,Flag,regs); insn_t(15, 10, 12,Flag,regs); insn_t(5, 1, 14,Flag,regs); insn_t(21, 2, 0,Flag,regs); insn_t(20, 13, 13,Flag,regs); insn_t(0, 14, 8,Flag,regs); insn_t(24, 14, 0,Flag,regs); insn_t(19, 10, 11,Flag,regs); insn_t(5, 2, 14,Flag,regs); insn_t(6, 12, 10,Flag,regs); insn_t(0, 14, 9,Flag,regs); insn_t(8, 11, 11,Flag,regs); insn_t(24, 14, 8,Flag,regs); insn_t(5, 2, 14,Flag,regs); insn_t(0, 14, 10,Flag,regs); insn_t(4, 11, 12,Flag,regs); insn_t(24, 14, 16,Flag,regs); insn_t(5, 2, 14,Flag,regs); insn_t(0, 14, 11,Flag,regs); insn_t(24, 14, 24,Flag,regs); insn_t(4, 13, 12,Flag,regs); insn_t(5, 2, 14,Flag,regs); insn_t(21, 3, 0,Flag,regs); insn_t(14, 10, 12,Flag,regs); insn_t(0, 14, 12,Flag,regs); insn_t(13, 10, 11,Flag,regs); insn_t(24, 14, 0,Flag,regs); insn_t(16, 10, 10,Flag,regs); insn_t(5, 3, 14,Flag,regs); insn_t(5, 11, 12,Flag,regs); insn_t(0, 14, 13,Flag,regs); insn_t(12, 10, 13,Flag,regs); insn_t(24, 14, 8,Flag,regs); insn_t(2, 10, 13,Flag,regs); insn_t(5, 3, 14,Flag,regs); insn_t(20, 11, 11,Flag,regs); insn_t(0, 14, 14,Flag,regs); insn_t(24, 14, 16,Flag,regs); insn_t(18, 13, 11,Flag,regs); insn_t(5, 3, 14,Flag,regs); insn_t(6, 11, 13,Flag,regs); insn_t(0, 14, 15,Flag,regs); insn_t(24, 14, 24,Flag,regs); insn_t(4, 11, 10,Flag,regs); insn_t(5, 3, 14,Flag,regs); insn_t(21, 4, 0,Flag,regs); insn_t(15, 13, 11,Flag,regs); insn_t(0, 14, 16,Flag,regs); insn_t(6, 10, 10,Flag,regs); insn_t(24, 14, 0,Flag,regs); insn_t(14, 10, 12,Flag,regs); insn_t(5, 4, 14,Flag,regs); insn_t(0, 14, 17,Flag,regs); insn_t(12, 13, 13,Flag,regs); insn_t(24, 14, 8,Flag,regs); insn_t(19, 11, 10,Flag,regs); insn_t(5, 4, 14,Flag,regs); insn_t(0, 14, 18,Flag,regs); insn_t(17, 13, 12,Flag,regs); insn_t(24, 14, 16,Flag,regs); insn_t(5, 4, 14,Flag,regs); insn_t(0, 14, 19,Flag,regs); insn_t(24, 14, 24,Flag,regs); insn_t(21, 12, 10,Flag,regs); insn_t(5, 4, 14,Flag,regs); insn_t(13, 13, 10,Flag,regs); insn_t(21, 5, 0,Flag,regs); insn_t(0, 14, 20,Flag,regs); insn_t(19, 10, 13,Flag,regs); insn_t(24, 14, 0,Flag,regs); insn_t(5, 5, 14,Flag,regs); insn_t(0, 14, 21,Flag,regs); insn_t(24, 14, 8,Flag,regs); insn_t(8, 13, 13,Flag,regs); insn_t(5, 5, 14,Flag,regs); insn_t(0, 14, 22,Flag,regs); insn_t(16, 13, 11,Flag,regs); insn_t(24, 14, 16,Flag,regs); insn_t(10, 10, 13,Flag,regs); insn_t(5, 5, 14,Flag,regs); insn_t(7, 10, 12,Flag,regs); insn_t(0, 14, 23,Flag,regs); insn_t(19, 13, 10,Flag,regs); insn_t(24, 14, 24,Flag,regs); insn_t(5, 5, 14,Flag,regs); insn_t(17, 12, 10,Flag,regs); insn_t(21, 6, 0,Flag,regs); insn_t(16, 11, 10,Flag,regs); insn_t(0, 14, 24,Flag,regs); insn_t(24, 14, 0,Flag,regs); insn_t(10, 11, 10,Flag,regs); insn_t(5, 6, 14,Flag,regs); insn_t(0, 14, 25,Flag,regs); insn_t(24, 14, 8,Flag,regs); insn_t(7, 10, 12,Flag,regs); insn_t(5, 6, 14,Flag,regs); insn_t(0, 14, 26,Flag,regs); insn_t(16, 12, 11,Flag,regs); insn_t(24, 14, 16,Flag,regs); insn_t(3, 11, 10,Flag,regs); insn_t(5, 6, 14,Flag,regs); insn_t(15, 11, 13,Flag,regs); insn_t(0, 14, 27,Flag,regs); insn_t(4, 12, 13,Flag,regs); insn_t(24, 14, 24,Flag,regs); insn_t(5, 6, 14,Flag,regs); insn_t(14, 11, 13,Flag,regs); insn_t(21, 7, 0,Flag,regs); insn_t(0, 14, 28,Flag,regs); insn_t(21, 13, 11,Flag,regs); insn_t(24, 14, 0,Flag,regs); insn_t(7, 12, 11,Flag,regs); insn_t(5, 7, 14,Flag,regs); insn_t(17, 11, 10,Flag,regs); insn_t(0, 14, 29,Flag,regs); insn_t(24, 14, 8,Flag,regs); insn_t(5, 7, 14,Flag,regs); insn_t(0, 14, 30,Flag,regs); insn_t(12, 10, 10,Flag,regs); insn_t(24, 14, 16,Flag,regs); insn_t(5, 7, 14,Flag,regs); insn_t(0, 14, 31,Flag,regs); insn_t(20, 10, 10,Flag,regs); insn_t(24, 14, 24,Flag,regs); insn_t(5, 7, 14,Flag,regs); insn_t(21, 8, 0,Flag,regs); insn_t(18, 10, 12,Flag,regs); insn_t(0, 14, 32,Flag,regs); insn_t(9, 11, 11,Flag,regs); insn_t(24, 14, 0,Flag,regs); insn_t(21, 12, 11,Flag,regs); insn_t(5, 8, 14,Flag,regs); insn_t(0, 14, 33,Flag,regs); insn_t(24, 14, 8,Flag,regs); insn_t(19, 10, 13,Flag,regs); insn_t(5, 8, 14,Flag,regs); insn_t(8, 12, 13,Flag,regs); insn_t(0, 14, 34,Flag,regs); insn_t(24, 14, 16,Flag,regs); insn_t(5, 8, 14,Flag,regs); insn_t(8, 10, 10,Flag,regs); insn_t(0, 14, 35,Flag,regs); insn_t(24, 14, 24,Flag,regs); insn_t(21, 13, 10,Flag,regs); insn_t(5, 8, 14,Flag,regs); insn_t(0, 12, 10,Flag,regs); insn_t(21, 9, 0,Flag,regs); insn_t(0, 14, 36,Flag,regs); insn_t(24, 14, 0,Flag,regs); insn_t(5, 9, 14,Flag,regs); insn_t(17, 11, 11,Flag,regs); insn_t(0, 14, 37,Flag,regs); insn_t(14, 10, 13,Flag,regs); insn_t(24, 14, 8,Flag,regs); insn_t(5, 9, 14,Flag,regs); insn_t(4, 10, 11,Flag,regs); insn_t(0, 14, 38,Flag,regs); insn_t(13, 11, 13,Flag,regs); insn_t(24, 14, 16,Flag,regs); insn_t(5, 9, 14,Flag,regs); insn_t(0, 14, 39,Flag,regs); insn_t(10, 11, 10,Flag,regs); insn_t(24, 14, 24,Flag,regs); insn_t(20, 13, 13,Flag,regs); insn_t(5, 9, 14,Flag,regs); insn_t(6, 12, 11,Flag,regs); insn_t(21, 14, 0,Flag,regs); insn_t(8, 0, 2769503260,Flag,regs); insn_t(10, 0, 997841014,Flag,regs); insn_t(19, 12, 11,Flag,regs); insn_t(2, 0, 4065997671,Flag,regs); insn_t(5, 13, 11,Flag,regs); insn_t(8, 0, 690011675,Flag,regs); insn_t(15, 11, 11,Flag,regs); insn_t(8, 0, 540576667,Flag,regs); insn_t(2, 0, 1618285201,Flag,regs); insn_t(8, 0, 1123989331,Flag,regs); insn_t(8, 0, 1914950564,Flag,regs); insn_t(8, 0, 4213669998,Flag,regs); insn_t(21, 13, 11,Flag,regs); insn_t(8, 0, 1529621790,Flag,regs); insn_t(10, 0, 865446746,Flag,regs); insn_t(2, 10, 11,Flag,regs); insn_t(8, 0, 449019059,Flag,regs); insn_t(16, 13, 11,Flag,regs); insn_t(8, 0, 906976959,Flag,regs); insn_t(6, 10, 10,Flag,regs); insn_t(8, 0, 892028723,Flag,regs); insn_t(10, 0, 1040131328,Flag,regs); insn_t(2, 0, 3854135066,Flag,regs); insn_t(2, 0, 4133925041,Flag,regs); insn_t(2, 0, 1738396966,Flag,regs); insn_t(2, 12, 12,Flag,regs); insn_t(8, 0, 550277338,Flag,regs); insn_t(10, 0, 1043160697,Flag,regs); insn_t(2, 1, 1176768057,Flag,regs); insn_t(10, 1, 2368952475,Flag,regs); insn_t(8, 12, 11,Flag,regs); insn_t(2, 1, 2826144967,Flag,regs); insn_t(8, 1, 1275301297,Flag,regs); insn_t(10, 1, 2955899422,Flag,regs); insn_t(2, 1, 2241699318,Flag,regs); insn_t(12, 11, 10,Flag,regs); insn_t(8, 1, 537794314,Flag,regs); insn_t(11, 13, 10,Flag,regs); insn_t(8, 1, 473021534,Flag,regs); insn_t(17, 12, 13,Flag,regs); insn_t(8, 1, 2381227371,Flag,regs); insn_t(10, 1, 3973380876,Flag,regs); insn_t(10, 1, 1728990628,Flag,regs); insn_t(6, 11, 13,Flag,regs); insn_t(8, 1, 2974252696,Flag,regs); insn_t(0, 11, 11,Flag,regs); insn_t(8, 1, 1912236055,Flag,regs); insn_t(2, 1, 3620744853,Flag,regs); insn_t(3, 10, 13,Flag,regs); insn_t(2, 1, 2628426447,Flag,regs); insn_t(11, 13, 12,Flag,regs); insn_t(10, 1, 486914414,Flag,regs); insn_t(16, 11, 12,Flag,regs); insn_t(10, 1, 1187047173,Flag,regs); insn_t(14, 12, 11,Flag,regs); insn_t(2, 2, 3103274804,Flag,regs); insn_t(13, 10, 10,Flag,regs); insn_t(8, 2, 3320200805,Flag,regs); insn_t(8, 2, 3846589389,Flag,regs); insn_t(1, 13, 13,Flag,regs); insn_t(2, 2, 2724573159,Flag,regs); insn_t(10, 2, 1483327425,Flag,regs); insn_t(2, 2, 1957985324,Flag,regs); insn_t(14, 13, 12,Flag,regs); insn_t(10, 2, 1467602691,Flag,regs); insn_t(8, 2, 3142557962,Flag,regs); insn_t(2, 13, 12,Flag,regs); insn_t(2, 2, 2525769395,Flag,regs); insn_t(8, 2, 3681119483,Flag,regs); insn_t(8, 12, 11,Flag,regs); insn_t(10, 2, 1041439413,Flag,regs); insn_t(10, 2, 1042206298,Flag,regs); insn_t(2, 2, 527001246,Flag,regs); insn_t(20, 10, 13,Flag,regs); insn_t(10, 2, 855860613,Flag,regs); insn_t(8, 10, 10,Flag,regs); insn_t(8, 2, 1865979270,Flag,regs); insn_t(1, 13, 10,Flag,regs); insn_t(8, 2, 2752636085,Flag,regs); insn_t(2, 2, 1389650363,Flag,regs); insn_t(10, 2, 2721642985,Flag,regs); insn_t(18, 10, 11,Flag,regs); insn_t(8, 2, 3276518041,Flag,regs); insn_t(15, 10, 10,Flag,regs); insn_t(2, 2, 1965130376,Flag,regs); insn_t(2, 3, 3557111558,Flag,regs); insn_t(2, 3, 3031574352,Flag,regs); insn_t(16, 12, 10,Flag,regs); insn_t(10, 3, 4226755821,Flag,regs); insn_t(8, 3, 2624879637,Flag,regs); insn_t(8, 3, 1381275708,Flag,regs); insn_t(2, 3, 3310620882,Flag,regs); insn_t(2, 3, 2475591380,Flag,regs); insn_t(8, 3, 405408383,Flag,regs); insn_t(2, 3, 2291319543,Flag,regs); insn_t(0, 12, 12,Flag,regs); insn_t(8, 3, 4144538489,Flag,regs); insn_t(2, 3, 3878256896,Flag,regs); insn_t(6, 11, 10,Flag,regs); insn_t(10, 3, 2243529248,Flag,regs); insn_t(10, 3, 561931268,Flag,regs); insn_t(11, 11, 12,Flag,regs); insn_t(10, 3, 3076955709,Flag,regs); insn_t(18, 12, 13,Flag,regs); insn_t(8, 3, 2019584073,Flag,regs); insn_t(10, 13, 12,Flag,regs); insn_t(8, 3, 1712479912,Flag,regs); insn_t(18, 11, 11,Flag,regs); insn_t(2, 3, 2804447380,Flag,regs); insn_t(17, 10, 10,Flag,regs); insn_t(10, 3, 2957126100,Flag,regs); insn_t(18, 13, 13,Flag,regs); insn_t(8, 3, 1368187437,Flag,regs); insn_t(17, 10, 12,Flag,regs); insn_t(8, 3, 3586129298,Flag,regs); insn_t(10, 4, 1229526732,Flag,regs); insn_t(19, 11, 11,Flag,regs); insn_t(10, 4, 2759768797,Flag,regs); insn_t(1, 10, 13,Flag,regs); insn_t(2, 4, 2112449396,Flag,regs); insn_t(10, 4, 1212917601,Flag,regs); insn_t(2, 4, 1524771736,Flag,regs); insn_t(8, 4, 3146530277,Flag,regs); insn_t(2, 4, 2997906889,Flag,regs); insn_t(16, 12, 10,Flag,regs); insn_t(8, 4, 4135691751,Flag,regs); insn_t(8, 4, 1960868242,Flag,regs); insn_t(6, 12, 12,Flag,regs); insn_t(10, 4, 2775657353,Flag,regs); insn_t(16, 10, 13,Flag,regs); insn_t(8, 4, 1451259226,Flag,regs); insn_t(8, 4, 607382171,Flag,regs); insn_t(13, 13, 13,Flag,regs); insn_t(10, 4, 357643050,Flag,regs); insn_t(2, 4, 2020402776,Flag,regs); insn_t(8, 5, 2408165152,Flag,regs); insn_t(13, 12, 10,Flag,regs); insn_t(2, 5, 806913563,Flag,regs); insn_t(10, 5, 772591592,Flag,regs); insn_t(20, 13, 11,Flag,regs); insn_t(2, 5, 2211018781,Flag,regs); insn_t(10, 5, 2523354879,Flag,regs); insn_t(8, 5, 2549720391,Flag,regs); insn_t(2, 5, 3908178996,Flag,regs); insn_t(2, 5, 1299171929,Flag,regs); insn_t(8, 5, 512513885,Flag,regs); insn_t(10, 5, 2617924552,Flag,regs); insn_t(1, 12, 13,Flag,regs); insn_t(8, 5, 390960442,Flag,regs); insn_t(12, 11, 13,Flag,regs); insn_t(8, 5, 1248271133,Flag,regs); insn_t(8, 5, 2114382155,Flag,regs); insn_t(1, 10, 13,Flag,regs); insn_t(10, 5, 2078863299,Flag,regs); insn_t(20, 12, 12,Flag,regs); insn_t(8, 5, 2857504053,Flag,regs); insn_t(10, 5, 4271947727,Flag,regs); insn_t(2, 6, 2238126367,Flag,regs); insn_t(2, 6, 1544827193,Flag,regs); insn_t(8, 6, 4094800187,Flag,regs); insn_t(2, 6, 3461906189,Flag,regs); insn_t(10, 6, 1812592759,Flag,regs); insn_t(2, 6, 1506702473,Flag,regs); insn_t(8, 6, 536175198,Flag,regs); insn_t(2, 6, 1303821297,Flag,regs); insn_t(8, 6, 715409343,Flag,regs); insn_t(2, 6, 4094566992,Flag,regs); insn_t(14, 10, 11,Flag,regs); insn_t(2, 6, 1890141105,Flag,regs); insn_t(0, 13, 13,Flag,regs); insn_t(2, 6, 3143319360,Flag,regs); insn_t(10, 7, 696930856,Flag,regs); insn_t(2, 7, 926450200,Flag,regs); insn_t(8, 7, 352056373,Flag,regs); insn_t(20, 13, 11,Flag,regs); insn_t(10, 7, 3857703071,Flag,regs); insn_t(8, 7, 3212660135,Flag,regs); insn_t(5, 12, 10,Flag,regs); insn_t(10, 7, 3854876250,Flag,regs); insn_t(21, 12, 11,Flag,regs); insn_t(8, 7, 3648688720,Flag,regs); insn_t(2, 7, 2732629817,Flag,regs); insn_t(4, 10, 12,Flag,regs); insn_t(10, 7, 2285138643,Flag,regs); insn_t(18, 10, 13,Flag,regs); insn_t(2, 7, 2255852466,Flag,regs); insn_t(2, 7, 2537336944,Flag,regs); insn_t(3, 10, 13,Flag,regs); insn_t(2, 7, 4257606405,Flag,regs); insn_t(10, 8, 3703184638,Flag,regs); insn_t(7, 11, 10,Flag,regs); insn_t(10, 8, 2165056562,Flag,regs); insn_t(8, 8, 2217220568,Flag,regs); insn_t(19, 10, 12,Flag,regs); insn_t(8, 8, 2088084496,Flag,regs); insn_t(15, 13, 10,Flag,regs); insn_t(8, 8, 443074220,Flag,regs); insn_t(16, 13, 12,Flag,regs); insn_t(10, 8, 1298336973,Flag,regs); insn_t(2, 13, 11,Flag,regs); insn_t(8, 8, 822378456,Flag,regs); insn_t(19, 11, 12,Flag,regs); insn_t(8, 8, 2154711985,Flag,regs); insn_t(0, 11, 12,Flag,regs); insn_t(10, 8, 430757325,Flag,regs); insn_t(2, 12, 10,Flag,regs); insn_t(2, 8, 2521672196,Flag,regs); insn_t(10, 9, 532704100,Flag,regs); insn_t(10, 9, 2519542932,Flag,regs); insn_t(2, 9, 2451309277,Flag,regs); insn_t(2, 9, 3957445476,Flag,regs); insn_t(5, 10, 10,Flag,regs); insn_t(8, 9, 2583554449,Flag,regs); insn_t(10, 9, 1149665327,Flag,regs); insn_t(12, 13, 12,Flag,regs); insn_t(8, 9, 3053959226,Flag,regs); insn_t(0, 10, 10,Flag,regs); insn_t(8, 9, 3693780276,Flag,regs); insn_t(15, 11, 10,Flag,regs); insn_t(2, 9, 609918789,Flag,regs); insn_t(2, 9, 2778221635,Flag,regs); insn_t(16, 13, 10,Flag,regs); insn_t(8, 9, 3133754553,Flag,regs); insn_t(8, 11, 13,Flag,regs); insn_t(8, 9, 3961507338,Flag,regs); insn_t(2, 9, 1829237263,Flag,regs); insn_t(16, 11, 13,Flag,regs); insn_t(2, 9, 2472519933,Flag,regs); insn_t(6, 12, 12,Flag,regs); insn_t(8, 9, 4061630846,Flag,regs); insn_t(10, 9, 1181684786,Flag,regs); insn_t(13, 10, 11,Flag,regs); insn_t(10, 9, 390349075,Flag,regs); insn_t(8, 9, 2883917626,Flag,regs); insn_t(10, 9, 3733394420,Flag,regs); insn_t(10, 12, 12,Flag,regs); insn_t(2, 9, 3895283827,Flag,regs); insn_t(20, 10, 11,Flag,regs); insn_t(2, 9, 2257053750,Flag,regs); insn_t(10, 9, 2770821931,Flag,regs); insn_t(18, 10, 13,Flag,regs); insn_t(2, 9, 477834410,Flag,regs); insn_t(19, 13, 12,Flag,regs); insn_t(3, 0, 1,Flag,regs); insn_t(12, 12, 12,Flag,regs); insn_t(3, 1, 2,Flag,regs); insn_t(11, 13, 11,Flag,regs); insn_t(3, 2, 3,Flag,regs); insn_t(3, 3, 4,Flag,regs); insn_t(3, 4, 5,Flag,regs); insn_t(1, 13, 13,Flag,regs); insn_t(3, 5, 6,Flag,regs); insn_t(7, 11, 11,Flag,regs); insn_t(3, 6, 7,Flag,regs); insn_t(4, 10, 12,Flag,regs); insn_t(3, 7, 8,Flag,regs); insn_t(18, 12, 12,Flag,regs); insn_t(3, 8, 9,Flag,regs); insn_t(21, 12, 10,Flag,regs); insn_t(3, 9, 10,Flag,regs)""")



constraints = [ 
  regs[0] == 0x3ee88722 ,
  regs[1] == 0xecbdbe2 ,
  regs[2] == 0x60b843c4 ,
  regs[3] == 0x5da67c7 ,
  regs[4] == 0x171ef1e9 ,
  regs[5] == 0x52d5b3f7 ,
  regs[6] == 0x3ae718c0 ,
  regs[7] == 0x8b4aacc2 ,
  regs[8] == 0xe5cf78dd ,
  regs[9] == 0x4a848edf ,
  regs[10] == 0x8f ,
  regs[11] == 0x4180000 ,
  regs[12] == 0x0 ,
  regs[13] == 0xd ,
  regs[14] == 0x0 
]

s.add(constraints)
s.add(Flag[0] ==ord("H"))
s.add(Flag[1] == ord("T"))
s.add(Flag[2] == ord("B"))
s.add(Flag[3] == ord("{"))
s.add(Flag[39] == ord("}"))

for i in range(4,38):
    s.add(Flag[i] >= 33)
    s.add(Flag[i] <= 126)

result = s.check()

if result == sat:

    model = s.model()
    string = ""

    for i, bitvec in enumerate(Flag):
        value = model[bitvec].as_long()
        temp = value
        string += chr(value)
    print(string)
else:
    print("Unsatisfiable")
