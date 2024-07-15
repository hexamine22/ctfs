import struct

ror = lambda val, r_bits, max_bits=8: \
    ((val & (2**max_bits-1)) >> r_bits%max_bits) | \
    (val << (max_bits-(r_bits%max_bits)) & (2**max_bits-1))
some_arr = [0xAEC4F08C,0x642C04AC,0xA3607854,0x2D393934,0x8E2C4F5A,0xDDD67D14,0x7E005496,0x3ED14A02,0xA56A772,0x466A4076,0xD3A352A9,0x495E93E3,0x67C44ADF,0x3AEBE5BA,0xED850DA8,0xD4B77198,0x51BDB6B2,0x3A5F2448,0x807889CA,0x5B9D4D6E,0x8320EFD6,0x9E68E874,0xBA7FBEA1,0x827BC7E4,0x129F824A]
targets = [0xa2cc3f37,0xb8b0e2e6,0x9dea4fd6,0x897da0d6,0x52b660e5,0x7dbcdc09,0x588e7836,0x3ea786e5,0x5bc7bb33,0xa3959e86,0x5ab05a2f,0xb09e4a8c]
div_cmp_arr = [0x1be3b694,0xad42f89,0x1003913b7,0x37c23eb4,0x64c07ef5,0xd7b4785,0x49115944,0x5241f45e,0x829722e9,0x6801ca71,0x165020cf,0xe45f7ab1]
flag12 = 0xbee66f8f #brute forced final loop for this val
remainders = []

def decrypt_value(val,idx):
    val = val ^^ some_arr[idx]
    val = val ^^ 0xCAFEBABE
    for i in range(26):
        val = ror(val, 0x19,32) ^^ 0x14530451
    val = ror(val, 0x19,32) ^^ 0xDEADBEEF
    return val

def get_actual_vals(mult_val):
    factors = factor(mult_val)
    for prime, exponent in factors:
        for i in range(1, exponent + 1):
            if (prime**i) >= (mult_val // (prime**i)):
                return (prime**i), (mult_val // (prime**i))


mod = 0xE53ACEB5
F = GF(mod)
base = F(0x56361E32)

for target_value in targets:
    target = F(target_value)
    try:
        remainder = discrete_log(target, base) #sonnet helped with this lol
        remainders.append(remainder) 
        result = pow(base, remainder, mod)
        if result != target:
            print("failed verification") 
            exit()
    except ValueError as e:
        print(f"for target 0x{target_value:X}:")
        print(f"  Error: {e}")
        exit()

#recover first part

counter =0
dec_idx = 0
decrypted_flag = ""
for i in range(6):
    temp = remainders[counter] + (div_cmp_arr[counter] * flag12)
    second_val,first_val = get_actual_vals(temp)
    second_val = int(second_val)
    first_val = int(first_val)
    decrypted_first_value = decrypt_value(first_val,dec_idx)
    decrypted_second_value = decrypt_value(second_val,dec_idx+1)
    decrypted_flag += hex(decrypted_first_value)[2:] + hex(decrypted_second_value)[2:]
    #print(hex(decrypted_first_value)) 
    counter += 1
    dec_idx+=2

#recover second part

dec_idx = 24
second_part = ""

for i in range(6):
    temp = remainders[counter] + (div_cmp_arr[counter] * flag12)
    second_val,first_val = get_actual_vals(temp)
    second_val = int(second_val)
    first_val = int(first_val)
    decrypted_first_value = decrypt_value(first_val,dec_idx)
    decrypted_second_value = decrypt_value(second_val,dec_idx-1)
    second_part += hex(decrypted_first_value)[2:]
    second_part += hex(decrypted_second_value)[2:]
    counter += 1
    dec_idx -=2

second_part = bytearray.fromhex(second_part).decode()
mid_val = hex(decrypt_value(flag12,12))[2:]
decrypted_flag += mid_val
decrypted_flag = bytearray.fromhex(decrypted_flag).decode()

i = len(second_part)
second_part = second_part[::-1]
for i in range(0,len(second_part),4):
    decrypted_flag += second_part[i:i+4][::-1]
print(decrypted_flag)
