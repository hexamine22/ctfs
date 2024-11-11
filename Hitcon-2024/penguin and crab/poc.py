import struct 

rol = lambda val, r_bits, max_bits: \
    (val << r_bits%max_bits) & (2**max_bits-1) | \
    ((val & (2**max_bits-1)) >> (max_bits-(r_bits%max_bits)))

def bittest(source, bit_offset):
    mask = 1 << bit_offset
    return bool(source & mask)
some_arr = [0xAEC4F08C,0x642C04AC,0xA3607854,0x2D393934,0x8E2C4F5A,0xDDD67D14,0x7E005496,0x3ED14A02,0xA56A772,0x466A4076,0xD3A352A9,0x495E93E3,0x67C44ADF,0x3AEBE5BA,0xED850DA8,0xD4B77198,0x51BDB6B2,0x3A5F2448,0x807889CA,0x5B9D4D6E,0x8320EFD6,0x9E68E874,0xBA7FBEA1,0x827BC7E4,0x129F824A]

div_cmp_arr = [0x1be3b694,0xad42f89,0x1003913b7,0x37c23eb4,0x64c07ef5,0xd7b4785,0x49115944,0x5241f45e,0x829722e9,0x6801ca71,0x165020cf,0xe45f7ab1]
remainder_cmp_arr = [0xa2cc3f37,0xb8b0e2e6,0x9dea4fd6,0x897da0d6,0x52b660e5,0x7dbcdc09,0x588e7836,0x3ea786e5,0x5bc7bb33,0xa3959e86,0x5ab05a2f,0xb09e4a8c]
flag12_cmp_arr =[0x38ED550C61366B19,0x0,0xA368D7F6F944EF95,0x0,0x7730E544811B003B,0x0,0xBA7B915F29478B8,0x0,0x4CF3C7A1444DDCD5,0x0,0x6A1EE5D1CB932EDD,0x0,0x1C653D0FAA75CD04,0x0,0x5129602CEBB27CD3,0x0,0x8D3E0DDB822D166C,0x0,0x7743085C81B563CA,0x0,0x1FD73D5B1682BEC1,0x0,0x49CA0C91D932E680,0x0,0x10AC7806FD7DC9E2,0x0,0x939CB3D71DC3703E,0x0,0x3719C10EFED548AF,0x0,0x91AAD1F7FE14E4B,0x0,0x8FE8985576B03857,0x0,0x376937BC0AF64E77,0x0,0x26190529FD5F0437,0x0,0x12CF894F2AF71BF3,0x0,0x22E8F33E31870D59,0x0,0x6842E8D2ED57A1F1,0x0,0x189EBE5A06E8334F,0x0,0x591CEA928108D643,0x0,0x4914740091A11C11,0x0,0x3B1A8BB8CD64FAE1,0x0,0x48009C01B6DC47BA,0x0,0x6CC80ED5A2D94B80,0x0,0x3A41F29B470B9346,0x0,0x154D52272BF8F,0x0,0x7E416B359A0655CC,0x0,0x6858E18B590D1A8F,0x0]
flag12_1 =[0x38ed550c61366b19,0x7730e544811b003b,0x4cf3c7a1444ddcd5,0x1c653d0faa75cd04,0x8d3e0ddb822d166c,0x1fd73d5b1682bec1,0x10ac7806fd7dc9e2,0x3719c10efed548af,0x8fe8985576b03857,0x26190529fd5f0437,0x22e8f33e31870d59,0x189ebe5a06e8334f,0x4914740091a11c11,0x48009c01b6dc47ba,0x3a41f29b470b9346,0x7e416b359a0655cc]

flag12_2 =[0xa368d7f6f944ef95,0xba7b915f29478b8,0x6a1ee5d1cb932edd,0x5129602cebb27cd3,0x7743085c81b563ca,0x49ca0c91d932e680,0x939cb3d71dc3703e,0x91aad1f7fe14e4b,0x376937bc0af64e77,0x12cf894f2af71bf3,0x6842e8d2ed57a1f1,0x591cea928108d643,0x3b1a8bb8cd64fae1,0x6cc80ed5a2d94b80,0x154d52272bf8f,0x6858e18b590d1a8f]
hardcoded_flag = b"hitcon{????????????????????????????????????????????????????????????????????????????????????????????}"
xored_arr = []
for i in range(len(hardcoded_flag)//4):
    temp_int = struct.unpack('>I', hardcoded_flag[i*4:(i+1)*4].ljust(4))[0]
    xored_arr.append(temp_int)

for i in range(25):
    xored_arr[i] = rol(xored_arr[i] ^ 0xDEADBEEF, 0x19,32)
    xored_arr[i] = rol(xored_arr[i] ^ 0x14530451, 0x19,32)
    xored_arr[i] = rol(xored_arr[i] ^ 0x14530451, 0x19,32)
    xored_arr[i] = rol(xored_arr[i] ^ 0x14530451, 0x19,32)
    xored_arr[i] = rol(xored_arr[i] ^ 0x14530451, 0x19,32)
    xored_arr[i] = rol(xored_arr[i] ^ 0x14530451, 0x19,32)
    xored_arr[i] = rol(xored_arr[i] ^ 0x14530451, 0x19,32)
    xored_arr[i] = rol(xored_arr[i] ^ 0x14530451, 0x19,32)
    xored_arr[i] = rol(xored_arr[i] ^ 0x14530451, 0x19,32)
    xored_arr[i] = rol(xored_arr[i] ^ 0x14530451, 0x19,32)
    xored_arr[i] = rol(xored_arr[i] ^ 0x14530451, 0x19,32)
    xored_arr[i] = rol(xored_arr[i] ^ 0x14530451, 0x19,32)
    xored_arr[i] = rol(xored_arr[i] ^ 0x14530451, 0x19,32)
    xored_arr[i] = rol(xored_arr[i] ^ 0x14530451, 0x19,32)
    xored_arr[i] = rol(xored_arr[i] ^ 0x14530451, 0x19,32)
    xored_arr[i] = rol(xored_arr[i] ^ 0x14530451, 0x19,32)
    xored_arr[i] = rol(xored_arr[i] ^ 0x14530451, 0x19,32)
    xored_arr[i] = rol(xored_arr[i] ^ 0x14530451, 0x19,32)
    xored_arr[i] = rol(xored_arr[i] ^ 0x14530451, 0x19,32)
    xored_arr[i] = rol(xored_arr[i] ^ 0x14530451, 0x19,32)
    xored_arr[i] = rol(xored_arr[i] ^ 0x14530451, 0x19,32)
    xored_arr[i] = rol(xored_arr[i] ^ 0x14530451, 0x19,32)
    xored_arr[i] = rol(xored_arr[i] ^ 0x14530451, 0x19,32)
    xored_arr[i] = rol(xored_arr[i] ^ 0x14530451, 0x19,32)
    xored_arr[i] = rol(xored_arr[i] ^ 0x14530451, 0x19,32)
    xored_arr[i] = rol(xored_arr[i] ^ 0x14530451, 0x19,32)
    xored_arr[i] = rol(xored_arr[i] ^ 0x14530451, 0x19,32)
    xored_arr[i]  = xored_arr[i] ^ 0xCAFEBABE
    xored_arr[i] = xored_arr[i] ^ some_arr[i]

mult_array  = [0] * 12

mult_array[0] = (xored_arr[0x1] * xored_arr[0x0]) & 0xFFFFFFFFFFFFFFFF
mult_array[1] = (xored_arr[0x3] * xored_arr[0x2]) & 0xFFFFFFFFFFFFFFFF
mult_array[2] = (xored_arr[0x5] * xored_arr[0x4]) & 0xFFFFFFFFFFFFFFFF
mult_array[3] = (xored_arr[0x7] * xored_arr[0x6]) & 0xFFFFFFFFFFFFFFFF

mult_array[4] = (xored_arr[0x9] * xored_arr[0x8]) & 0xFFFFFFFFFFFFFFFF
mult_array[5] = (xored_arr[0xb] * xored_arr[0xa]) & 0xFFFFFFFFFFFFFFFF
mult_array[6] = (xored_arr[0x17] * xored_arr[0x18]) & 0xFFFFFFFFFFFFFFFF
mult_array[7] = (xored_arr[0x15] * xored_arr[0x16]) & 0xFFFFFFFFFFFFFFFF

mult_array[8] = (xored_arr[0x13] * xored_arr[0x14]) & 0xFFFFFFFFFFFFFFFF
mult_array[9] = (xored_arr[0x11] * xored_arr[0x12]) & 0xFFFFFFFFFFFFFFFF
mult_array[10] = (xored_arr[0xf] * xored_arr[0x10]) & 0xFFFFFFFFFFFFFFFF
mult_array[11] = (xored_arr[0xd] * xored_arr[0xe]) & 0xFFFFFFFFFFFFFFFF

div_array = []
remainder_array = []

for i in range(12):
    print(hex(mult_array[i]))
    div_array.append(mult_array[i] // xored_arr[12])
    remainder_array.append(mult_array[i] % xored_arr[12])

for i in range(12):
    if div_array[i] != div_cmp_arr[i]:
        print(f"div_array[{i}] failed the check")
#didn't implement the remainder check

flag_12 = xored_arr[12]

bitnum = 0 
result = 0
for i in range(16):
    val1 = bittest(flag_12,bitnum) * flag12_1[i]
    result += (val1) & 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF
    val2 = bittest(flag_12, bitnum + 1) * flag12_2[i]
    result = (result + val2) & 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF
    bitnum += 2
if result == 0x6B3312EC731522288:
    print("Correct flag!")
else:
    print("Incorrect flag!")
