import struct

Counter = 0
Character_Counter = 0
with open('message.txt.cz', 'rb') as file:
    data = file.read()
dec = [0] * 10000

while Counter < len(data):
    val = struct.unpack('<Q', data[Counter:Counter+8])[0]
    if val == 0:
        Counter += 8
        Character_Counter += 1
        continue
    if val != 0:
        length= val
        Counter += 8
        for i in range(Counter,Counter + (8*length),8):
            val = struct.unpack('<Q', data[i:i+8])[0]
            dec[val] = Character_Counter
        Character_Counter += 1
        Counter += 8*length
decstr = ""
for i in dec:
    if i != 0:
        decstr += chr(i)
    else:
        break
print(decstr)
    
