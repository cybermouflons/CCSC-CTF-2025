.intel_syntax noprefix

.section .data
message: 
    .asciz "Exiting...\n",
msg_dbg: 
    .asciz "Debugger detected!\n",
msg_time: 
    .asciz "Execution is running super slow. Probably in a debugger!\n",
msg_decrypted: 
    .asciz "Flag decrypted! Check stack memory!\n",

.section .text
.global _start 

_start:
mov rbp, rsp
sub rsp, 0x60

mov dword ptr [rbp-0x3c], 0x25 # flag length

# Save timestamp counter
rdtsc
mov rax, rdx
mov [rbp-0x50], rax

# Load "encrypted" flag
mov rax, 0x87084a2f74dd2120
mov rbx, 0x1235414325ae3239
add rax, rbx
mov [rbp-0x30], rax

mov rax, 0xeeb96c88e6528835
sub ax, 0x56ff
mov [rbp-0x28], rax

mov rax, 0x979d50e492b679a3
mov rcx, 0x234ac87300003300
xor rax, rcx
mov [rbp-0x20], rax

#mov rax, 0x8676da4f68c69032 (obfuscated with 3 junk bytes resulting the instructions below)
call skip_3_bytes
test   al,0x6d
ror    DWORD PTR [rax-0x48],0x32
nop
.byte 0xc6
push   0xffffffff8676da4f
mov [rbp-0x18], rax

mov rax, 0xa7767b57bbdfd
shr rax, 8
mov [rbp-0x10], rax

lea    rax,[rbp-0x30]
mov    QWORD PTR [rbp-0x38],rax
mov    eax,DWORD PTR [rbp-0x3c]
sub    eax,0x1
mov    DWORD PTR [rbp-0x40],eax

# Debugger detection
xor rcx, rcx
mov rdx, 0xffffffffffffffff
add rdx, 2
mov rsi, rcx
mov rdi, rdx
sub rdi, 1
mov rax, 0x324c20
xor rax, 0x324c45

# ptrace syscall
call skip_4_bytes
jmp    0xf448ece
.byte 0x5

cmp rax, 0xffffffffffffffff
jne no_dbg
mov rdi, 1 
lea rsi, msg_dbg
mov edx, 19
mov rax, 1
syscall
jmp exit
mov qword ptr [rax], 0 # access invalid address
no_dbg:

# Decrypt flag
jmp check_end
decrypt_procedure:

# int3 (obfuscated)
call skip_4_bytes
call   0xffffffffcca94439

mov    eax,DWORD PTR [rbp-0x40]
movsxd rdx,eax
mov    rax,QWORD PTR [rbp-0x38]
add    rax,rdx
movzx  eax,BYTE PTR [rax]
movsx  ecx,al
mov    eax,DWORD PTR [rbp-0x40]
add    eax,0x2
cdq
idiv   DWORD PTR [rbp-0x3c]
mov    eax,edx
movsxd rdx,eax
mov    rax,QWORD PTR [rbp-0x38]
add    rax,rdx
movzx  eax,BYTE PTR [rax]
movsx  eax,al
sub    ecx,eax

#mov    edx,ecx (obfuscated with 3 junk bytes resulting the instructions below)
call skip_3_bytes
push   0x3a
mov    ch,0x89
.byte 0xca

mov    eax,edx
sar    eax,0x1f
shr    eax,0x18
add    edx,eax
movzx  edx,dl
sub    edx,eax
mov    eax,edx
mov    BYTE PTR [rbp-0x42],al
mov    eax,DWORD PTR [rbp-0x40]
add    eax,0x1
cdq
idiv   DWORD PTR [rbp-0x3c]
mov    eax,edx
movsxd rdx,eax
mov    rax,QWORD PTR [rbp-0x38]
add    rax,rdx
movzx  eax,BYTE PTR [rax]
xor    al,BYTE PTR [rbp-0x42]
mov    BYTE PTR [rbp-0x41],al
mov    eax,DWORD PTR [rbp-0x40]
movsxd rdx,eax
mov    rax,QWORD PTR [rbp-0x38]
add    rdx,rax
movzx  eax,BYTE PTR [rbp-0x41]
mov    BYTE PTR [rdx],al
sub    DWORD PTR [rbp-0x40],0x1

# NOP obfuscation
push rax
add eax, ecx
and eax, 0x1337
push rbx
sub rbx, rax
pop rbx
pop rax

# compare timestamp counter
rdtsc
sub rdx, [rbp-0x50]
cmp rdx, 0x2
jl check_end
mov rdi, 1 
lea rsi, msg_time
mov edx, 57
mov rax, 1
syscall
jmp exit
mov qword ptr [rax], 0 # access invalid address

check_end:
    cmp DWORD PTR [rbp-0x40], 0x0
    jns decrypt_procedure


# print decrypted flag
mov rdi, 1 
lea rsi, msg_decrypted
mov edx, 36
add edx, 1
mov rax, 1
syscall

exit:
mov rdi, 1 
lea rsi, message
mov edx, 11
mov rax, 1
syscall

mov rdi, 0
mov rax, 60
syscall

skip_3_bytes:
add qword ptr [rsp], 3
ret

skip_4_bytes:
add qword ptr [rsp], 4
ret
