# Solution: Anti-Tricks (Reverse Engineering)

## Initial examination

- The binary is an ELF 64-bit LSB executable, x86-64, statically linked, stripped

- When we try to run it, we receive a `SIGTRAP`, which likely means it contains an `int3` instruction (`0xCC`), commonly used for triggering breakpoints.

- Using `objdump -d | grep cc` we search for any `int3` instructions. None are found directly, but there is a `0xCC` byte present in the executable code. This may be an obfuscated `int3` instruction. 
```shell
objdump -d chall | grep cc
  4010cc:       75 29                   jne    0x4010f7
  401101:       e8 33 33 69 cc          call   0xffffffffcca94439
```

- If we try to statically (e.g. using `hexedit`) replace the `0xCC` byte with a `NOP` instruction (`0x90`), we can see that we no longer receive a `SIGTRAP`:
```shell
./chall
Flag decrypted! Check stack memory!
Exiting...
```

- We now see a message stating the flag is decrypted in the stack memory. Let’s investigate further using a debugger.

## Debugger Detection

### PTRACE Syscall

- Running the binary inside `gdb` prints "Debugger detected!" and causes the program to exit immediately.

- At address `0x4010c6` there is a `ptrace` syscall followed by a `cmp` instruction checking the return value. If the binary is being debugged, this syscall returns `-1`. We can bypass this check by modifying the return value in `rax` after the `syscall` executes.

### Time-based debugger detection

- If we continue execution, a new message appears: "Execution is running super slow. Probably in a debugger!"

- The binary uses two rdtsc instructions (at `0x40100e` and `0x401199`) to read the CPU's timestamp counter.

- After the first `rdtsc`, the value in `rdx` is saved to the stack at `rbp - 0x50`:
```
  40100e:       0f 31                   rdtsc
  401010:       48 89 d0                mov    %rdx,%rax
  401013:       48 89 45 b0             mov    %rax,-0x50(%rbp)
```
- After the second `rdtsc`, the program calculates the difference and compares it:
```
  401199:       0f 31                   rdtsc
  40119b:       48 2b 55 b0             sub    -0x50(%rbp),%rdx
  40119f:       48 83 fa 02             cmp    $0x2,%rdx
  4011a3:       7c 26                   jl     0x4011cb
```
- If the difference is less than 2, execution continues. Otherwise, it exits with a debugger warning.

- We can bypass this check if we modify `rdx` just before the `cmp $0x2,%rdx` instruction at `0x40119f`. 

- The second `rdtsc` is in a loop and therefore executed multiple times. We must bypass every sinlge check, or patch the code to jump directly to `0x0x4011cb`. 
  
- Alternatively, we can modify the returned value of the first `rdtsc`, saved at `rbp - 0x50`.

## Obfuscation

### Anti-Disassembler code obfuscation

- There are various calls to the functions at addresses `0x401222` and `0x401228` which do nothing more than modify the saved return address and return:
```
  401222:       48 83 04 24 03          addq   $0x3,(%rsp)
  401227:       c3                      ret

  401228:       48 83 04 24 04          addq   $0x4,(%rsp)
  40122d:       c3                      ret
```

- This results in returning to a different instruction, skipping some (junk) bytes. However, these junk bytes are being disassembled to false instructions, never executed on runtime.

### NOP obfuscation
- The following instructions appear functional but ultimately do nothing, leaving the program state unchanged:

```
  40118b:       50                      push   %rax
  40118c:       01 c8                   add    %ecx,%eax
  40118e:       25 37 13 00 00          and    $0x1337,%eax
  401193:       53                      push   %rbx
  401194:       48 29 c3                sub    %rax,%rbx
  401197:       5b                      pop    %rbx
  401198:       58                      pop    %rax
```

## Solution steps

Here’s one way to bypass the protections and retrieve the flag:

1. Start execution
```gdb
starti
```

2. Set a breakpoint on the `cmp` instruction after the `ptrace syscall`, continue execution and modify the `rax` register. After continuing, you are going to hit the `SIGTRAP` from the `int3` instruction at `0x401105`.
```gdb
b *0x4010c8
c
set $rax = 0
c
```

3. The `int3` instruction is in a loop. Replace it with a `NOP` instruction (`0x90`), so you don’t need to resume execution manually each time.
```gdb
set {char} 0x401105 = 0x90
```

4. Modify the saved return value of the first `rdtsc` instruction to a large number, making the calculated difference always less than 2.
```gdb
set {int} ($rbp-0x50) = 0xffffffff
```

5. Set a breakpoint right after the "Flag decrypted!" message is printed. And examine the stack for the flag.
```gdb
b *0x4011f5
c
x/s $rbp-0x30 
```