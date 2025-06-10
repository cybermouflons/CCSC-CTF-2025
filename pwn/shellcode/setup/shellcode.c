// gcc -static-pie -fPIE -Wl,-z,relro,-z,now -o shellcode shellcode.c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>
#include <stdint.h>

#define SC_LEN 74

void setup(void) {
    setvbuf(stdout, (char *)0x0, 2, 0);
    setvbuf(stderr, (char *)0x0, 2, 0);
    return;
}

int not_allowed(char *ptr) {
    // Check for "bin/" substring first using optimized library function
    if (strstr(ptr, "bin/") != NULL) {
        puts("Forbidden!");
        return 1;
    }
    
    for (unsigned long i = 0; i <= SC_LEN - 2; i++) {
        if (ptr[i] == 0x0f) {  // Check for 0x0f byte (common in SYSENTER / SYSCALL )
            puts("Not Allowed!");
            return 1;
        }
        if (ptr[i] == 0xcd && ptr[i+1] == 0x80) {  // int 0x80 (32-bit syscall)
            puts("Not Allowed!");
            return 1;
        }
    }
    return 0;
}

int main(void) {
    char *mem;
    void (*func)();

    setup();
    
    // Allocate RWX memory at fixed address 0x13370000
    mem = mmap((void*)0x13370000, SC_LEN, 
              PROT_READ | PROT_WRITE | PROT_EXEC,
              MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
    
    if (mem == MAP_FAILED) {
        perror("mmap");
        return 1;
    }
    
    memset(mem, 0, SC_LEN);
    
    puts("\nGive me your shellcode: ");
    read(STDIN_FILENO, mem, SC_LEN);
    puts("\nShellcode Received\n");

    if (not_allowed(mem)) {
        exit(1);
    }
    
    // Change protection to RX after validation
    mprotect(mem, SC_LEN, PROT_READ | PROT_EXEC);
    
    // clear regs
    __asm__ volatile (
        "xor rax, rax\n\t"
        "xor rbx, rbx\n\t"
        "xor rcx, rcx\n\t"
        "mov rdx, 0xdeadbeef\n\t"
        "mov rsi, 0x13371337\n\t"
        "mov rdi, 0xc0decafe\n\t"
        "xor r8, r8\n\t"
        "xor r9, r9\n\t"
        "xor r10, r10\n\t"
        "xor r11, r11\n\t"
        "xor r12, r12\n\t"
        "xor r13, r13\n\t"
        "xor r14, r14\n\t"
        "xor r15, r15"
        : /* No outputs */
        : /* No inputs */
        : "rax", "rbx", "rcx", "rdx", "rsi", "rdi",
          "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15", "cc"
    );

    func = (void (*)())mem;
    func();

    return 0;
}
