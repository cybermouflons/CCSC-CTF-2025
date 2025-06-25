# Just a Key

Fire up Ghidra and decompile the binary...

By feeding the code extracted from the Ghidra to an AI LLM we can reconstruct pieces of the original code:
```C
#include <stdio.h>
#include <string.h>

// XOR-based decryption: output[i] = input[i % input_len] ^ key[i]
void xor_decrypt(const char *key, char *output, const char *input) {
    size_t key_len = strlen(key);
    size_t input_len = strlen(input);

    if (key_len <= 1 || input_len <= 1) return;

    for (size_t i = 0; i < key_len - 1; i++) {
        output[i] = input[i % (input_len - 1)] ^ key[i];
    }
    output[key_len - 1] = '\0';
}

int main(int argc, char **argv) {
    if (argc != 2) {
        printf("[!] Usage: %s <key>\n", argv[0]);
        return 1;
    }

    const char *input_key = argv[1];
    size_t input_key_len = strlen(input_key);

    if (input_key_len <= 5) {
        puts("[!] Input key is too small");
        return 1;
    }

    // Internal keys and buffers
    char mutable_key[40] = {
        0x11, 0x11, 0x11, 0x11, 0x11,
        0x01, 0x3d, 0x46, 0x8f, 0x9e, 0xba, 0xe9, 0x59,
        0x4f, 0xff, 0xcf, 0x56, 0xea, 0xc9, 0x94, 0x5b,
        0x05, 0x3e, 0x68, 0x7f, 0x38, 0x9b, 0x12, 0xc1,
        0x7a, 0xe0, 0xd7, 0x81, 0xe5, 0x94, 0x9d, 0xc1,
        0x00
    };

    const char encrypted_stage1[] = {
        0x64, 0x5c, 0x37, 0xea, 0xd5, 0xf0, 0x9e, 0x4e,
        0x1d, 0x90, 0xdb, 0x2b, 0xa6, 0xde, 0xe7, 0x48,
        0x98, 0xd6, 0xb1, 0xe5, 0xde, 0x54, 0x46, 0x5a,
        0x15, 0x83, 0x9d, 0x97, 0xf2, 0x95, 0x8e, 0x8d,
        0x00
    };

    char buffer1[256] = {0};
    char buffer2[256] = {0};

    // Mutate mutable_key using the input key
    for (size_t i = 0; i < input_key_len - 1; i += 5) {
        xor_decrypt(mutable_key, mutable_key, input_key + i);
    }

    puts("[.] Decrypting ...");

    xor_decrypt((char *)mutable_key + 5, buffer1, mutable_key);
    xor_decrypt(encrypted_stage1, buffer2, buffer1);

    printf("[.] Here is your flag: %s\n", buffer2);
    return 0;
}

```


We can see that the output is the flag, thus the encrypted values bellow should result to `ECSC{`:
```
    0x64, 0x5c, 0x37, 0xea, 0xd5
XOR 0x45, 0x43, 0x53, 0x43, 0x7B # ECSC{
  = 0x??, 0x??, 0x??, 0x??, 0x??
```

Here is a python code to do that:
```python
a = [0x64, 0x5c, 0x37, 0xea, 0xd5]
b = [0x45, 0x43, 0x53, 0x43, 0x7B]
res = [a[i] ^ b[i] for i in range(len(a))]
print(", ".join(f"0x{b:02x}" for b in res)) # 0x21, 0x1f, 0x64, 0xa9, 0xae
```

Resulting in:
```
    0x64, 0x5c, 0x37, 0xea, 0xd5
XOR 0x45, 0x43, 0x53, 0x43, 0x7B # ECSC{
  = 0x21, 0x1f, 0x64, 0xa9, 0xae # Possible key start
```

Hence part of the `buffer1`'s start should be their XORing:
```
    0x01, 0x3d, 0x46, 0x8f, 0x9e # Encrypted key start
XOR 0x21, 0x1f, 0x64, 0xa9, 0xae # Possible key start
XOR 0x11, 0x11, 0x11, 0x11, 0x11 # Initial XOR value
  = 0x??, 0x??, 0x??, 0x??, 0x?? # Posible user input
```

And the coresponding code
```python
a = [0x01, 0x3d, 0x46, 0x8f, 0x9e]
b = [0x21, 0x1f, 0x64, 0xa9, 0xae]
c = [0x11, 0x11, 0x11, 0x11, 0x11]
res = [(a[i] ^ b[i] ^ c[i]) for i in range(len(a))]
print(", ".join(f"0x{b:02x}" for b in res)) # 0x31, 0x33, 0x33, 0x37, 0x21
print(''.join([chr(c) for c in res])) # 1337!
```

Adding the `1337!` as input:

```
thanos@potato:~$ ./chall "1337!"
[.] Decrypting ...
[.] Here is your flag: ECSC{jU5t_4_n1C3_waRM_up_Ch4113nGe!}
```
