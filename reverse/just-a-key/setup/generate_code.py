#!/usr/bin/env python3
import secrets

# Configuration
input_key = "1337!"

# Read the flag from flag.txt
with open("flag.txt", "r") as f:
    flag = f.read().strip()
print('Working with flag:', flag)

# Helping functions
def decode(enc, msg, key):
    l = len(enc)
    keyl = len(key)
    for i in range(l):
        msg[i] = enc[i] ^ key[i % keyl];
    return msg

def format_c_string(byte_list):
    return "{" + ", ".join(f"0x{b:02x}" for b in byte_list) + ", 0x00}"


# Convert data to arrays
input_key = [ord(c) for c in input_key]
flag = [ord(c) for c in flag]


# Generate values
ready = False
while not ready:
    dynamic_key = [0x11, 0x11, 0x11, 0x11, 0x11]
    for i in range(0, len(input_key), 5):
        decode(dynamic_key, dynamic_key, input_key[i:]);
    decrypted_key = [b for b in secrets.token_bytes(len(flag))]
    encrypted_key = [0x00 for b in decrypted_key]
    decode(decrypted_key, encrypted_key, dynamic_key);

    encrypted_flag = [0x00 for c in flag]
    decode(flag, encrypted_flag, decrypted_key);

    ready = True
    if (0x00 in dynamic_key) or (0x00 in encrypted_key) or (0x00 in encrypted_flag) or (0x00 in decrypted_key):
        ready = False
        print('[!] NULL byte found in values... regenerating...')
    else:
        print('[.] Byte values were generated')
        break


# Format for C
encrypted_key_c = format_c_string(encrypted_key)
encrypted_flag_c = format_c_string(encrypted_flag)

# Read the C template
with open("chall.template.c", "r") as template_file:
    template = template_file.read()

# Replace placeholders
code_c = template
code_c = code_c.replace("%ENCRYPTED_KEY%", encrypted_key_c)
code_c = code_c.replace("%ENCRYPTED_KEY_LEN%", str(len(encrypted_key_c)))
code_c = code_c.replace("%ENCRYPTED_FLAG%", encrypted_flag_c)
code_c = code_c.replace("%ENCRYPTED_FLAG_LEN%", str(len(encrypted_flag_c)))

# Write final challenge file
with open("chall.c", "w") as out_file:
    out_file.write(code_c)

print("[+] Code generated successfully.")
