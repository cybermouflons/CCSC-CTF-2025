# !/usr/local/bin/python3
import types
import secrets
import os
from pathlib import Path
import aes

_print, _eval, _len = print, eval, len

flag_path = Path(os.environ.get("FLAG_PATH"))
flag = flag_path.read_bytes().rstrip()
flag_path.unlink(missing_ok=True)

key = secrets.token_bytes(16)
block_size = 16

crypto = aes.AES(key)
encrypted = b"".join(
    crypto.encrypt_block(
        flag[i : i + block_size] + bytearray(block_size - len(flag[i : i + block_size]))
    )
    for i in range(0, len(flag), block_size)
)

del flag

import gc


class Context:
    def __init__(self, aes, ct):
        self.aes = aes
        self.ct = ct


_ = Context(ct=encrypted, aes=crypto)


def is_valid(bytecode):
    if _len(bytecode) > 50:
        return False
    return True


if __name__ == "__main__":
    try:
        bytecode = bytes.fromhex(input("Program: "))
        code = types.CodeType(
            0,
            0,
            0,
            0,
            0,
            0,
            bytecode,
            (),
            (),
            (),
            "",
            "",
            "",
            0,
            b"",
            b"",
            (),
            (),
        )
        assert is_valid(bytecode)

        __builtins__.__dict__.clear()
        _print(_eval(code, {}))
    except:
        _print("Try harder...")
