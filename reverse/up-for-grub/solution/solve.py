import struct
import sys

if len(sys.argv) < 2:
    print(f"Usage: {sys.argv[0]} bootx64.efi")
    sys.exit(1)

key = b"\x883-\x8e*X\xf3F}[\x0e)\xe9\x0c\xae\xce\xb1\x00B\xc7k\xa9\x97\xa0[x\xb8\x11qj\x8b\xb7"

elf_offsets = [0x1E020, 0x1ECA0, 0x1FA30, 0x20C50]

with open(sys.argv[1], "rb") as f:
    boot = f.read()


for off in elf_offsets:
    # read length part of TLV
    l = struct.unpack_from("I", boot, off - 4)[0]

    data = boot[off : off + l]

    with open(f"elf_{hex(off)}", "wb") as f:
        f.write(data)


# dump tail
tl = struct.unpack_from("I", boot, off + l - 4)[0]

data = boot[off + l : off + l + tl]

with open("tail.bin", "wb") as f:
    f.write(data[:0x100])
    f.write(bytes([x ^ key[i % len(key)] for i, x in enumerate(data[0x100:])]))
