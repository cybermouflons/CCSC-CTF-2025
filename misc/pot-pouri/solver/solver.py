import sys
from pwn import remote, args, process


def decode_uart(bitstream: str) -> str:
    # UART: start(0), 8 LSB-first bits, parity, stop(1)
    FRAME = 1 + 8 + 1 + 1
    bits = bitstream.strip().replace(' ', '')
    msg = ''
    for i in range(0, len(bits), FRAME):
        frame = bits[i:i+FRAME]
        # strip start and stop bits
        data_parity = frame[1:-1]
        data_bits = data_parity[:8]
        # ignore parity bit (data_parity[8])
        byte = int(data_bits[::-1], 2)
        msg += chr(byte)
    return msg


def decode_manchester(encoded: str) -> str:
    # Manchester: '10'->1, '01'->0, space separated per byte
    block = encoded.strip().split()[0]
    bits = ''

    for i in range(0, len(block), 2):
        pair = block[i:i+2]
        bits += '1' if pair == '10' else '0'

    msg = ''
    for i in range(0, len(bits), 8):
        byte = bits[i:i+8]
        if len(byte) < 8:
            break
        msg += chr(int(byte, 2))
    return msg


def decode_nrzi(encoded: str) -> str:
    # NRZI decoding: transitions indicate '1', no change indicates '0'
    segments = ''.join(encoded.strip().split())
    prev_level = 0
    data_bits = ''
    for ch in segments:
        level = int(ch)
        # transition => data 1, no change => data 0
        data_bits += '1' if level != prev_level else '0'
        prev_level = level
    # Reassemble bytes
    msg = ''
    for i in range(0, len(data_bits), 8):
        byte = data_bits[i:i+8]
        if len(byte) < 8:
            break
        msg += chr(int(byte, 2))
    return msg


def decode_hamming74(encoded: str) -> str:
    # Hamming(7,4): p1,p2,d0,p3,d1,d2,d3 per codeword
    bits = ''.join(encoded.strip().split())
    # correct syndrome and extract data
    data = ''
    for i in range(0, len(bits), 7):
        cw = bits[i:i+7]
        r = [int(x) for x in cw]
        # syndrome bits
        s1 = r[0] ^ r[2] ^ r[4] ^ r[6]
        s2 = r[1] ^ r[2] ^ r[5] ^ r[6]
        s3 = r[3] ^ r[4] ^ r[5] ^ r[6]
        syndrome = s1 * 1 + s2 * 2 + s3 * 4
        if syndrome:
            # correct bit
            r[syndrome-1] ^= 1
        # extract data bits
        nib = [r[2], r[4], r[5], r[6]]
        data += ''.join(str(x) for x in nib)
    # group into bytes (two nibbles per char)
    msg = ''
    for i in range(0, len(data), 8):
        byte = data[i:i+8]
        if len(byte) < 8:
            break
        msg += chr(int(byte, 2))
    return msg


# ------ Main solver ------

def pwn(p):
    # Skip welcome and example decode
    p.recvuntil(b'Correct!')

    for round_num in range(2, 101):
        line = p.recvline().decode().strip()
        # skip blank lines
        while not line.startswith('['):
            line = p.recvline().decode().strip()
        # parse
        line = line.strip('[]').split('] ', 1)
        proto, payload = line[1].strip('[]').split('] ', 1)
        proto = proto.strip()
        # decode
        if proto == 'UART':
            answer = decode_uart(payload)
        elif proto == 'Manchester':
            answer = decode_manchester(payload)
        elif proto == 'NRZI':
            answer = decode_nrzi(payload)
        elif proto == 'Hamming74':
            answer = decode_hamming74(payload)
        else:
            raise ValueError(f"Unknown protocol: {proto}")
        # send
        p.sendline(answer.encode())
        # read confirmation
        p.recvuntil(f'Correct!'.encode())

    # final flag
    p.recvline()
    p.recvline()
    flag = p.recvline().decode().strip()
    print(flag)


if __name__ == "__main__":
    if args.REMOTE:
        ip, port = args.HOST.split(":")
        connection = remote(ip, int(port))
    else:
        connection = process("python3 server.py",
                             shell=True,
                             cwd="../challenge")

    pwn(connection)
