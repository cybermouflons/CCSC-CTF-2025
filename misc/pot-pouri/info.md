Name: Pot Pouri

Difficulty: <font color=green>Easy</font>

## Description

* A mischievous trickster has sent 100 mysterious transmissions through the network. Can you unravel every single one before the clock runs out and seize the ultimate secret?

# Enumeration

## Network Interaction & Protocol Discovery

Since source code is unavailable locally, we enumerate by interacting with the service:

1. **Connect to the server** with `nc host port` (or via pwntools).
2. **Observe the welcome banner**, which lists supported protocols and shows an example:

```
Decode 100 randomized messages encoded with various schemes.
Protocols you'll see:
  - NRZ-I
  - Manchester
  - Hamming (7,4)
  - UART

[Round 1/100] [Manchester] 01101001100101010110100101100110011010011010010101101001101001010110100110101010
> hello
✔ Correct (1/100)
```

3. **Infer each encoding scheme** from banner and example.
4. **Note** the strict **1‑second** per-round timeout.

A summary of our findings:

1. The server uses 1 s timeouts enforced via signal alarms.
2. Four distinct line‑coding or error‑control schemes appear: NRZ‑I, Manchester, Hamming(7,4), UART.

# Solution

## Finding the decoding strategy

By inspecting the banner and trial example:

* **Manchester**: bit pairs `10→1`, `01→0`.
* **NRZ‑I**: transitions = 0, holds = 1; initial bit assumed 1.
* **Hamming(7,4)**: 7-bit codewords with 3 parity bits for single‑bit correction.
* **UART**: frames of `[0][8 LSB bits][parity][1]` per byte.

## Exploitation

### Connecting to the server

A pretty basic script for connecting to the server with `pwntools`:

```python
if __name__ == "__main__":
    r = remote("0.0.0.0", 1337)
    pwn()
```

### The Decoders

Implement each `dispatch_decoder()`:

```python
if proto == 'UART':
    return decode_uart(payload)
elif proto == 'Manchester':
    return decode_manchester(payload)
elif proto == 'NRZI':
    return decode_nrzi(payload)
elif proto == 'Hamming74':
    return decode_hamming74(payload)
```

#### Manchester

```python
def decode_manchester(encoded: str) -> str:
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
```

#### NRZI

```python
def decode_nrzi(encoded: str) -> str:
    segments = ''.join(encoded.strip().split())
    prev_level = 0
    data_bits = ''
    for ch in segments:
        level = int(ch)
        data_bits += '1' if level != prev_level else '0'
        prev_level = level
    msg = ''
    for i in range(0, len(data_bits), 8):
        byte = data_bits[i:i+8]
        if len(byte) < 8:
            break
        msg += chr(int(byte, 2))
    return msg

```

#### UART

```python
def decode_uart(bitstream: str) -> str:
    FRAME = 1 + 8 + 1 + 1
    bits = bitstream.strip().replace(' ', '')
    msg = ''
    for i in range(0, len(bits), FRAME):
        frame = bits[i:i+FRAME]
        data_parity = frame[1:-1]
        data_bits = data_parity[:8]
        byte = int(data_bits[::-1], 2)
        msg += chr(byte)
    return msg
```

#### Hamming (7, 4)

```python
def decode_hamming74(encoded: str) -> str:
    bits = ''.join(encoded.strip().split())
    data = ''
    for i in range(0, len(bits), 7):
        cw = bits[i:i+7]
        r = [int(x) for x in cw]
        s1 = r[0] ^ r[2] ^ r[4] ^ r[6]
        s2 = r[1] ^ r[2] ^ r[5] ^ r[6]
        s3 = r[3] ^ r[4] ^ r[5] ^ r[6]
        syndrome = s1 * 1 + s2 * 2 + s3 * 4
        if syndrome:
            r[syndrome-1] ^= 1
        nib = [r[2], r[4], r[5], r[6]]
        data += ''.join(str(x) for x in nib)
    msg = ''
    for i in range(0, len(data), 8):
        byte = data[i:i+8]
        if len(byte) < 8:
            break
        msg += chr(int(byte, 2))
    return msg
```

### Getting the flag

1. Loop through rounds, decoding each bitstream and immediately responding.
2. On round 100 success, the server prints:

   ```
   FLAG{it5_7h3_f1r57_4nd_la57_71m3_y0u_w1ll_533_m4nch3573r_3nc0d1n6!}
   ```

