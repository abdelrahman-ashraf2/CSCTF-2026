# Telltale

**Category:** Misc

## Solution

### 1. Identify the active optical signal

I inspected `telltale(1).wav`: mono, 16-bit PCM, 48,000 samples per second, and 46,656 samples in total. The 0.972-second file recorded an LED through a photodiode.

The active interval was about `0.250–0.722 s`. I measured 24 samples per half-bit: `0.5 ms`, giving a Manchester data rate of 1,000 bits/s.

### 2. Decode the half-bit transitions

I started at sample 12,000 and compared the mean amplitude of each half-bit, skipping four samples at each edge to reduce transition noise. Low-to-high represented `1`, and high-to-low represented `0`.

I packed the 472 recovered bits MSB first, giving this 59-byte frame:

| Offset | Contents |
|---|---|
| `0x00–0x07` | Eight `0xAA` preamble bytes |
| `0x08` | Sync marker `0x7E` |
| `0x09` | Length `0x30`, or 48 bytes |
| `0x0A–0x39` | 48-byte ASCII flag |
| `0x3A` | CRC `0x37` |

### 3. Check the frame with CRC-8

I calculated CRC-8 over the length byte followed by the payload, using polynomial `0x07`, initial value zero, no reflection, and no final XOR. The 48-byte payload gave `0x37`, matching the frame.

This was my decoder:

```python
import wave
import numpy as np

filename = 'telltale(1).wav'
with wave.open(filename, 'rb') as w:
    fs = w.getframerate()
    assert w.getnchannels() == 1 and w.getsampwidth() == 2
    signal = np.frombuffer(w.readframes(w.getnframes()), dtype='<i2')

bitrate = 1000
half_bit = fs // (2 * bitrate)  # 24 samples
start = int(0.250 * fs)        # sample 12000
frame_bytes = 8 + 1 + 1 + 48 + 1
bits = []

for i in range(frame_bytes * 8):
    pos = start + i * 2 * half_bit
    first = signal[pos + 4:pos + half_bit - 4].mean()
    second = signal[pos + half_bit + 4:pos + 2 * half_bit - 4].mean()
    bits.append(int(first < second))  # low-to-high is 1

data = bytes(
    sum(bits[i + j] << (7 - j) for j in range(8))
    for i in range(0, len(bits), 8)
)

assert data[:8] == b'\xaa' * 8
assert data[8] == 0x7e
length = data[9]
payload = data[10:10 + length]
received_crc = data[10 + length]

def crc8(buf):
    crc = 0
    for byte in buf:
        crc ^= byte
        for _ in range(8):
            crc = ((crc << 1) ^ (0x07 if crc & 0x80 else 0)) & 0xff
    return crc

calculated_crc = crc8(data[9:10 + length])
assert received_crc == calculated_crc
print('Length:', length)
print('CRC:', hex(received_crc))
print('Flag:', payload.decode('ascii'))
```

The decoder returned a 48-byte payload with CRC `0x37`, followed by the flag below.

## Flag

```text
CSCTF{telltale_05c3394a279a6cd9108388d5f1d45036}
```
