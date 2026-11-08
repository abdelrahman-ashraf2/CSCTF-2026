# Tone Burst

**Category:** Forensics

## Solution

1. I inspected the WAV as a signal and found two tones near `1000 Hz` and `2000 Hz`, consistent with frequency-shift keying.
2. I used a `20 ms` window per bit and compared the energy around those two frequencies.
3. I tried both tone-to-bit mappings and adjusted the starting offset until the bytes formed readable text.
4. I decoded the bitstream into bytes and recovered the flag below.

## Flag

```text
CSCTF{tone_burst_4481dda445a0a227c3a8eb90fda4fd92}
```

> **Note:** The original WAV is absent. My notes preserve the tones and bit period, but not the exact successful polarity or start offset, so I could not reproduce the decoding byte for byte.
