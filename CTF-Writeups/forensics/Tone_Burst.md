# Tone Burst

**Category:** Forensics

## Solution

1. I inspected the WAV as a signal and found two tones around 1 kHz and 2 kHz. The recording used frequency-shift keying: the tone present during each interval carried a bit value.
2. I compared energy around those frequencies in 20 ms windows, which matched the bit period.
3. I tried both tone-to-bit mappings and adjusted the starting offset, then packed the resulting bits into bytes.
4. The decoded text contained the complete flag below.

## Flag

```text
CSCTF{tone_burst_4481dda445a0a227c3a8eb90fda4fd92}
```
