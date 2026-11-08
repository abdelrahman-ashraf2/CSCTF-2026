# Telltale

**Category:** Misc

## Solution

1. I inspected `telltale(1).wav`, a mono 16-bit capture at `48,000 Hz`. It recorded an LED through a photodiode; the active signal ran from about `0.250 s` to `0.722 s`.
2. I measured 24 samples per half-bit. That is `0.5 ms`, giving Manchester data at `1,000 bits/s`. In this capture, low-to-high meant `1` and high-to-low meant `0`.
3. I started at sample `12000`, compared the mean amplitude of each half-bit while skipping transition edges, and packed the bits MSB first. The 472 bits formed a 59-byte frame:

   | Field | Recorded value |
   |---|---|
   | Preamble | Eight `0xAA` bytes |
   | Sync | `0x7E` |
   | Length | `0x30` = 48 bytes |
   | Payload | The 48-byte ASCII flag |
   | CRC | `0x37` |

4. I checked CRC-8 over the length byte followed by the payload, using polynomial `0x07`, initial value `0x00`, no reflection, and no final XOR. Recalculating it from the saved payload gives `0x37`.
5. I read the ASCII payload as the flag below.

## Flag

```text
CSCTF{telltale_05c3394a279a6cd9108388d5f1d45036}
```

> **Note:** I rechecked the saved payload length and CRC. The original WAV is absent, so I could not independently verify the waveform, timing, or decoded frame.
