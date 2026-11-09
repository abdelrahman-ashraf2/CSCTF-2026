# The Key Wheel — Chronos Security CTF

## Introduction

A seized CBOR journal holds 1,248 consecutive 32-bit outputs from a unit's key-schedule register, plus five sealed dispatches. One of them — the standing order — was sealed *before* the recorded window begins. The task is to reconstruct the generator's earlier outputs and decrypt that one dispatch. The scheme needs no cryptanalysis once understood; the actual challenge is figuring out which PRNG produced the register, then running its recurrence backward to recover state the journal never recorded.

## Initial Reconnaissance

The CBOR parses into five fields:

```
device         : "ASH ARMY KEY UNIT v3  (seized; key-schedule journal)"
scheme         : "seal: TX t keys on register outputs [8*t, 8*t+8); key = concat
                  uint32be(word); ks = concat SHA-256(key || uint32be(i)) for i=0,1,..;
                  plain = ciphertext ^ ks"
window_opens_tx: 156
register       : 1,248 uint32 words
traffic        : 5 items
```

The traffic list pins the geometry down immediately: TX 156–161 are "field dispatch" items, and the standing order is `tx=155, sealed_len=42`. Since TX `t` keys on register words `[8*t, 8*t+8)`, and the journal's 1,248 words cover exactly 156 TXs starting at TX 156, `register[0]` corresponds to absolute word 1248 — so the standing order (TX 155) needs absolute words `[1240, 1248)`, i.e. the eight outputs immediately before the recorded window. That's what "predates the recorded output window" actually means here: a single key-window rewind, not an open-ended search.

## Investigation

**Which generator?** A related Ash Army challenge used MT19937, so that was the natural first guess — but the journal's register could just as easily be tempered outputs or raw state words, and those behave very differently. I tested both directly:

```
raw words as a state array satisfying the in-place twist: 0/624
endianness/byte-order variants: all 0/624
```

Neither matched. Untempering the words and checking the MT19937 recurrence `u[k+624] = u[k+397] ^ g((u[k] & 0x80000000) | (u[k+1] & 0x7fffffff))` across the window's two halves gave a strange 24/624 on the first attempt — far too many matches for pure chance (expected ~2⁻³² per word), but nowhere near a correct recurrence either. A roundtrip self-test against a reference generator found the cause: my untemper function applied a left-shift inverse to the `y ^= y >> 11` temper step, which actually needs a right-shift inverse, and the `>>18` inverse needs two iterations of the shift-XOR, not one. After fixing both:

```
untemper self-check vs reference generator: OK
MT19937 recurrence check over 624 in-window words: 624/624 ok
```

The register is confirmed, conclusively, as standard MT19937 tempered output.

**Validating the seal scheme on known plaintext.** Decrypting the four in-window dispatches with keys taken straight from the register:

```
tx=156: b"COVER TRAFFIC ONLY. the standing order went out one cycle before
        this journal's window opens; its key is not in this register.
        turn the key wheel back to read it."
tx=157: b'hold positions and keep to radio discipline until relieved'
tx=158: b'ration resupply reaches the forward line after dark'
tx=161: b'acknowledge all command traffic on the hour'
```

Four clean plaintexts confirmed both the alignment (`register[0] = word 1248`) and the seal construction itself. The cover message even states the intended attack outright — useful confirmation that I wasn't overthinking the scheme.

**Rewinding eight outputs with zero brute force.** The MT19937 recurrence solves backward deterministically. For step `k`, `z_k = u[k+624] ^ u[k+397] = g(y_k)` where `y_k = (u[k] & UP) | (u[k+1] & LOW)`. Since `g(y) = (y >> 1) ^ (MAG if y & 1)`, and `y >> 1` always has bit 31 clear while `MAG` always has bit 31 set, the branch bit is directly readable off `z`'s own top bit: `y_k & 1 = z_k >> 31`. That makes each backward step fully deterministic:

```python
z = U[k + 624] ^ U[k + 397]
b = z >> 31                                  # = y_k & 1 = u[k+1] & 1
y = (((z ^ (MAG if b else 0)) & 0x7FFFFFFF) << 1) | b
# y's bit31 = u[k]'s top bit, y's low31 = u[k+1]'s low 31 bits
```

Chaining `k = -1 … -9` recovers `u[-8] … u[-1]` — each word's top bit comes from its own step, its low 31 bits from the *next-earlier* step, which means the loop has to run one step past -8. I hit an off-by-one there (a `KeyError`) before realizing the loop bound was short by exactly one iteration. Two internal checks validated the backward machinery: step `k = -1` has to reproduce the already-known `u[0]` — both the branch bit (`b == U[0] & 1`) and the low-31-bit half matched.

**One more subtlety that cost a garbage decryption.** The recovered words are *untempered* state words, but the journal's actual key material is the *tempered* output stream — the in-window keys that decrypted cleanly used raw register values, which are tempered outputs, not internal state. Applying `temper()` to the eight recovered pre-window words before building the key fixed the decryption.

## Exploitation

```
MT19937 recurrence check over 624 in-window words: 624/624 ok
backward-step consistency vs window word u[0]: OK
recovered pre-window words (absolute 1240..1247, tempered):
  ['0x37ea0460', '0xe9b9d7fc', '0x8b1c2a45', '0x4f33e6f3',
   '0xe7f2f198', '0x313cf5d5', '0xe8f0c5ec', '0x480a2ab1']
standing order (TX 155):
  b'CSCTF{15_jam_the_enemy_net_at_dawn_7e2c04}'
```

The plaintext is exactly the 42 sealed bytes, fully printable, and lands directly in flag format — the clean decryption is itself the confirmation that the recovered key is correct, since a wrong keystream would produce garbage rather than a readable string.

## Root Cause

1. **The journal exposes 624 consecutive MT19937 outputs**, which is exactly a full internal state for that generator — MT19937's design means any 624-output window is sufficient to reconstruct the entire sequence, forward or backward, with zero brute force.
2. **Using a non-cryptographic PRNG to derive per-message keys at all is the actual design flaw**; MT19937 is explicitly not meant for this purpose, and its invertibility is a known, intended property of the algorithm rather than an implementation bug.

## Validation

**What was confirmed in testing:**
- The register's values satisfy the standard MT19937 twist recurrence across all 624 in-window words once untempering is corrected and self-tested against a reference generator.
- Decrypting the four in-window dispatches with keys taken directly from the register produces four clean, fully printable plaintexts, confirming both the seal construction and the register-to-TX alignment.
- The backward recurrence step at `k = -1` reproduces the known word `u[0]` exactly (both the branch bit and the low 31 bits).
- The eight recovered pre-window words, tempered and assembled into the TX 155 key, decrypt the standing order to a fully printable, flag-formatted string.

**What was not confirmed in my own session, and must not be claimed:**
- Nothing outstanding — the clean decryption of the standing order is direct, positive confirmation, not an inference from indirect evidence.

## Conclusion

The core insight was recognizing that 624 consecutive MT19937 outputs constitute the generator's entire state, which makes "recover outputs from before the recording started" a solved problem rather than a search. Most of the actual time in this solve went to two self-inflicted bugs — a wrong shift direction in my untemper function, and conflating tempered output with raw internal state when building the pre-window key — both of which were caught by comparing against a reference implementation rather than trusting my own first pass.

## Flag

```
CSCTF{15_jam_the_enemy_net_at_dawn_7e2c04}
```
