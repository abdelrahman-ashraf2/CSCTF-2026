# Emanation — Chronos Security CTF

## Introduction

The handout is a synthetic side-channel corpus: 8,000 known plaintexts and one 56-sample power trace per plaintext, plus a 43-byte ciphertext encrypted under the same AES-128 key in CTR mode with an all-zero counter. The README states the traces follow a Hamming-weight leakage-plus-noise model, with the device's countermeasures intact — a modeled random delay and a fresh byte mask per row. The goal is to recover the first-round key from the traces and decrypt the sealed order. This is a standard masked-AES side-channel attack in structure, but it took a wrong turn or two before the second-order approach actually worked.

## Initial Reconnaissance

One honest note before anything else: the archive's SHA-256 (`093731…`) didn't match the value in the challenge listing (`f1d1fe…`), most likely from re-compression before upload. The contents matched the stated description, so I proceeded anyway rather than treating the mismatch as a blocker.

A first recon pass printed per-sample statistics and a diagnostic correlation of every trace sample against the Hamming weight (HW) of each known plaintext byte:

```
samples 0–16 : std ~6.0, mean rising 1.5 → 3.2
samples 17–51: std ~2.4, mean declining
samples 52–55: std ~1.0, mean ~0      (pure noise)
corr(sample, HW(pt byte)): all ≤ 0.034
```

Two things followed. First, nothing correlates with `HW(pt)` column-wise — expected, since plaintext HW is key-independent anyway; this check mainly showed where activity sits in the trace. Second, the means are smeared across columns rather than sitting at fixed positions, suggesting a per-trace random delay was misaligning everything. Looking at three raw traces confirmed it directly: each starts with a single spike of roughly 25 amplitude, but the spike lands at a different sample index per trace (sample 0 in trace 0, sample 13 in trace 2).

## Investigation

**Hypothesis 1 — the head spike is a delay marker.** It's constant in amplitude (mean 25.01, std 1.01) and its position varies over 0–16:

```
head-spike positions histogram (delays 0..16):
[480 453 483 464 447 442 453 444 470 476 500 484 460 459 490 477 518]
```

Aligning every trace by shifting left by its own argmax position cleaned the profile up considerably: pure noise everywhere except 17 active samples at odd positions 3–35, each with std ≈ 1.71–1.76 against a noise baseline of std ≈ 1.0.

**Hypothesis 2 — standard first-order CPA should now work.** I ran column-wise correlation power analysis against both natural first-round intermediates — `HW(pt ⊕ k)` (S-box input) and `HW(SBox(pt ⊕ k))` (S-box output) — across all 256 key candidates and all 56 samples:

```
byte  0: k=60 max|corr|=0.042   (HW(pt^k))
byte  0: k=f5 max|corr|=0.043   (HW(SBox(pt^k)))
...
all 16 bytes in both families: 0.038 – 0.048
```

That's exactly the noise floor you'd expect by chance with 8,000 traces and 256 hypotheses (roughly 0.045). Both standard first-order intermediates failed completely — which ruled out unmasked leakage and pointed squarely at the stated byte mask.

**Hypothesis 3 — the leak is `HW(v ⊕ m)` and the mask itself leaks somewhere.** Forensic analysis of the aligned traces made this precise:

```
active odd samples 3,5,...,35: mean ≈ 4.00, std ≈ 1.73   (each)
sample 0:                     mean = 25.007              (delay marker)
cross-correlation among the 17 active samples: all |c| < 0.05
per-plaintext-bit mean shift at active samples: ≤ 0.13    (noise floor)
```

A mean of exactly 4.0 is the mean Hamming weight of a uniform byte, and a std of 1.73 is almost exactly `√(Var(HW)=2 + unit_noise=1)`. Mutually uncorrelated and plaintext-independent means each active sample is the HW of a byte that's uniform regardless of the key — the fingerprint of `HW(v ⊕ m)` with a fresh per-row mask. With 17 active samples against 16 S-box outputs, one sample has to be leaking the shared per-row mask itself. Under that model, the second-order centered-product combination

```
E[(HW(v⊕m) − 4)(HW(m) − 3.5) · HW(v)]  =  E[(HW(m)−3.5)(2 − 0.5·HW(m))]  =  −2
```

is provably nonzero, which is what makes a centered-product CPA over sample pairs viable. [CONFIRM — not derived on paper first]: I went straight from this algebra to scanning the real corpus rather than verifying the expectation on a simulated dataset first; the derivation is sound on its own terms, but I don't have an independent simulation confirming it before applying it live.

## Exploitation

The attack (`emanation_cpa2o.py`): align as above, take the 17 active columns standardized to zero mean and unit variance, and for each key byte scan every ordered pair of active positions, correlating the centered product with `HW(SBox(pt ⊕ k))` for all 256 keys:

```python
head = tr.argmax(axis=1)                  # delay marker position
al = np.zeros_like(tr)
for i, d in enumerate(head):
    al[i, :S - d] = tr[i, d:]
active = np.arange(3, 37, 2)              # 17 leaky columns
Xn = (al[:, active] - al[:, active].mean(0)) / al[:, active].std(0)
kk = np.arange(256)[:, None, None]
H = HW[SBOX[np.bitwise_xor(pt[None, :, :], kk)]]     # HW(SBox(pt^k))
for j in range(16):
    for a in range(17):
        for b in range(17):
            if a == b: continue
            Z = Xn[:, a] * Xn[:, b]                 # centered product
            corr = H[:, :, j] @ (Z - Z.mean())      # vs all 256 keys
            # keep the best |corr| over (a, b, k)
```

Every byte's best-scoring pair landed on the same structural pattern — sample 3 paired with that byte's own dedicated position:

```
byte  0: k=52 |corr|=0.075 pair=(3,5)     byte  8: k=66 |corr|=0.090 pair=(3,21)
byte  1: k=cc |corr|=0.085 pair=(3,7)     byte  9: k=e3 |corr|=0.078 pair=(3,23)
byte  2: k=11 |corr|=0.079 pair=(3,9)     byte 10: k=34 |corr|=0.078 pair=(3,25)
byte  3: k=fc |corr|=0.061 pair=(3,11)    byte 11: k=9f |corr|=0.081 pair=(3,27)
byte  4: k=4a |corr|=0.090 pair=(3,13)    byte 12: k=4a |corr|=0.062 pair=(3,29)
byte  5: k=2e |corr|=0.089 pair=(3,15)    byte 13: k=f9 |corr|=0.077 pair=(3,31)
byte  6: k=cf |corr|=0.097 pair=(3,17)    byte 14: k=fd |corr|=0.094 pair=(3,33)
byte  7: k=c0 |corr|=0.071 pair=(3,19)    byte 15: k=ea |corr|=0.069 pair=(3,35)
key candidate = 52cc11fc4a2ecfc066e3349f4af9fdea
```

The correlations themselves are modest (0.06–0.10), so I treated this as a candidate, not a confirmed key, on the strength of the correlation values alone. The structural pattern is the stronger evidence: sample 3 consistently acting as the mask leak, samples 5–35 mapping cleanly to key bytes 0–15 in order, and 16 independently-attacked bytes converging on the same pairing scheme isn't something that happens by chance. I only ran the S-box-*output* family for the second-order attack (not the input family) since it produced this consistent pattern immediately, and validated the result directly rather than also scanning the alternative family.

**Validation was the CTR decryption** (`emanation_trykey.py`), using `pycryptodome`'s AES-ECB as the keystream core with a big-endian 128-bit counter starting at zero:

```python
aes = AES.new(key, AES.MODE_ECB)
ks = aes.encrypt(blk.to_bytes(16, 'big'))
plain = bytes(c ^ k for c, k in zip(ct, ks))
```

```
ct len 43
key 52cc11fc4a2ecfc066e3349f4af9fdea: printable 43/43  -> b'CSCTF{relay_order_55a10bd8f06393bcc1ae8065}'
```

The first and only key candidate produced fully printable output in correct flag format — the decryption itself is what confirmed the key, not the correlation magnitudes alone.

## Root Cause

1. **First-order masking is defeated the moment any leak of the mask exists anywhere in the trace** — the design intends `HW(v ⊕ m)` to hide `v` completely at first order, and it does, but the extra 17th active sample leaking `HW(m)` directly reopens the attack at second order.
2. **The countermeasure (random delay) only protects against misalignment, not against the underlying leakage model** — once traces are aligned by their own delay marker, the masking scheme's actual weakness (a leaking mask) is fully exposed.

## Validation

**What was confirmed in testing:**
- Raw traces carry a constant-amplitude delay marker (mean ≈ 25, std ≈ 1.01) at a variable position; aligning by its argmax collapses the smeared first-order statistics into 17 clean active columns.
- Standard first-order CPA against both `HW(pt⊕k)` and `HW(SBox(pt⊕k))` tops out at the expected noise floor (~0.045) for all 16 bytes, confirming no first-order leak is exploitable.
- The 17 active columns have mean ≈ 4.00 and std ≈ 1.73 each, mutually uncorrelated and plaintext-bit-independent — consistent with `HW(v⊕m)` under a uniform mask.
- A second-order centered-product CPA recovers all 16 key bytes with a consistent pairing structure (sample 3 against each byte's dedicated position).
- The resulting 16-byte key, used as an AES-128-ECB keystream generator in CTR mode (zero counter), decrypts the 43-byte sealed ciphertext to fully printable, flag-formatted ASCII.

**What was not confirmed in my own session, and must not be claimed:**
- The nonzero-expectation derivation for the second-order centered product was not verified against a separate simulated dataset before being applied to the real corpus — only the algebra and the final decryption confirm it, not an intermediate simulation check.
- The archive's published SHA-256 does not match the hash I computed on download; I proceeded on the basis that the contents matched the stated description, but did not resolve the discrepancy itself.

## Exploitation note on confidence

Peak correlation height alone was not treated as sufficient evidence here — a ρ ≈ 0.08 second-order peak is unremarkable in isolation. What made the result trustworthy was the consensus pairing pattern holding across all 16 independently-attacked bytes, followed by a clean, fully printable CTR decryption.

## Conclusion

The chain was: align traces using a deliberate timing marker, rule out first-order leakage decisively, recognize the `HW(v⊕m)` signature from the active samples' statistics, locate the shared mask's own leak by counting active positions against expected intermediates, and recover the key with a second-order centered-product attack. The peak correlations alone (0.06–0.10) would not have been convincing on their own — it was the consistent structural agreement across 16 bytes, confirmed by a clean decryption, that made this a real result rather than a coincidental fit.

## Flag

```
CSCTF{relay_order_55a10bd8f06393bcc1ae8065}
```
