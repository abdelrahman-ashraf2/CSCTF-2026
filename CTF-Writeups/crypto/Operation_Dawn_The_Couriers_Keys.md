# Operation Dawn: The Courier's Keys — Chronos Security CTF

## Introduction

The capture for this challenge holds a plain-text fleet provisioning protocol: a broadcast describing how each field unit derives its RSA keypair on power-up, nine units registering their moduli, and one encrypted `ORDER` addressed to unit 6631. The goal is to reconstruct that unit's private key purely from public information in the capture and decrypt the order. The protocol broadcast hands over the entire key-derivation recipe in the clear, which is the whole premise — this isn't a cryptographic weakness in RSA itself, it's a weak, fully-observable source of entropy behind the key generation.

## Initial Reconnaissance

A `scapy` survey, followed by a raw payload dump, showed 86 packets of mixed traffic — ARP chatter, DNS lookups, HTTP to `system.terminal43.ro`, ICMP echoes — wrapped around a small UDP broadcast protocol:

```
[  1] ts=1699989988 UDP broadcast  payload=b'ASH ARMY KEY UNIT :: provisioning profile...'
[  5] ts=1699990195 REG serial=4391 Nbits=1024   (+ ACK from the key unit)
[ 53] ts=1699994071 REG serial=6631 Nbits=1024
[ 83] ts=1699996000 ORDER serial=6631 C=42c2b662d2c1e70d...   (1023-bit ciphertext)
```

The `PROFILE` broadcast is the crux of the whole challenge:

```
ASH ARMY KEY UNIT :: provisioning profile
on power-up each set derives its key from the boot clock and its set serial:
  seed = (power_up_epoch_seconds << 16) | serial
  generator = MT19937 seeded with that value
  draw two 512-bit primes in turn: take a 512-bit candidate with top and bottom
  bits set, keep the first that is prime; these are p then q
  modulus N = p * q, public exponent 65537
```

So each unit's keypair is entirely determined by one unknown value: its power-up epoch `T`. Given a registered modulus `N` (sent in the clear in every `REG`), the attack is to guess `T`, regenerate `p` from the resulting MT19937 stream, and test `N mod p == 0`.

Two timestamps anchor the scenario's "story": ICMP payloads begin with `3f 98 cf 6a` (little-endian `0x6ACF983F = 1791989823`), and the HTTP response carries `Date: Wed, 14 Oct 2026 14:57:03 GMT` — the same epoch, 2026-10-14. But the capture's own packet timestamps run through late 2023 (`1699989962 → 1699996099`). That mismatch looked deliberate: one of the two timelines is a decoy, and figuring out which one actually anchors the seed became the central question.

## Investigation

**Hypothesis 1 — a single fleet-wide boot epoch.** My first solver assumed a simultaneous cold start, seeded with both the story time and the capture timestamps, then widened to ±24h windows around each. It screened embedded anchors first (HTTP epoch, ICMP epoch, first-packet and first-`REG` timestamps ±30s), then brute-forced with `random.Random(seed)` (CPython's MT19937) at roughly 400 epochs/sec across two processes:

```
[quick] no hit among embedded timestamps
[py story-1h window]  nothing in [1791986223, 1791993423) (18.3s)
[py story-24h window] nothing in [1791903423, 1791993423) (226.3s)
[py capture-24h window] 48000 epochs tried, 385/s, elapsed 125s
[log ends here]
```

Nothing. Two flaws only became visible in hindsight: the fleet-wide-cold-start assumption itself was wrong, and my capture-side search window stopped at the first `REG` packet's timestamp — but unit 6631's true epoch actually sits about 64 minutes *after* that packet.

**Hypothesis 2 — the author's RNG usage differs from my model.** The profile text is ambiguous in ways that change the actual byte stream: does "seeded with that value" mean CPython's `random.Random` (which converts an integer seed into a key array via `init_by_array`) or the classic single-word `init_genrand`? And is the candidate masked by forcing the top/bottom bits (V1), redrawn until the bits happen to be set (V2), forced with two top bits (V3), or found via `nextprime` (V4)? I encoded a 2×5 matrix of these choices and wrote a smoke test that synthesizes a modulus from a known `T` for every combination, confirming the checker recovers exactly that `T` in each case. All combinations passed self-test, but raw Python speed (~700/sec) remained the actual bottleneck.

**Hypothesis 3 — remove primality testing from the hot loop entirely.** A C searcher (GMP + OpenMP) rests on one observation: since `N = p·q` with both factors 512 bits, the *only* 512-bit divisors of `N` are `p` and `q` themselves. There's no need to test primality for each candidate at all — just compute `N mod candidate` and stop at the first zero, which is roughly 10× cheaper per candidate than Miller–Rabin. The tool also had to encode two details that silently break a naive reimplementation: CPython's `getrandbits(512)` consumes words least-significant-first, and `init_by_array` keys on the little-endian base-2³² words of the 48-bit seed. One honest note: I'd written a small-prime sieve plus a Horner-style filter into the tool as a pre-filter, expecting it to matter for performance, but the raw mod-check loop turned out fast enough on its own that the filter never actually ran.

Before trusting the searcher with a real campaign, a validation script synthesized moduli from a known epoch across seven authoring-style variants and required the searcher to recover exactly that epoch in every case:

```
OK   force-bits / random.Random                    hits at T=[1791970000]
OK   top-two-bits / random.Random                  hits at T=[1791970000]
OK   nextprime    / random.Random                  hits at T=[1791970000]
OK   force-bits / init_genrand                     hits at T=[1791970000]
[...]
ALL OK
```

**The campaign.** Staged in increasing cost:

- **Stage 1, residue sweep:** for `init_genrand` and single-word `init_by_array` seedings, the effective seed is `((T & 0xFFFF) << 16) | serial` — only the low 16 bits of `T` matter, so sweeping `T ∈ [0, 65536)` covers every possible epoch under those seedings at once. Both came back `hits=0`, eliminating them entirely.
- **Stage 2, targeted probes:** ±6 seconds around candidate epochs — round-number epochs, both decoy anchors, and each unit's own `REG` packet timestamp.
- **Stages 3–7, wide sweeps** (±24h/±60d/±365d) staged behind the targeted probes, never actually needed.

The hit landed at stage 2, on the probe built from serial 6631's own registration packet (`ts 1699994071`):

```
!!!! HIT in s2_p1699994070_byarr_m1:
HIT mode=m1 seeding=byarr T=1699994067 draw=116 c=c3d9a5055380fcec...b0600d5a [trimmed]
```

The interpretation that fell out of this: units boot *individually*, roughly 4–5 seconds before their own registration hits the wire — not as one synchronized fleet. The 2026 ICMP/HTTP timestamps were decoys set against the capture's real 2023 timeline, and the "fleet-wide epoch" assumption from Hypothesis 1 was the actual mistake, not the RNG model or the primality shortcut. Candidate draw #116 of the prime stream is unremarkable on its own — the expected gap between primes near 2⁵¹² is `ln(2⁵¹²) ≈ 355` candidates, so landing well inside that range isn't suspicious.

## Exploitation

With `T = 1699994067` in hand, the final script regenerated the keypair via `random.Random((T << 16) | 6631)`, asserted `p*q == N` against the registered modulus, and decrypted with `d = 65537⁻¹ mod (p−1)(q−1)`:

```
seeding=byarr variant=V1 epoch=1699994067
target serial 6631: p*q == N  OK
  serial  1983: p*q == N  OK  (boot=1699995356)
  serial  3263: p*q == N  OK  (boot=1699991911)
  serial  4391: p*q == N  OK  (boot=1699990191)
  serial  7318: no boot found in delta scan (not needed for decryption)
  serial  7805: p*q == N  OK  (boot=1699994411)
  serial  9668: p*q == N  OK  (boot=1699990866)
[...]
raw block: b'\x00'*96 + b'CSCTF{01_advance_on_the_mill_a7c3f1}'
```

Six of the nine registered units verified against boot epochs found within ±10 seconds of their own `REG` timestamps — independent corroboration that the per-unit model, not the fleet-wide one, is what the author actually implemented. The plaintext is unpadded textbook RSA (96 leading zero bytes followed by ASCII; the code path for PKCS#1 type-2 padding never triggered), and the recovered text lands directly in flag format.

## Root Cause

1. **The RSA keypair's entire entropy reduces to one 32-bit-ish unknown — the unit's own boot epoch** — once seeded, MT19937 and the deterministic prime-selection rule produce the same keypair every time. This is a textbook weak-randomness-source failure, not a flaw in RSA itself.
2. **Treating the fleet as one synchronized cold start was the actual modeling mistake in my own first attempt**, not a flaw in the challenge: per-unit boot events (visible in the capture's own `REG` timestamps) bound each unit's seed search to a handful of seconds, while a fleet-wide assumption searches a calendar range for no reason.
3. **Decoy timestamps embedded in unrelated protocol traffic (ICMP, HTTP headers) are a deliberate distraction**, not a vulnerability — the capture's own internal chronology (packet and `REG` timestamps) was the trustworthy source throughout.

## Validation

**What was confirmed in testing:**
- The MT19937-seeded, two-prime key derivation self-tests correctly across seven authoring-style variants (seeding function × bit-masking rule) when synthesizing from a known epoch.
- The residue-sweep stage conclusively eliminates `init_genrand` and single-word `init_by_array` seedings across the full possible range of `T mod 65536`.
- A hit at `T = 1699994067` (via `init_by_array`, force-bits masking) factors the registered modulus for unit 6631 exactly (`p*q == N`).
- Six of the other eight registered units in the capture also factor cleanly against boot epochs found independently within ±10 seconds of their own `REG` packet timestamps.
- The decrypted ORDER ciphertext, under `d` derived from the recovered `p, q`, yields unpadded textbook-RSA plaintext in exact `CSCTF{...}` format.

**What was not confirmed in my own session, and must not be claimed:**
- Serial 7318's boot epoch was not found in the delta scan; this wasn't pursued further since it wasn't needed for the target decryption, so I have no independent confirmation for that unit specifically.

## Conclusion

The actual break here is a weak-entropy RSA key derivation: once the provisioning broadcast reveals that each unit's keypair is a pure function of its boot-time epoch and serial, the only remaining work is bounding the epoch search space tightly enough to be practical and removing primality testing from the hot loop by exploiting the fact that a 512-bit factor of an N with two 512-bit primes must be one of them. The costliest mistake wasn't cryptographic at all — it was modeling the fleet as one synchronized cold start, when the capture's own registration timestamps show each unit booting independently just seconds before registering.

## Flag

```
CSCTF{01_advance_on_the_mill_a7c3f1}
```
