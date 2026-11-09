# Rollback Pair — Chronos Security CTF

## Introduction

The export for this challenge contains a secp256k1 public key and eight ECDSA-signed dispatch records, each a base64 message with a raw `r‖s` signature. The scenario note says the signer "resumed from a faulty application nonce-state snapshot" — which, if you've seen this class of bug before, is basically an announcement that somewhere in those eight signatures, the same nonce got reused. The goal was to determine whether the private key was actually exposed and, if so, recover it.

## Initial Reconnaissance

For each record I decoded `message_b64`, split `signature_rs_hex` into two 32-byte big-endian integers, and hashed the decoded message with SHA-256 to get `z`:

```python
msg = base64.b64decode(r['message_b64'])
sig = bytes.fromhex(r['signature_rs_hex'])
rr = int.from_bytes(sig[:32], 'big')
ss = int.from_bytes(sig[32:64], 'big')
z = int.from_bytes(hashlib.sha256(msg).digest(), 'big')
```

Every signature was exactly 64 bytes — plain `r‖s`, no DER wrapper, no trailing bytes, matching the stated `signature_format`. Confirming that up front ruled out a parsing-format issue before looking at the actual values.

## Investigation

The "faulty nonce-state snapshot" line was the only real hint in the scenario, so the working hypothesis was nonce (`k`) reuse: in ECDSA, `r` is the x-coordinate of `k·G mod n`, so two signatures sharing the same `r` almost certainly used the same `k`. Grouping all eight records by `r` found exactly one collision:

```
Reused-r groups: 1
group ids: ['R-6103', 'R-6107']  r = 0x821f300799a645e288df87f4e1913c60606c13aa50cae4804a375890887b4f4a
```

All six other `r` values were distinct. That confirmed the hypothesis — only this one pair was exploitable, but a single colliding pair is all that's needed for a full key recovery.

With the same `k` behind both signatures, standard algebra gives:

```
s1 = k^-1 (z1 + r·d)   mod n
s2 = k^-1 (z2 + r·d)   mod n
k  = (z1 - z2) · (s1 - s2)^-1   mod n
d  = (s1·k - z1) · r^-1         mod n
```

```python
k = ((z1 - z2) % n) * inv((s1 - s2) % n, n) % n
d = ((s1 * k - z1) % n) * inv(r % n, n) % n
```

```
pair R-6103,R-6107 -> k=0xd12e52720675d17d57136b691ef6abb6fa90116527022ef1a76be7503b0c2049
                       d=0x3b5789e468dadf358d375bb08dcd19b977c5715364a709326b43a35b0d5eaab1
```

**A mistake, and where it actually was.** Computing `d·G` with my own double-and-add implementation didn't match the published public key, and the standard ECDSA verify equation failed for every record too. The recovery formula is textbook, so my first instinct was to suspect the curve constants I'd typed in by hand rather than the math itself. I checked whether the published public key satisfies `y² ≡ x³ + 7 (mod p)` — it did — then ran the same check on my hardcoded generator point `G`:

```
on curve? True      # published pubkey
G on curve? False   # my hardcoded G
```

`G` failing its own curve equation meant the constant itself was wrong, not the attack. Comparing it against the standard secp256k1 generator, my `Gy` was missing its trailing hex digit — `...FFB10D4B` instead of `...FFB10D4B8`, a plain transcription slip when typing the constants by hand. After correcting it:

```
G on curve? True
Computed pubkey from d: 0xed479d884711fbf4a1772073d051f6a78818ed8506eeb278c13b936cac50ce7b
                         0xca77b859dfdc23e8f40ca4b2a9698dc49588c9fdb4d153fe5ed1c91004462874
Given pubkey x,y:        0xed479d884711fbf4a1772073d051f6a78818ed8506eeb278c13b936cac50ce7b
                         0xca77b859dfdc23e8f40ca4b2a9698dc49588c9fdb4d153fe5ed1c91004462874
match x? True  match y? True
```

## Exploitation

With `G` corrected, `d·G` reproduces the published public key exactly. As a stronger check than matching the one colliding pair, I ran the standard ECDSA verify equation for all eight records — not just the two used to derive the key — against the published public key:

```
R-6101 True
R-6102 True
R-6103 True
R-6104 True
R-6105 True
R-6106 True
R-6107 True
R-6108 True
ALL VALID: True
```

All eight verifying confirms the published key is genuine and that the recovered scalar is the real private key behind every signature in the export, not merely an artifact that happens to fit the two colliding signatures. I did not independently verify the key against anything outside this export (there was no live signing service to check it against); acceptance here is based on internal consistency across all eight signatures, which is a strong signal but not an external oracle.

Final scalar, zero-padded to 64 hex characters:

```python
format(d % n, '064x')
# 3b5789e468dadf358d375bb08dcd19b977c5715364a709326b43a35b0d5eaab1
```

## Root Cause

1. **Nonce reuse across two ECDSA signatures is a complete key-recovery vulnerability**, not a partial weakness — this follows directly from the algebra, and it's catastrophic the moment it happens even once.
2. **A faulty "nonce-state snapshot" being restorable/resumable is the design flaw** that produced the reuse in the scenario's framing; ECDSA itself has no tolerance for a repeated nonce, which is a property of the algorithm, not a bug that could be patched within ECDSA — the fix has to be at the nonce-generation layer (e.g., deterministic nonces per RFC 6979, or never persisting/restoring nonce state at all).

## Validation

**What was confirmed in testing:**
- All eight signatures parse as plain 64-byte `r‖s` pairs with no DER wrapper, matching the stated format.
- Exactly one pair of records (`R-6103`, `R-6107`) shares an identical `r` value; all other six `r` values are distinct.
- The nonce-reuse recovery formula applied to that pair yields a private key `d` whose public point `d·G` matches the challenge's published public key exactly (both x and y coordinates).
- All eight signatures in the export verify correctly against the recovered key using the standard ECDSA verification equation.

**What was not confirmed in my own session, and must not be claimed:**
- There was no live signing or scoring service to check the recovered key against outside the export itself; confirmation rests on internal consistency (all eight signatures verifying), not an external oracle.

## Conclusion

The actual cryptographic break here was a one-step nonce-reuse recovery — the kind of bug that's catastrophic specifically because it needs only two signatures, not a large corpus. The real time sink in this solve wasn't the math; it was a mistyped hex digit in my own hardcoded generator point, which silently broke every point multiplication and made a completely correct key-recovery formula look like it had failed. Checking the curve equation against both the published key and my own constants is what separated "the attack is wrong" from "my code is wrong" — worth doing early next time rather than last.

## Flag

```
CSCTF{3b5789e468dadf358d375bb08dcd19b977c5715364a709326b43a35b0d5eaab1}
```
