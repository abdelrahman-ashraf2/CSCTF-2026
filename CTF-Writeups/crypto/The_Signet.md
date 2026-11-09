# Two-Key Turn — Chronos Security CTF

## Introduction

Two artifacts: `sealed-orders.der` (1,042 bytes), a DER `SignetBundle` holding a secp256k1 public key, six ECDSA signatures, and one AES-256-GCM sealed order; and `case-note.txt`, a plain-text note describing an entropy fault — each signing operation `i` consumed a nonce `k_i = start + i·stride (mod n)`, with `start` and `stride` unlogged. The goal is the plaintext of the sealed order. The note does essentially all of the "discovery" work for you; the actual task is implementing the recovery correctly and proving the result is real before trusting it with a decryption key.

## Initial Reconnaissance

The case note laid out every fact that mattered:

- A trusted fingerprint pins the signer: SPKI SHA-256 `1c6b38a8...a6b3`, taken from a pre-incident key register.
- Hash inputs are the exact message OCTET STRING bytes: `z_i = int_be(SHA-256(message_i)) mod n`. Signatures carry raw issuer `s` values — no low-s rewrite — so no normalization is needed, or allowed.
- The sealed order's key is the private key itself: `IKM = I2OSP(d, 32)`, then `HKDF-SHA-256(IKM, salt, info, L=32)`, then AES-256-GCM with the seal's 12-byte nonce and a separate 16-byte tag, empty AAD.

So the chain was fixed from the start: recover `d` from the six signatures, derive the key, decrypt. I confirmed the environment first (`cryptography` 44.0.3 and `pycryptodome` 3.23.0 were both available), and since `xxd` wasn't installed, I printed the raw bytes directly in Python:

```python
>>> len(data); data[:32].hex(' ')
1042
30 82 04 0e 02 01 01 30 56 30 10 06 07 2a 86 48 ce 3d 02 01 06 05 2b 81 04 00 0a 03 42 00 04 46 ab ...
```

That's a standard SPKI: `id-ecPublicKey` (1.2.840.10045.2.1), secp256k1 (1.3.132.0.10), uncompressed point.

## Investigation

**Turning the entropy fault into linear algebra.** ECDSA signing satisfies `s·k ≡ z + r·d (mod n)`. Substituting the stated fault model `k_i = a + i·b` turns every signature into one linear equation over `GF(n)`:

```
s_i·a + (i·s_i)·b − r_i·d ≡ z_i   (mod n)
```

Three unknowns (`a`, `b`, `d`), six equations. I used full Gaussian elimination over any three independent rows rather than pairwise elimination, because `n` (the secp256k1 group order) is prime, so elimination yields a unique solution and the remaining three rows over-determine the system — a free consistency check built into the method itself. Brute-forcing a 256-bit `start`/`stride` was never on the table.

**A real dead end: a hand-rolled DER parser.** I wrote a minimal TLV parser instead of pulling in `pyasn1`, and it cost three failed runs before I got the data model right:

```
Line 71 in <module>: IndexError ... read_tlv(alg_body, 0)      # run 1
Line 71 in <module>: IndexError ... read_tlv(alg_content, o2)  # run 2, one level deeper
AssertionError  (expected tag 0x04, len 16 for the seal salt)  # run 3
```

`read_tlv` returns `(tag, content, raw_tlv, next_offset)`, and in several call sites I unpacked it as if the second element were the raw TLV bytes rather than just the content — so every subsequent read started one DER nesting level too deep. A step-by-step recursive dump of the whole structure made the mistake visible immediately: what I thought was the SPKI body came back as just the 16-byte OID blob. After settling on the correct 4-tuple contract consistently, a ~20-line recursive dump resolved the full tree in one shot — SignedOrder sequences each containing a readable ASCII dispatch message and an ECDSA-Sig-Value (`r`, `s`), followed by a SealedOrder sequence (salt, nonce, ciphertext, tag). The messages themselves are plain-text dispatch strings ("Dispatch 01 | canal watch | ..."), confirming the hashing rule operates on the exact message bytes with no re-rendering.

## Exploitation

The equations, one row per signature, indexed by the signature's own sequence number:

```python
for o in orders:
    z = int.from_bytes(hashlib.sha256(o['message']).digest(), 'big') % N
    i = o['seq']
    rows.append([o['s'] % N, (i * o['s']) % N, (-o['r']) % N, z])   # [a, b, d | z]
```

Gaussian elimination over `GF(n)`, normalizing each pivot with a modular inverse, eliminating above and below, and requiring the surplus rows to reduce to zero:

```python
for col in range(3):
    sel = next((r for r in range(piv_row, len(M)) if M[r][col] % N != 0), None)
    M[piv_row], M[sel] = M[sel], M[piv_row]
    inv = pow(M[piv_row][col], -1, N)
    M[piv_row] = [(v * inv) % N for v in M[piv_row]]
    for r in range(len(M)):
        if r != piv_row and M[r][col] % N:
            f = M[r][col]
            M[r] = [(M[r][c] - f * M[piv_row][c]) % N for c in range(4)]
    piv_row += 1
start, stride, d = (M[c][3] % N for c in range(3))
assert all(v % N == 0 for row in M[3:] for v in row), "inconsistent system"
```

I verified the result three independent ways before trusting it enough to derive a decryption key from it: the stride model reproduces all six signatures (`s_i·k_i ≡ z_i + r_i·d` with `k_i = a + i·b`); `d·G` equals the uncompressed point in the SPKI, whose SHA-256 matches the trusted register fingerprint; and each `(r, s)` passes textbook verification against `Q = dG` using raw (non-normalized) `s` values. The final run:

```
[SPKI] SHA-256 = 1c6b38a86c3ff8b1d295e02b884c457da537767b5fdf063cf6d7d733b683a6b3
[SPKI] fingerprint match: True
[seal] salt=539563c83bc068e2cf9b8cf38d7a0ca1 nonce=057f7d5692097c1ed13cc11f ct=54B tag=e7b13d777e62bcfaf8e4d59060d6ab06
[recovered] start  k0 = 0x1d91ccdfd95a3f14005cb9d9ec02bc63e8b23440666b29d10e909e6227c71440
[recovered] stride    = 0x4bf35d9d83234500d2c1518730bc89750a004e7cf611ea9dcd13051876dab69c
[recovered] privkey d = 0x79c7842bf8177446127be0061bfb456d8c99811601cf3f86187b1a3b45b59d8f
[check] all six stride-nonce equations consistent: OK
[check] d*G == SPKI point: True
[check] raw-s ECDSA verification per seq: [True, True, True, True, True, True]
```

**Decryption**, with HKDF implemented by hand (extract, then a single expand block since `L=32`) and AES-GCM via `pycryptodome`:

```python
ikm  = d.to_bytes(32, 'big')                          # I2OSP(d, 32)
info = b"CSCTF26/TheSignet/v1/standing-order"
prk  = hmac.new(salt_b, ikm, hashlib.sha256).digest()
key  = hmac.new(prk, info + b'\x01', hashlib.sha256).digest()[:32]
cipher = AES.new(key, AES.MODE_GCM, nonce=nonce_b)
plaintext = cipher.decrypt_and_verify(ct_b, tag_b)    # empty AAD
```

```
[HKDF] key=1e866b7bb372d0a0ad574ec35c23985f36e204c7c7b4f4f1e62a750d3cac96f4
[GCM] authentication: OK
=== RECOVERED TOKEN ===
CSCTF{canal_signet_recovered_2f17026a4a9c032f4ba186ab}
```

The GCM tag authenticating successfully is itself a strong piece of corroborating evidence, not just a success message — GCM fails closed on a wrong key, so a valid tag rules out an accidental near-miss anywhere upstream in the key-recovery chain.

## Root Cause

1. **A linear (arithmetic-progression) nonce fault is algebraically equivalent to full key exposure** given enough signatures — here, three unknowns and six equations made the system not just solvable but self-checking.
2. **The DER parsing bugs were tooling mistakes on my part, not properties of the challenge** — worth separating clearly: the challenge's cryptographic weakness is nonce-stride correlation; the time I lost was to a hand-rolled parser returning an inconsistent tuple shape across call sites.

## Validation

**What was confirmed in testing:**
- The six ECDSA signatures and the SealedOrder structure parse cleanly once the DER TLV contract is applied consistently.
- The linear system built from the stride fault model is consistent: three equations pin `start`, `stride`, `d`, and the remaining three rows reduce to zero exactly, as the over-determination predicts.
- `d·G` matches the uncompressed point encoded in the bundle's SPKI, and that SPKI's SHA-256 matches the trusted pre-incident fingerprint from the case note.
- All six signatures independently verify against `Q = d·G` using raw (non-low-s) `s` values.
- The HKDF-derived AES-256-GCM key authenticates the sealed ciphertext successfully (`decrypt_and_verify` completes without exception), and the plaintext is a well-formed UTF-8 flag string.

**What was not confirmed in my own session, and must not be claimed:**
- Nothing outstanding — every link in this chain (key recovery, fingerprint match, signature re-verification, and authenticated decryption) was independently checked within this session.

## Conclusion

The weakness here was structural rather than purely computational: signing nonces that follow a known arithmetic progression collapse ECDSA key recovery into a linear-algebra problem the moment you have enough samples, which is the same failure class behind several real-world signature incidents involving correlated or reused nonces. The part that actually slowed me down was unrelated to the cryptography — a hand-rolled DER parser whose return-value contract I didn't apply consistently across call sites, caught only by writing a full recursive structure dump instead of trying to patch individual offsets.

## Flag

```
CSCTF{canal_signet_recovered_2f17026a4a9c032f4ba186ab}
```
