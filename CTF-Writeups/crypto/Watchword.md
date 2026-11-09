# Watchword — Chronos Security CTF


## Introduction

This handout puts you on the receiving end of a fictional "SABRELINK" fire-control net that authenticates every dispatch with AES-128-GCM. A firmware fault made the unit reuse one 96-bit nonce across three dispatches, and separately, a master order is sealed with AES-128-CTR (all-zero IV) under the per-nonce tag mask `E_K(J0)`. The zip contains a README and `intercepts.json`: three dispatches (plaintext, ciphertext, 16-byte GCM tag each, empty AAD) plus the sealed order. The master-order plaintext is the flag. The AES key itself is never needed anywhere in this attack, which is the whole point of the design flaw.

## Initial Reconnaissance

```console
$ sha256sum watchword.zip
1e081c278b16e265391a8c6cf68cf2787ff2e54aae574b6c2d1cf0cada02647e  watchword.zip
$ file watchword.zip
watchword.zip: Zip archive data, made by v2.0 UNIX, [...] method=deflate
$ unzip -o watchword.zip -d work/
```

The README spells out the mechanic directly: *"The authentication tags are the 'watchword.' The master order text is sealed with AES-128-CTR (IV all-zero) under the link's per-nonce tag mask E_K(J0) — the same value that lets the unit stamp a valid tag. Recover the master order text; the flag is that text."*

`intercepts.json` carries the traffic (link/cipher/note metadata trimmed here):

```json
{
  "nonce_hex": "8f7ce996b767134353fe1145",
  "intercepts": [
    {"dispatch_plaintext": "RELAY CHECK 0931",
     "ciphertext_hex": "051cf3d41191dbb609374f8f730f0b5d",
     "tag_hex": "667d34dba2febb36872ca5096adb86cd"},
    {"dispatch_plaintext": "HOLD STATION 07",
     "ciphertext_hex": "1f16f3d168e2ccbf183d4be163060f",
     "tag_hex": "dbaa4d5bbc022bb9f9a7873f8c0ec5fe"},
    {"dispatch_plaintext": "RESUME PATROL",
     "ciphertext_hex": "051cecc005f4b8ae0d2056e00f",
     "tag_hex": "da88d564995ba128364fdae29007888a"}
  ],
  "sealed_master_order_ctr_hex": "e7dc7dd519b3c637d69f6d95443d9ed1f81d3bfdd5f6524268920e03d030d99c1a0a5ae635f51eb7613b5a689d5614cc13812fa9cb13958ced"
}
```

Two observations shaped the plan: all three plaintexts are short enough (16, 15, and 13 bytes) that each ciphertext is a single padded GHASH block, which collapses GHASH from a general polynomial in `H` into a plain quadratic; and since the plaintexts are given, nonce reuse can be confirmed directly before touching anything related to authentication.

## Investigation

**1. Confirming the shared nonce via known plaintext.** For a 96-bit GCM nonce, `J0 = nonce || 0^31 || 1`, and encryption starts at counter `inc32(J0)` — so the first keystream block is identical across all three dispatches sharing that nonce. Testing it: `P0 ⊕ C0 = 5759bf9548b198fe4c7404af4336386c`, and the other two dispatches share the same prefix against this value. This confirmed the premise, but it was a deliberate dead end for the actual tag attack: `E_K(counter 2)` and `E_K(J0)` are independent AES outputs under the unknown key, so knowing the keystream tells me nothing about the tag mask. That had to come from the authentication side instead.

**2. Turning tag differences into solvable equations.** GCM computes `T = E_K(J0) ⊕ GHASH_H(A, C)` with `H = E_K(0^128)`; `GHASH` folds each 16-byte block into an accumulator via multiplication in `GF(2^128)` modulo `x^128 + x^7 + x^2 + x + 1`. With empty AAD and a single ciphertext block:

```
GHASH_H(C_i) = (C_i·H ⊕ L_i)·H = C_i·H² ⊕ L_i·H,   L_i = 0^64 || bitlen(C_i)_64
```

(bit lengths 128/120/104 for the three dispatches). Since the nonce repeats, `M := E_K(J0)` cancels out when two tags are XORed together, leaving one quadratic per pair `i < j`:

```
(C_i ⊕ C_j)·H² ⊕ (L_i ⊕ L_j)·H ⊕ (T_i ⊕ T_j) = 0
```

Three pairs give three quadratics over `GF(2^128)`. Rather than computing a GCD across them, substituting `H = (b/a)·X` (with `a = C_i⊕C_j`, `b = L_i⊕L_j`, `c = T_i⊕T_j`, both `a` and `b` nonzero since the dispatches differ in content and length) reduces each equation to:

```
X² ⊕ X ⊕ β = 0,   β = c·a/b²
```

which needs only a `GF(2)` *linear* solve. The map `X ↦ X²⊕X` has kernel `{0, 1}`, so each pair yields exactly two `H` candidates — solvable iff `Tr(β) = 0` — and intersecting the three candidate sets across all three pairs should leave exactly one true `H`.

**3. Validating the field implementation before trusting any of it.** GCM's bit convention is a well-known trap: the leftmost bit of a block (MSB of byte 0) is the coefficient of `x^0`, which is backwards from the usual reading. I handled this by bit-reversing every block into an integer, after which ordinary carry-less multiplication and reduction with `0x87` are correct. Since I worked this mapping out from memory rather than an open spec, I wrote a self-test before touching the real data: for random key/nonce/AAD/plaintext, recompute the tag as `E_K(J0) ⊕ GHASH_H` with my own code and compare against `pycryptodome`'s GCM output, plus rebuild the plaintext from the keystream separately. Three trials covered empty AAD, multi-block inputs, and partial final blocks. It printed `SELF-TEST: OK` on the first run — a bit-order bug here would otherwise have produced plausible-but-wrong equations that fail confusingly several steps downstream, not an obvious crash.

**4. Solving and intersecting.** `solve_xx_xor_beta` implements the linear solve: column `j` of the matrix is `L(e_j) = e_j² ⊕ e_j` for basis `e_j = x^j`, solved via Gaussian elimination over `GF(2)` (128 equations, one per output bit). The two solutions come back as the particular solution plus its kernel flip (`X ⊕ 1`). I picked the explicit linear-solve route over a half-trace construction specifically because it's harder to get subtly wrong for an even-degree field, and `main` intersects the root sets from all three pair equations.

## Exploitation

The full attack script (`solve_watchword.py`), condensed to its structure:

```python
# GF(2^128) carry-less multiply/reduce, bit-reversed per GCM convention
def gmul(u, v): return reduce_poly(clmul(u, v))
def ginv(a):    return gpow(a, (1 << 128) - 2)

def solve_xx_xor_beta(beta):
    if trace(beta): return []          # no root unless Tr(beta) == 0
    # build the GF(2) linear system L(X) = beta and Gaussian-eliminate it
    ...
    return [xp, xp ^ 1]                # the two candidate H values

def quadratic(a, b, c):                # roots of a*H^2 xor b*H xor c = 0
    ba = gmul(b, ginv(a))
    beta = gmul(gmul(c, a), gmul(ginv(b), ginv(b)))
    return [gmul(ba, x) for x in solve_xx_xor_beta(beta)]

cands = None
for i in range(3):
    for j in range(i + 1, 3):
        roots = quadratic(ci_xor_cj, li_xor_lj, ti_xor_tj)
        cands = set(roots) if cands is None else (cands & set(roots))
# cands should now contain exactly one H
```

It ran cleanly on the first execution:

```
SELF-TEST: OK
sanity: shared keystream across dispatches confirmed; 5759bf9548b198fe4c7404af4336386c
pair (0,1): 2 root(s)
pair (0,2): 2 root(s)
pair (1,2): 2 root(s)
candidate H values: ['730426f0d054fc7539d26145168be28a']
H = E_K(0^128) = 730426f0d054fc7539d26145168be28a
tag mask E_K(J0) = 66b18782c578d8b27ec249a6298dfeb2
sealed master order: 57 bytes
decrypted bytes: b'CSCTF{watchword_2005b4d082c8f06019960d36c5131e783d4bc532}'
MASTER ORDER TEXT: CSCTF{watchword_2005b4d082c8f06019960d36c5131e783d4bc532}
```

Each pair contributed exactly two roots, matching the `{0, 1}` kernel exactly as predicted. The three-way intersection left a single `H`, and recomputing the tag mask independently from each of the three tags produced the *same* mask every time — the script asserts this equality explicitly rather than just using the first one. The final step is a one-liner: treat the mask as an AES-128 key, start CTR mode from an all-zero counter, and the 57 sealed bytes decrypt to printable ASCII. I did not independently verify the original AES key behind any of this — the entire attack, by design, never needs it.

## Root Cause

1. **GCM nonce reuse breaks more than confidentiality.** Tags produced under a shared nonce leak the GHASH subkey `H` through solvable polynomial equations; when every message fits a single block, those equations reduce to quadratics with a closed-form solution, no generic cryptanalytic tooling required.
2. **Key recovery was never necessary for this seal.** Once `H` is known, the per-nonce tag mask `E_K(J0)` falls out as `T ⊕ GHASH_H(C)` for any one of the reused-nonce messages — and anything else encrypted under that same mask, such as this challenge's CTR key, falls with it. The AES key itself stays a secret throughout.
3. The firmware fault causing the nonce reuse is the root design failure; GCM's security guarantees are explicitly conditioned on nonce uniqueness, so this isn't a weakness in GCM but a violation of its precondition.

## Validation

**What was confirmed in testing:**
- The GF(2^128)/GHASH implementation matches `pycryptodome`'s GCM tag and independently reconstructed keystream across three self-test trials (empty AAD, multi-block, partial final block).
- The three dispatches share a keystream prefix consistent with a reused 96-bit nonce.
- Each pairwise tag-difference quadratic yields exactly two roots, and the three-way intersection across all pairs narrows to a single candidate `H`.
- Recomputing the tag mask `E_K(J0)` independently from each of the three tags produces an identical value in all three cases.
- The recovered mask, used as an AES-128-CTR key with an all-zero counter, decrypts the sealed master order to a fully printable, flag-formatted ASCII string.

**What was not confirmed in my own session, and must not be claimed:**
- The underlying AES key `K` was never recovered or needed, and I made no attempt to verify it independently — this is a property of the attack, not a gap in testing.

## Conclusion

The chain was: confirm nonce reuse from known plaintext, convert pairwise tag differences into GF(2^128) quadratics, solve them with linear algebra instead of brute force, intersect to a unique GHASH subkey, derive the tag mask directly from any one tag, and use that mask as the CTR key for the sealed order. The self-test against `pycryptodome` before touching real data is what made a correct first-run solve possible — a GCM bit-convention mistake fails silently and produces plausible-looking but wrong algebra, which would have been far harder to debug downstream than catching it at the self-test stage.

## Flag

```
CSCTF{watchword_2005b4d082c8f06019960d36c5131e783d4bc532}
```
