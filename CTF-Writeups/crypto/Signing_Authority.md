# Signing Authority — Chronos Security CTF

## Introduction

The service promotes a "master arming image" only on a valid ECDSA signature over one exact message, and it explicitly refuses to sign that message itself. What it does publish are signed release receipts. The goal is to turn those receipts into a valid signature over the master message and submit it to `/authorize`. Unusually for this kind of challenge, the service's own `/schema` endpoint basically hands over the entire attack plan — the interesting part is noticing that and verifying it carefully rather than discovering anything novel.

## Initial Reconnaissance

`GET /schema` describes the whole API, and gives away considerably more than a typical schema would:

```json
{
  "curve": "secp256k1",
  "hash_to_integer": "sha256-int-be-mod-n",
  "receipt_s_rule": "raw-no-low-s",
  "same_nonce_recovery": "k=(z1-z2)*inv(s1-s2)modn;d=(s1*k-z1)*inv(r)modn",
  "authorize_message_rule": "exact-master-message-hex",
  "authorize_s_rule": "low-s",
  "authorize_s_range": "1-through-floor-n-over-2",
  "authorize_field_order": ["message_hex", "r", "s"],
  "master_message_hex": "544f5256454e2d415554485a2d56310a6f7065726174696f6e3d..."
}
```

Two things stood out immediately. First, the schema literally publishes the same-nonce recovery formula — that told me the intended weakness before I'd even looked at the receipts. Second, it documents a wire-format asymmetry I'd need at the very end: receipts are signed with raw `s` values, but `/authorize` demands canonical low-s.

`GET /receipts` returned two release receipts:

```
ta-9.7.14: r=3d2a9d81df9d85fc...43321a42  s=36f9a8231a61379a...d59b146d
ta-9.7.15: r=3d2a9d81df9d85fc...43321a42  s=216776e795e1c9a5...0600d5a
```

Identical `r` across both. In ECDSA, `r = (k·G).x mod n` is a pure function of the ephemeral nonce, so two signatures sharing `r` means the signer reused the nonce — exactly the case the schema's own formula addresses.

## Investigation

I checked the given formula against the ECDSA equations directly rather than just trusting it: with the same nonce `k` signing two messages, `s₁ = k⁻¹(z₁ + r·d)` and `s₂ = k⁻¹(z₂ + r·d)`. Subtracting gives `s₁ − s₂ = k⁻¹(z₁ − z₂)`, so `k = (z₁ − z₂)/(s₁ − s₂) mod n`, and then `d = (s₁·k − z₁)/r mod n`. The `z` values are `sha256(message)` read big-endian and reduced mod `n`, per the schema's `hash_to_integer` rule. The one subtlety is sign ambiguity — `k` and `−k` both produce the same `r` — so I kept a fallback branch to flip signs if the first attempt didn't verify; it never actually triggered.

Since the schema already hands over the curve parameters and I only needed point multiplication for verification and signing (not for recovery itself), I implemented secp256k1 point arithmetic directly — roughly 30 lines of affine add/double/multiply using Python's built-in modular inverse — rather than pulling in a library for something this small.

The receipt messages decode to human-readable release records, which is also how I confirmed the hash-input rule was being applied correctly:

```
TORVEN-RECEIPT-V1
release=ta-9.7.14
artifact=nav-controller
```

## Exploitation

The solve script runs four stages.

**1. Recover the key from the two receipts:**

```python
z1, z2 = z_of(rc1['message_hex']), z_of(rc2['message_hex'])
k = (z1 - z2) * inv(s1 - s2, N) % N
d = (s1 * k - z1) * inv(r, N) % N
```

**2. Verify before using it** — compute `d·G` and compare against the service's own published key at `/pubkey`:

```
d = 0xb4d49b0ab787546f7bbfd43ac210f216d605a6d5fdc2c31652d59f928a215026
d*G matches pubkey: True
```

This is the step that turns "a plausible-looking key" into "the signer's actual key" — any error in the nonce algebra, the `z` derivation, or the mod-`n` reduction would have failed right here instead of surfacing later as a rejected submission.

**3. Sign the master message with a fresh random nonce, following the service's own conventions.** The message itself (from `master_message_hex`) decodes to `TORVEN-AUTHZ-V1\noperation=promote-master-arming\nartifact=master-arming-image\n`. Since `/authorize` enforces low-s, I normalized:

```python
kd = secrets.randbelow(N - 1) + 1
Rx, Ry = pt_mul(kd)
rr = Rx % N
ss = inv(kd, N) * (zm + rr * d) % N
if ss > N // 2:
    ss = N - ss
```

**4. Submit with the exact wire format the schema demands** — minified JSON, all string values, fixed field order:

```json
{"message_hex":"544f...","r":"09ee1aaef665a391...","s":"35561373ccc3efe7..."}
```

```
HTTP 200 {"master_authorization":"CSCTF{8rMCe6b5VQCaho1QUHs2Hnce}"}
```

## Root Cause

1. **Nonce reuse across the two published receipts is the actual cryptographic break.** The signer here reused `k` across `ta-9.7.14` and `ta-9.7.15`, and any service publishing signatures — receipts, timestamps, certificates — exposes exactly this surface the moment that happens, even just once.
2. **Canonicalization is enforced inconsistently between the two endpoints** — raw-s accepted for receipts, low-s required for authorization. That's a design inconsistency rather than a cryptographic flaw per se, but it's a real gotcha: a mathematically correct signature over the right message still gets rejected if `s` is on the wrong half of the group order.

## Validation

**What was confirmed in testing:**
- Two published receipts (`ta-9.7.14`, `ta-9.7.15`) share an identical `r` value.
- The same-nonce recovery formula applied to those two receipts yields a private key `d` whose public point `d·G` matches the service's own published public key exactly.
- A freshly signed master message, normalized to low-s per the schema's `authorize_s_rule`, is accepted by `/authorize` and returns an authorization code matching the `CSCTF{...}` format.

**What was not confirmed in my own session, and must not be claimed:**
- Nothing outstanding — the service's own `HTTP 200` response with the authorization code is a direct, positive confirmation, not an inference.

## Conclusion

This challenge is unusual in that the vulnerable mechanism (nonce reuse, and the recovery formula to exploit it) is handed to you openly by the service's own schema — the work is verifying each step rather than discovering the weakness. The one place a correct recovery formula still silently produces the wrong answer is canonicalization: this service accepts raw-s on its receipts but demands low-s on its authorization endpoint, so even a mathematically sound signature over the right message gets rejected unless that difference is caught.

## Flag

```
CSCTF{8rMCe6b5VQCaho1QUHs2Hnce}
```
