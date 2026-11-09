# Countersign — Chronos Security CTF

## Introduction

A console signs every substation command with a keyed hash. From an intercepted session we're given one legitimate `STATUS` command, its signature, and the signing specification. The goal is to produce a valid signature over a command we never signed — getting an arbitrary `DISPATCH` accepted — and submit the forged pair. This is a length-extension attack from the moment you read the spec; the actual work is implementing it correctly.

## Initial Reconnaissance

The signing specification describes the MAC as `SHA-256(key || message)` with the key held server-side — a secret-prefix construction. The API exposes two endpoints:

- `GET /api/sample` → JSON with `message_hex` (the legitimate `STATUS` command) and `sig` (its tag)
- `POST /api/command` → JSON `{"message_hex": ..., "sig": ...}` for submission

The spec also documents the console's command parsing: the message is a form-style string, and the parser takes the *last* `cmd=` parameter. That's the detail that makes the attack useful on its own, not just theoretically interesting — appending `&cmd=DISPATCH` to the end of a signed message overrides the legitimate `cmd=STATUS` earlier in the same string.

## Investigation

**Why this MAC falls.** SHA-256 processes input in 64-byte blocks and carries its 8-word chaining state between blocks; the tag is just that final state, serialized. Given a tag for `key || msg`, I can deserialize it back into a chaining state and keep hashing from there — over the glue padding that "resumes" the stream, followed by my own suffix — producing a valid tag for `key || msg || glue || suffix`, all without ever learning `key`. The only unknown the attack depends on is the key's length, since the glue padding has to make `key || msg` land on a block boundary.

**Building and self-testing the primitive.** I implemented SHA-256 from scratch (~40 lines: round constants, compression function, padding) with an injectable chaining state, and validated it against `hashlib` before trusting it with anything real:

```python
def sha256(data: bytes) -> bytes:
    st = IV[:]
    bl = data + b'\x80' + b'\x00' * ((55 - len(data)) % 64) + struct.pack('>Q', len(data) * 8)
    for i in range(0, len(bl), 64):
        st = compress(st, bl[i:i+64])
    return struct.pack('>8I', *st)
assert sha256(b'abc').hex() == hashlib.sha256(b'abc').hexdigest()
```

The extension function deserializes a tag into a state and compresses the suffix after correcting the message-length field — the length claimed has to be `bits(key||msg||glue) + bits(suffix)`, not just the suffix's own length:

```python
def extend(tag, orig_len, suffix):
    state = list(struct.unpack('>8I', tag))
    consumed = ((orig_len // 64) + 1) * 64 if (orig_len % 64) >= 56 else ((orig_len // 64) + 1) * 64
    bits = consumed * 8
    buf = suffix + b'\x80' + b'\x00' * ((55 - len(suffix)) % 64) + struct.pack('>Q', bits + len(suffix) * 8)
    for i in range(0, len(buf), 64):
        state = compress(state, buf[i:i+64])
    return struct.pack('>8I', *state)
```

with the glue block reproducing the tail of `key || msg`'s own padding:

```python
def glue(orig_len):
    z = (55 - orig_len) % 64
    return b'\x80' + b'\x00' * z + struct.pack('>Q', orig_len * 8)
```

The self-test asserts full equivalence against a known key:

```python
_t = sha256(_key + _msg)
assert extend(_t, len(_key) + len(_msg), b'&cmd=DISPATCH') == \
       sha256(_key + _msg + glue(len(_key) + len(_msg)) + b'&cmd=DISPATCH')
```

**Re-checking the construction, and getting one framing detail wrong a second time.** I re-ran the self-test and re-proved the forgery end-to-end against a synthetic key before touching the live target, and it printed clean — but on the first re-check I made the same category of mistake the glue function exists to prevent: I computed the glue length using just the key length rather than `len(key) + len(msg)`, the full padded prefix the padding actually closes over. After correcting that:

```
forged msg  : b'station=KRAJOVA&cmd=STATUS\x80\x00...[padding]...\x01P&cmd=DISPATCH'
real tag    : b7d1fdd62dd4ffe9c3cffd35b6bb2ae1d53bc479264d27fd440f38bfbc652529
extended tag: b7d1fdd62dd4ffe9c3cffd35b6bb2ae1d53bc479264d27fd440f38bfbc652529
MATCH: True
```

## Exploitation

The spec never discloses the server's key length, so the attack loop fetches the sample and sweeps candidate key lengths, building a forged message and matching tag for each:

```python
sample = json.load(urllib.request.urlopen(BASE + '/api/sample', timeout=20))
msg = bytes.fromhex(sample['message_hex'])
tag = bytes.fromhex(sample['sig'])
suffix = b'&cmd=DISPATCH'

for L in range(8, 33):
    total = L + len(msg)
    fg = msg + glue(total) + suffix
    tg = extend(tag, total, suffix)
    code, resp = submit(fg.hex(), tg.hex())
    if 'CSCTF{' in resp:
        print('*** AUTH CODE FOUND with key length', L)
        break
```

Because the console's parser resolves to the *last* `cmd=` parameter, the forged message evaluates as `cmd=DISPATCH` on the server side while the tag verifies over the exact byte string submitted — the two checks (what gets executed, what gets authenticated) are looking at the same bytes but drawing different conclusions from them. The live run returned the authorization code in the HTTP response.

[CONFIRM — exact run details]: I saved the response to `download/dispatch_authcode.txt` at solve time, but the specific key length that produced the hit and the exact sample bytes used in that run weren't preserved in my surviving notes. I'm reporting the flag as recorded, without being able to restate which `L` in the sweep was the winning one.

## Root Cause

1. **`SHA-256(key || message)` is not a MAC.** Any Merkle–Damgård hash inherits the length-extension property, because the "tag" is nothing more than the hash function's internal state after absorbing the message — anyone holding a valid tag can resume hashing from it. The fix is a construction designed to resist this specifically (HMAC, or a keyed mode like BLAKE2's), not a patch to this scheme.
2. **Last-parameter-wins parsing on the receiving end is what converts a signature-over-appended-garbage into actual command execution.** The signing scheme's weakness alone would only let an attacker produce a valid tag over an unintelligible string; the parser's resolution rule is what turns that string into `cmd=DISPATCH`.
3. Unknown key length is a minor obstacle at most — each candidate length only changes the glue block, so sweeping a plausible range costs one request per guess, not an exponential search.

## Validation

**What was confirmed in testing:**
- The hand-written SHA-256 implementation matches `hashlib.sha256` exactly on a test vector (`b'abc'`).
- The length-extension function, applied to a synthetic known key, reproduces the directly-computed hash of `key || msg || glue || suffix` exactly — confirming the extension logic, the glue-padding construction, and the corrected length field are all consistent.
- Submitting the forged message/tag pair to the live service returned an HTTP response containing a `CSCTF{...}`-formatted authorization code.

**What was not confirmed in my own session, and must not be claimed:**
- I don't have a record of the exact key length that produced the successful submission, nor the precise sample bytes used in that specific run — only the saved response containing the flag.

## Conclusion

The chain here was a textbook length-extension forgery made practical by a parser that resolves to the last occurrence of a repeated parameter. The self-test against `hashlib` and the end-to-end re-proof against a synthetic key were what caught a subtle re-introduced bug (glue length computed from the key alone instead of the full padded prefix) before it could burn a live request against a presumably rate-limited endpoint — cheap insurance that paid off on the second pass, not the first.

## Flag

```
CSCTF{jJWnUI1uvS5eTcfmQw2WAZFx}
```
