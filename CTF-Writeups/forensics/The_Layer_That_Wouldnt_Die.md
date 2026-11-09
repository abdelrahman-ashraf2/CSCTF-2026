# The Layer That Wouldn't Die — Chronos Security CTF

## Introduction

The archive here is a standard OCI image layout — `oci-layout`, `index.json`, and a content-addressed `blobs/sha256/` store. The credential at the center of the challenge is recoverable entirely from the layout itself: the image config documents the exact sealing scheme and its key material, and the file the attacker "deleted" still physically exists in a lower layer. The title gives away the lesson before you even start: in an OCI image, deletion is just another layer, not a removal.

## Initial Reconnaissance

```console
$ sha256sum historian-image.zip
e87c82ecc31ddbd05a6982f13d48b6a3d39ed4f23ef0a3e02e850a4b4e1cfe91  historian-image.zip
$ unzip -o historian-image.zip -d image
[...]  creating: image/cascade-historian-config-image/blobs/sha256/[...]
```

`index.json` points at one manifest:

```json
{"schemaVersion":2,"manifests":[{"mediaType":"application/vnd.oci.image.manifest.v1+json","digest":"sha256:3a2bbea5a21a1629660018ba0c832e93fd5acabf9be21ce563f25db4b2227db3","annotations":{"org.opencontainers.image.ref.name":"cascade-historian-config:site-east"}}]}
```

The manifest names a config blob plus five gzipped tar layers. In container forensics the config JSON is usually the highest-value artifact available without unpacking anything — it holds labels, `diff_id`s, and the full build history — so I read it first, before touching any of the layer archives.

## Investigation

**The config's labels and history did most of the work.** The `Labels` block carried the sealing key directly, and the `history` array's `comment` field for the layer that added the secret spelled out the full seal specification:

```
"Labels": { [...], "build.seal": "ddc9bfb15738fbd10757eb936a593931" }

COPY historian.key.sealed /etc/cascade/historian.key.sealed
comment: release seal: sealed = plaintext XOR repeating(HMAC-SHA256(key=bytes.fromhex(Labels['build.seal']), msg=raw bytes of /etc/cascade/.sealed_marker as it
stands in the image at the end of this layer)); the 32-byte digest is repeated to the length of the sealed file
```

That removed all guesswork about the crypto: it's HMAC-SHA256 used as a repeating XOR keystream, keyed by the 16 bytes decoded from the label. The only remaining unknown is the exact content of the marker file referenced in the comment. The last two history entries explained how that marker went missing:

```
COPY site-rev-b/ /etc/cascade/        (2026-10-12, by registry-push@cascade.example)
RUN rm -f /etc/cascade/.sealed_marker (2026-10-12, by registry-push@cascade.example)
```

**Extracting all five layers to see what each snapshot actually contained.**

```console
$ for d in eac5e15... be85964...; do tar -tzvf blobs/sha256/$d; done
[...] layer 1: etc/hostname, etc/os-release
[...] layer 2: etc/cascade/.sealed_marker (32 B), etc/cascade/config.yaml (48 B)
[...] layer 3: etc/cascade/historian.key.sealed (32 B)
[...] layer 4: etc/cascade/.sealed_marker (32 B), etc/cascade/config.yaml (48 B)
[...] layer 5: etc/cascade/.wh..sealed_marker (0 B)
```

This confirmed the mechanics directly: OCI layers are purely additive snapshots, and a "deletion" is only a whiteout entry (`.wh..sealed_marker`) added in a later layer — the original marker file in layer 2 is still physically present and fully readable. Dumping both copies of the marker showed the rev-B layer had actually *replaced* it, not merely deleted it:

```console
$ cat 3fd0c55.../etc/cascade/.sealed_marker ; cat 3fd0c55.../etc/cascade/config.yaml
f4901a8d069d99180eed0cb14c8fd2a9
site: east-02
poll_interval_s: 30
marker_rev: A
$ cat 824c9dd.../etc/cascade/.sealed_marker ; cat 824c9dd.../etc/cascade/config.yaml
f5d8040f988f7e4917c0281af23d00ac
site: east-02
poll_interval_s: 30
marker_rev: B
$ od -A x -t x1z 928dc52.../etc/cascade/historian.key.sealed
000000 ea 9d d1 bd 75 d7 d8 7c 78 7d 06 e3 2f f2 0a 4a  >....u..|x}../..J<
000010 b4 60 d9 15 2c 3c 9c 1c 80 35 05 ac f2 5a 5d 82  >.`..,<...5...Z].<
```

One detail mattered quietly here: both markers list as exactly 32 bytes in the layer listing, equal to the 32-character hex string with no trailing newline — that's the exact byte sequence to feed the HMAC. The spec's wording, "as it stands in the image at the end of *this layer*," points to the rev-A marker from the sealing layer (layer 3), which predates rev B. Since the sealed file is itself only 32 bytes, a single HMAC digest block covers it entirely and the "repeating" clause in the spec never actually triggers.

## Exploitation

I wrote a short script to compute the keystream for *both* markers — rev-A from layer 2 and the rev-B replacement — and XOR each against the sealed bytes, so the right input would be confirmed by its output rather than assumed up front:

```python
import hashlib, hmac
KEY_HEX  = "ddc9bfb15738fbd10757eb936a593931"   # config Labels['build.seal']
MARKER_A = b"f4901a8d069d99180eed0cb14c8fd2a9"  # layer 2, rev A
MARKER_B = b"f5d8040f988f7e4917c0281af23d00ac"  # layer 4, rev B
SEALED = bytes.fromhex("ea9dd1bd75d7d87c787d06e32ff20a4a"
                       "b460d9152c3c9c1c803505acf25a5d82")

def unseal(marker: bytes) -> bytes:
    key = bytes.fromhex(KEY_HEX)
    digest = hmac.new(key, marker, hashlib.sha256).digest()
    stream = (digest * (len(SEALED) // len(digest) + 1))[: len(SEALED)]
    return bytes(a ^ b for a, b in zip(SEALED, stream))
```

```
marker rev A (end of sealing layer): b'CSCTF{layer_remembers_93e33478c}'
marker rev B (post-intrusion decoy): b'\x9a\xf2\x830\x84\xe1\x80\x07\xf8\xbef\x19\xa1<J\xa2\xa1%N\xbe_+\xc8\x9b\r\xfb\x04\xcb\xa7G\xcf<'
```

Rev A produced printable text landing exactly in flag format; rev B produced binary garbage. That settled which marker version the seal actually used and conclusively ruled out the post-intrusion replacement as the right key material.

As a final independent check, I re-derived everything from the extracted files instead of trusting transcribed constants: every blob re-hashed correctly to its own filename, and every layer's `diff_id` was recomputed and compared against the config's `rootfs.diff_ids`. My first pass at that check failed its assertion because I'd hashed the *compressed* gzip blobs — `diff_id` is actually the SHA-256 of the *decompressed* tar, not the compressed blob. Fixing it to `sha256(gzip.decompress(blob))` made it pass:

```
[+] all 7 blobs match their sha256 digests
[+] all 5 layer diff_ids match config rootfs
[+] flag: CSCTF{layer_remembers_93e33478c}
```

## Root Cause

1. **OCI image layers are purely additive, and a "deletion" is only ever a whiteout marker in a later layer** — the original file remains fully present and readable in whichever earlier layer wrote it. This is a design property of the OCI layer format, not a bug; it's just something an attacker (or a defender doing forensics) needs to know to act on correctly.
2. **The sealing scheme's key material was published in the image's own labels**, and its one remaining secret input (the marker file) survived unintentionally in an earlier layer despite being overwritten and later "deleted" in subsequent layers.

## Validation

**What was confirmed in testing:**
- The original `.sealed_marker` (rev A) is fully present and readable in layer 2, despite a later layer replacing it and a still-later layer adding a whiteout for it.
- HMAC-SHA256 keyed by the config label's 16-byte key, applied to the rev-A marker, decrypts the 32-byte sealed file to fully printable, flag-formatted ASCII.
- The same construction applied to the rev-B marker instead produces binary garbage, confirming rev A is the correct input.
- All seven blobs in the image independently re-hash to their own filenames, and all five layers' `diff_id`s (SHA-256 of the decompressed tar, not the compressed blob) match the config's `rootfs.diff_ids`.

**What was not confirmed in my own session, and must not be claimed:**
- Nothing outstanding — every step of this chain (key, marker, decryption, and full-image integrity re-verification) was independently confirmed within this session.

## Conclusion

The whole chain traced back to one fact about the OCI image format: deleting a file is just adding a whiteout entry in a later layer, and the original content survives untouched in whatever earlier layer wrote it. Reading the image config before touching any layer archive handed over the complete sealing scheme and its key up front, and the one real debugging moment — hashing compressed blobs instead of decompressed tars when checking `diff_id`s — was a reminder that OCI's integrity fields are specified against the uncompressed content, not the blob you actually download.

## Flag

```
CSCTF{layer_remembers_93e33478c}
```
