# The Capability Ghost

**Category:** Forensics

## Solution

### 1. Read the seal from TAR metadata

I inspected `runner-fs.tar.gz` without restoring capabilities or running the contained binaries. On `usr/local/bin/hc-probe`, the PAX attribute `SCHILY.xattr.user.build_seal` held the raw tag:

```text
509df6cd8e103fa5
```

I used those eight bytes, not the `security.capability` attribute. The encrypted marker was the 27-byte file `etc/solunet/signaling-cfg.sealed`.

### 2. Use the journal's custom epoch

I read the journal as JSON:

```bash
journalctl --file=runner.journal -o json
```

The `hc-probe` entry supplied `X_SEAL_EPOCH=1793294042`. Its normal journal timestamp was a different field and was not the key input.

### 3. Derive the key and decrypt the marker

Static strings in `hc-probe` described HMAC-SHA256 using the raw tag as the key and the ASCII decimal epoch as the message. Each ciphertext byte was XORed with the resulting key, repeating every 32 bytes.

I decrypted the marker with:

```python
import hashlib, hmac
cipher = bytes.fromhex('b05507fba7348bb36e0324ede8f7b2bd13eedddb2d81aec037997f')
tag = bytes.fromhex('509df6cd8e103fa5')
key = hmac.new(tag, b'1793294042', hashlib.sha256).digest()
plain = bytes(c ^ key[i % 32] for i, c in enumerate(cipher))
print(plain.decode())
assert bytes(c ^ key[i % 32] for i, c in enumerate(plain)) == cipher
```

The derived key was `f30644afe14fedd4585c5cda81ced08b71ddb3b572e3c4f744f302ecff16446d`. I also applied the same XOR to the plaintext and got the original ciphertext back.

## Flag

```text
CSCTF{fg6_x7i9b6b3nn_bj7sj}
```
