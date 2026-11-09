# Polyglot Requiem

**Category:** Forensics

## Solution

### 1. Find the second file format inside the PNG

I inspected `telemetry_icon.png`. The PNG data ended at offset 114, and a ZIP archive followed it. That archive contained `telemetry_cache.db` and `assetsignd`.

I inspected `assetsignd` without running it.

### 2. Recover the deleted SQLite seal

I searched the database's free pages and unallocated space for `ci_provenance_seal`. I found the deleted row at offset `0x1e7f`, containing 36 ciphertext bytes.

The key inputs were provenance `0f18e37122ddbcca` and epoch `1792061626`.

### 3. Derive the repeating XOR key

I reversed the provenance's raw bytes, appended the epoch as an unsigned 64-bit little-endian value, and hashed those bytes with SHA-256:

```python
import hashlib
import struct

key = hashlib.sha256(
    bytes.fromhex('0f18e37122ddbcca')[::-1]
    + struct.pack('<Q', 1792061626)
).digest()
print(key.hex())
```

The resulting key was:

```text
ad97fc7c11e76bf976338c2482a4e0f418898b3442a2e27c8993dcd83e2e464c
```

### 4. Decrypt the recovered row

I XORed ciphertext byte `i` with `key[i % 32]`. The 36-byte plaintext was the flag below.

## Flag

```text
CSCTF{p0lygl0t_r3qu13m_1d0a73980738}
```
