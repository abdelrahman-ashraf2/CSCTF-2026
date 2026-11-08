# Polyglot Requiem

**Category:** Forensics

## Solution

1. I checked `telemetry_icon.png` and found that the PNG ended at offset `114`. A ZIP archive followed it, containing `telemetry_cache.db` and `assetsignd`.
2. I searched the SQLite free space and recovered the deleted `ci_provenance_seal` row at `0x1e7f`. It contained 36 encrypted bytes.
3. I used provenance `0f18e37122ddbcca` and epoch `1792061626` to derive the key. The provenance bytes are reversed, and the epoch is an unsigned 64-bit little-endian value:

   ```python
   import hashlib
   import struct

   key = hashlib.sha256(
       bytes.fromhex('0f18e37122ddbcca')[::-1]
       + struct.pack('<Q', 1792061626)
   ).digest()
   print(key.hex())
   ```

4. I XORed each ciphertext byte with `key[i % 32]`. The recovered text was the flag; I did not need to execute `assetsignd`.

## Flag

```text
CSCTF{p0lygl0t_r3qu13m_1d0a73980738}
```

> **Note:** I rechecked the key derivation. The original database and ciphertext are absent, so I could not repeat the final decryption.
