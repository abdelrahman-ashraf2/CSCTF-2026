# The Capability Ghost

**Category:** Forensics

## Solution

1. I inspected the TAR metadata in `runner-fs.tar.gz`. The PAX attribute `SCHILY.xattr.user.build_seal` on `usr/local/bin/hc-probe` contained tag `509df6cd8e103fa5`; the capability attribute was not the seal.
2. I read the `hc-probe` journal entry with the recorded command:

   ```bash
   journalctl --file=runner.journal -o json
   ```

   I used the custom field `X_SEAL_EPOCH=1793294042`, rather than the entry's timestamp.
3. I read the binary's static strings to identify the scheme: HMAC-SHA256 with raw tag bytes as the key and the decimal epoch as the message, followed by repeating-key XOR. I did not execute the binary.
4. I decrypted `etc/solunet/signaling-cfg.sealed`. I rechecked the saved ciphertext with this code and confirmed that the XOR round trip reproduces it:

   ```python
   import hashlib
   import hmac

   cipher = bytes.fromhex('b05507fba7348bb36e0324ede8f7b2bd13eedddb2d81aec037997f')
   tag = bytes.fromhex('509df6cd8e103fa5')
   key = hmac.new(tag, b'1793294042', hashlib.sha256).digest()
   plain = bytes(c ^ key[i % 32] for i, c in enumerate(cipher))
   print(plain.decode())
   assert bytes(c ^ key[i % 32] for i, c in enumerate(plain)) == cipher
   ```

## Flag

```text
CSCTF{fg6_x7i9b6b3nn_bj7sj}
```

> **Note:** I rechecked the decryption from the saved values. The TAR and journal are absent, so I could not repeat their extraction.
