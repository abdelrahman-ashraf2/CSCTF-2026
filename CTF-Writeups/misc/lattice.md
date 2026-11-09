## 1. Title + Metadata
# Lattice 

## 2. Introduction
The challenge supplied a custom block cipher, a ciphertext named `TARGET`, and a service that accepted the recovered plaintext. The intended approach was to reconstruct the inverse encryption routine and validate the plaintext locally.

## 3. Initial Reconnaissance
The remote service was reachable:

```bash
timeout 10 bash -c 'cat < /dev/null > /dev/tcp/w05.ctf.chronos-security.ro/33546 && echo "TCP CONNECT OK"'
```

The archive contained `lattice.py`. The cipher used 8-byte blocks, 16 rounds, ECB mode, and PKCS#7 padding. Each round performed key mixing, S-box substitution, and a 64-bit left rotation. The S-box and round keys were deterministically generated from hardcoded seeds `0x1A2B3C4D` and `0xCAFEB0BA`.

## 4. Investigation
The round operations were reversible:
- Even-round addition modulo 256 was reversed by subtraction.
- XOR was reversed by XOR.
- The S-box was inverted through a reverse lookup table.
- A left rotation was reversed by a right rotation.

Because encryption applied key mixing, substitution, then rotation, decryption had to reverse those operations in reverse order and process rounds from 15 down to 0.

## 5. Exploitation
The inverse S-box was constructed as follows:

```python
INV_SBOX = [0] * 256
for i, v in enumerate(SBOX):
    INV_SBOX[v] = i
```

The block decryption logic reversed the rotation, substitution, and key mixing for each round. Each 8-byte ciphertext block was decrypted independently, then PKCS##7 padding was removed.

Recovered plaintext:

```text
unl0ck-th3-l4tt1ce-pre1mage-3f9a7c2e1b8d4a60
```

Validation:

```text
re-encrypt matches TARGET: True
local check() says: True
```

`nc` was unavailable, so a Python socket client was used instead. The service accepted the passphrase and returned:

```text
CSCTF{q1Kbx7N1UzEVnjeWLSQn1xrI}
```

## 6. What I Cannot Confirm
- Challenge author and team name were not provided.
- No separate analysis of the LCG generators was necessary; the supplied implementation was reused.

## 7. Root Cause
The S-box and round-key schedule were reproducible from hardcoded seeds distributed with the source. The round construction was reversible, and all information needed to reconstruct the inverse was available.

## 8. Validation
Confirmed: service reachability, deterministic table generation, inverse-round implementation, plaintext recovery, padding removal, encryption round-trip, local `check()`, and remote acceptance.

Not confirmed: challenge author or team identity.

## 9. Conclusion
Reversing the cipher's round operations recovered the passphrase. Re-encryption and the supplied check function validated the result, and the remote service accepted it.

## 10. AI Methodology
**AI contribution:** organization, explanation of inverse-round ordering, and writeup structure.

**Personally verified:** source inspection, inverse S-box, decryption, padding, round-trip comparison, local check, socket interaction, and returned flag.

**Correctness statement:** The plaintext was checked against the original encryption implementation and the service's acceptance response.
