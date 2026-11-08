# Shadow-Dispatch

**Category:** Forensics

## Solution

1. I compared the Lambda versions and `auth-utils` layers. The application code stayed the same, and `python/_authlog.py` looked normal, but layers 4, 6, 8, and 10 contained extra logic in their `.pyc` files.
2. I inspected the bytecode without importing it. In layer 8, `_PICK=1` selected the SSM parameter `/gridlink/order-hmac-key`, and `_EVERY=5` controlled the periodic leak.
3. I paired CloudWatch `START RequestId` and version records with their telemetry. Each 16-byte correlation token held a one-byte index, two ciphertext bytes, two CRC bytes, and an 11-byte salt.
4. I recovered each two-byte chunk by XORing the ciphertext with `SHA256(request_id_ascii || salt)[:2]`. I checked CRC16-CCITT-FALSE over `index || plaintext_chunk || salt` and kept the matching layer-8 beacons.
5. I joined chunks 0–7 in order. Repeated beacons agreed on the same pieces:

   ```text
   b6b0 8815 2485 2112 e5d4 22f7 5053 d324
   ```

   I wrapped the resulting 32 hex characters in the flag format.

## Flag

```text
CSCTF{b6b0881524852112e5d422f75053d324}
```

> **Note:** I wrote this from my saved reconstruction. I could not recheck the extraction because I do not have the original Lambda layers and CloudWatch logs in the saved collection.
