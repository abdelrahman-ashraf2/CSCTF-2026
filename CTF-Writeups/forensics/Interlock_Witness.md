# Interlock Witness

**Category:** Forensics

## Solution

### 1. Apply the policy at acknowledgement time

I followed the Modbus/TCP register map. Maintenance permit (`0x000A`), isolation (`0x000B`), and protection armed (`0x000C`) all had to be `1` before writes to `trip_limit` (`0x0013`) or `restore_delay` (`0x0014`) were safe.

I matched each FC16 request to its normal response, checking the transaction and echoed start address and quantity. I evaluated safety immediately before the acknowledgement and applied state changes after their responses.

I found two unsafe windows: transactions 4–18, when permit and isolation were absent, and 127–141, when isolation was temporarily zero. A normal response showed that a write was accepted; it did not establish that the policy was satisfied.

### 2. Retain the 16 unsafe accepted writes

I kept these PDU pairs in response order:

| # | Transaction | PDU address | Value | Request PDU (hex) | Response PDU (hex) |
|---:|---:|---|---:|---|---|
| 1 | 4 | `0x0013` | 1037 | `10 00 13 00 01 02 04 0d` | `10 00 13 00 01` |
| 2 | 6 | `0x0014` | 338 | `10 00 14 00 01 02 01 52` | `10 00 14 00 01` |
| 3 | 8 | `0x0013` | 1076 | `10 00 13 00 01 02 04 34` | `10 00 13 00 01` |
| 4 | 10 | `0x0014` | 378 | `10 00 14 00 01 02 01 7a` | `10 00 14 00 01` |
| 5 | 12 | `0x0013` | 1117 | `10 00 13 00 01 02 04 5d` | `10 00 13 00 01` |
| 6 | 14 | `0x0014` | 420 | `10 00 14 00 01 02 01 a4` | `10 00 14 00 01` |
| 7 | 16 | `0x0013` | 1160 | `10 00 13 00 01 02 04 88` | `10 00 13 00 01` |
| 8 | 18 | `0x0014` | 464 | `10 00 14 00 01 02 01 d0` | `10 00 14 00 01` |
| 9 | 127 | `0x0013` | 3077 | `10 00 13 00 01 02 0c 05` | `10 00 13 00 01` |
| 10 | 129 | `0x0014` | 2408 | `10 00 14 00 01 02 09 68` | `10 00 14 00 01` |
| 11 | 131 | `0x0013` | 3176 | `10 00 13 00 01 02 0c 68` | `10 00 13 00 01` |
| 12 | 133 | `0x0014` | 2508 | `10 00 14 00 01 02 09 cc` | `10 00 14 00 01` |
| 13 | 135 | `0x0013` | 3277 | `10 00 13 00 01 02 0c cd` | `10 00 13 00 01` |
| 14 | 137 | `0x0014` | 2610 | `10 00 14 00 01 02 0a 32` | `10 00 14 00 01` |
| 15 | 139 | `0x0013` | 3380 | `10 00 13 00 01 02 0d 34` | `10 00 13 00 01` |
| 16 | 141 | `0x0014` | 2714 | `10 00 14 00 01 02 0a 9a` | `10 00 14 00 01` |

Each pair contributes eight request bytes and five response bytes, for `16 * 13 = 208` bytes. The witness uses PDU bytes, without the Modbus/TCP MBAP headers.

### 3. Build the witness and hash it

I prepended `INTERLOCK-WITNESS/1` and a NUL byte, making a 20-byte prefix. This code reconstructs the PDUs from their address/value pairs, joins each request and response, and calculates the digest:

```python
import hashlib
import struct

values = [
    (0x13, 1037), (0x14, 338), (0x13, 1076), (0x14, 378),
    (0x13, 1117), (0x14, 420), (0x13, 1160), (0x14, 464),
    (0x13, 3077), (0x14, 2408), (0x13, 3176), (0x14, 2508),
    (0x13, 3277), (0x14, 2610), (0x13, 3380), (0x14, 2714),
]
pairs = []
for address, value in values:
    response = b'\x10' + struct.pack('>HH', address, 1)
    request = response + b'\x02' + struct.pack('>H', value)
    pairs.append(request + response)

prefix = b'INTERLOCK-WITNESS/1\x00'
witness = b''.join(pairs)
assert len(prefix) == 20 and len(witness) == 208
print(hashlib.sha256(prefix + witness).hexdigest())
```

The complete witness was 228 bytes. Its SHA-256 was `1198b297c84064fab89d0f3e3e5308791165333c1b64da17185dd51493b6f339`.

## Flag

```text
CSCTF{1198b297c84064fab89d0f3e3e5308791165333c1b64da17185dd51493b6f339}
```

> **Note:** The PDU table comes from my original reconstruction. Checking the selection of unsafe writes requires the original capture.
