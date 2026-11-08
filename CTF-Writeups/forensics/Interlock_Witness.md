# Interlock Witness

**Category:** Forensics

## Solution

1. I followed the Modbus/TCP policy: maintenance permit (`0x000A`), isolation (`0x000B`), and protection armed (`0x000C`) all had to be `1` before writes to `0x0013` or `0x0014` were safe.
2. I matched FC16 requests with normal responses and tracked state at each acknowledgement, applying changes after the corresponding response. The saved report identifies 16 accepted writes during unsafe windows, at transactions 4–18 and 127–141.
3. I joined each unsafe request PDU with its response PDU in response order. These pairs contribute 208 bytes; the required prefix is `INTERLOCK-WITNESS/1` followed by a NUL byte.
4. I rechecked the hash from the request addresses and values preserved in the report. This rebuilds the documented eight-byte requests and five-byte responses:

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

## Flag

```text
CSCTF{1198b297c84064fab89d0f3e3e5308791165333c1b64da17185dd51493b6f339}
```

> **Note:** I verified the serialization and digest from the transcribed PDU data. The original capture is absent, so the unsafe-write selection still relies on the saved report.
