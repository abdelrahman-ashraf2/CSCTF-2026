# Shadow-Dispatch

**Category:** Forensics

## Solution

### 1. Locate the change in the Lambda layer

I compared `function-versions.json`, `layers-metadata.json`, and the `auth-utils-{1..10}.zip` layers. The main application hash stayed the same. `python/_authlog.py` also looked normal, while compiled bytecode in layers 4, 6, 8, and 10 contained `boto3`, `_ssm`, `_NAMES`, and `_PICK` references.

I inspected the bytecode as data without importing it. In layer 8, `_PICK=1` selected `/gridlink/order-hmac-key` from the SSM parameter list; the first item was `portal-session-secret`. `_EVERY=5` controlled the periodic leak.

### 2. Pair each beacon with its request and version

I read `cloudwatch/streams/stream-*.log` and paired the `START RequestId` and Lambda version with the following telemetry record. I kept the matching layer-8 leak events rather than mixing data from different versions.

Each 16-byte correlation token had this layout:

| Offset | Length | Field |
|---:|---:|---|
| 0 | 1 | Chunk index |
| 1 | 2 | Ciphertext |
| 3 | 2 | CRC16 |
| 5 | 11 | Salt |

### 3. Undo the XOR and validate the chunk

For each record I derived the first two SHA-256 bytes from `request_id` encoded as ASCII followed by the raw salt. I XORed those bytes with the ciphertext to recover a two-byte chunk.

I checked CRC16-CCITT-FALSE over `index || plaintext_chunk || salt`, and used the every-fifth-order condition to separate the leak from ordinary beacons.

### 4. Reassemble the selected SSM value

I found 20 matching version-8 requests. Repeated observations agreed on each indexed chunk:

```text
0: b6b0
1: 8815
2: 2485
3: 2112
4: e5d4
5: 22f7
6: 5053
7: d324
```

I joined indices 0–7 and put the 32 hex characters inside the flag wrapper. `subscription-filters.json` also showed the log group forwarding to a Kinesis stream in another account, explaining how the leaked telemetry left the account.

## Flag

```text
CSCTF{b6b0881524852112e5d422f75053d324}
```

> **Note:** The original verifier is not included, and my notes do not specify the CRC byte order.
