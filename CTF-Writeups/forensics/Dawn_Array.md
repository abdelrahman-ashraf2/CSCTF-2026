# Dawn Array

**Category:** Forensics

## Solution

### 1. Recover the array geometry

I started with three surviving members of a four-disk RAID-5 array. Each image was `41,943,040` bytes. The md metadata at member offset `0x1000` recorded:

```text
set_uuid   = 67662dd6d0cf450f8314edf0fde03868
set_name   = rrca-gw-e2:staging
level      = 5
layout     = 2 (left-symmetric)
size       = 79872 sectors per member
chunk_size = 64 sectors = 32768 bytes
raid_disks = 4
```

The images held `81,920` sectors each, while member data occupied `79,872` sectors. The difference gave the data offset: `(81920 - 79872) * 512 = 1048576` bytes.

### 2. Correct the surviving member order

I checked the ext4 magic at filesystem offset `0x438`, which is superblock offset `1024 + 0x38`. Finding it at physical offset `0x100438` identified `acq-1.raw` as role 0.

My first order produced a plausible superblock but an empty root directory. The root inode table was at logical block 48, where the other member roles mattered. Swapping the remaining two members fixed the parse:

| Image | Correct role |
|---|---:|
| `acq-1.raw` | 0 |
| missing member | 1 |
| `acq-2.raw` | 3 |
| `acq-3.raw` | 2 |

I reconstructed the array read-only and extracted the filesystem with my `raid5_extract.py` helper:

```bash
python3 tools/raid5_extract.py \
  --member 0:acq-1.raw --member 3:acq-2.raw --member 2:acq-3.raw \
  --member-count 4 --chunk-bytes 32768 \
  --data-offset-bytes 1048576 --array-bytes 122618880 \
  --layout left-symmetric --output array2.img
```

### 3. Recover the procedure and all three evidence sources

I extracted these files from the recovered filesystem:

```text
fs2/var/lib/rrca/dispatch.sqlite                   36864 bytes
fs2/var/lib/rrca/dispatch.sqlite-wal             552112 bytes
fs2/var/lib/rrca/dispatch.sqlite-shm              32768 bytes
fs2/var/log/rrca/controller-access.pcapng        381248 bytes
fs2/var/log/rrca/dispatch-gateway.syslog         146768 bytes
fs2/usr/share/doc/rrca-dispatch-procedure.txt     5198 bytes
```

The procedure, DP-7, defined four phases: `PREPARE_SENT`, `RESPONSE_OBSERVED`, `READBACK_OBSERVED`, and `COMMIT_WRITTEN`.

I opened copies of `dispatch.sqlite` and its matching WAL together, without the saved SHM file, so SQLite included committed transactions still present in the WAL. I recovered 128 committed cycles, 512 syslog events, and 128 HTTP connections.

For the pcapng evidence I rebuilt TCP streams by sequence number, then split HTTP messages using `Content-Length`. I matched reservation requests, their responses, and readback exchanges to the ledger and structured syslog fields.

### 4. Keep only the cycles that agree across sources

I applied DP-7's Q1–Q5 rules across all three evidence sources. These were some of the mismatches I rejected:

| Sequence | Conflict |
|---:|---|
| 1 | Reservation-response nonce disagreed with the ledger nonce. |
| 2 | Response revision disagreed with the ledger revision. |
| 3 | Readback register was `9002`, while the ledger said `7497`. |
| 4 | Syslog readback value was `0`, while the ledger said `1`. |

Of 128 cycles, 112 failed the cross-source checks. These 16 remained, ordered by `gateway_seq`:

```text
14, 15, 34, 35, 55, 69, 78, 79, 80, 83, 85, 87, 95, 103, 110, 117
```

### 5. Serialize the release witness

For every passing cycle, I wrote:

```text
cycle_id|request_id|prepare_revision|reservation_nonce|release_register|release_value
```

I prefixed the ASCII lines with `RRCA-DAWN-WITNESS-v1\n`, including the final LF after every record. With `lines` holding the 16 qualifying records in order, I built the witness as follows:

```python
import hashlib

# lines = the 16 fully validated DP-7 witness lines, in ascending gateway_seq
witness = 'RRCA-DAWN-WITNESS-v1\n' + ''.join(line + '\n' for line in lines)
raw = witness.encode('ascii')
print(len(raw))
digest = hashlib.sha256(raw).hexdigest()
print('CSCTF{dawn_' + digest + '}')
```

The witness was 1,733 bytes. Its SHA-256 was `12d6b2bf2703a884e970e2c4d0070c894c8cf53be91d44feabeb44e18c02eefb`, which gave me the flag.

## Flag

```text
CSCTF{dawn_12d6b2bf2703a884e970e2c4d0070c894c8cf53be91d44feabeb44e18c02eefb}
```

> **Note:** The extraction command records 122,618,880 bytes, but the ext4 geometry implies 122,683,392 bytes. That 64,512-byte difference remains unresolved. The full DP-7 rules and all 16 witness records are not included here; the final digest is retained from the original solve.
