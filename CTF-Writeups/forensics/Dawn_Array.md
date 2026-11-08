# Dawn Array

**Category:** Forensics

## Solution

1. I read the md metadata from the three surviving disks. The missing volume was a four-disk RAID-5 array with left-symmetric layout, 32 KiB chunks, and a 1 MiB data offset.
2. I used the ext4 magic at logical offset `0x438` to identify `acq-1.raw` as role 0. The root directory only parsed after I assigned `acq-2.raw` to role 3 and `acq-3.raw` to role 2. A valid superblock alone had not confirmed the disk order.
3. I extracted `rrca-dispatch-procedure.txt`, the SQLite database and WAL, the syslog, and the HTTP pcapng. I opened a copy of the database beside its matching WAL so committed, uncheckpointed rows were included.
4. I followed DP-7's Q1–Q5 checks across the ledger, the four syslog phases, and the HTTP reservation/readback exchanges. Of 128 cycles, 16 passed:

   ```text
   14,15,34,35,55,69,78,79,80,83,85,87,95,103,110,117
   ```

5. I sorted those cycles by `gateway_seq`. Each witness line used this field order:

   ```text
   cycle_id|request_id|prepare_revision|reservation_nonce|release_register|release_value
   ```

6. I prefixed the ASCII lines with `RRCA-DAWN-WITNESS-v1\n`, kept an LF after every line, and calculated SHA-256. My saved result records a 1,733-byte witness and the digest used in the flag below.

## Flag

```text
CSCTF{dawn_12d6b2bf2703a884e970e2c4d0070c894c8cf53be91d44feabeb44e18c02eefb}
```

> **Note:** The original disks and complete witness are absent, so I could not recompute the final hash. My saved extraction command requests 122,618,880 bytes, but the reported filesystem needs 122,683,392 bytes: a 64,512-byte discrepancy that remains unresolved.
