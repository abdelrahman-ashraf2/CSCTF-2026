# Operation Blackout — Chronos Security CTF

## Introduction

Five artifacts from one substation, describing the same power-loss incident from five different operational layers — an HMI config, an event log, an alarm file, a firmware image, and a network capture. The challenge statement spelled out the flag construction up front: the first 8 lowercase hex characters of `sha256("0x<FIRMWARE_FIRST_4_BYTES_UPPER_HEX>:0x<STATION_ID>:<LOG_TIMESTAMP>:<REGISTER_DECIMAL>:<SEED_DECIMAL>")`, with one named decoy (`scada_blackout_2026`) that must not enter the preimage. So the actual work wasn't guessing a scheme — it was pulling five specific fields out of five specific artifacts and making sure they agreed with each other before trusting any of them. This writeup follows the solve in the order the fields were recovered, including the one timestamp assumption that turned out to be wrong.

## Initial Reconnaissance

The HMI config and event log were plain text, so their values were readable immediately:

- `hmi_config.xml`: station_id `0x4A2E`, a `CalibrationRoutine` with `ManifestSeed 137`, and a `HiddenModbusWrite` with `function_code="16"`, `start_address="40001"`, `count="64"`, payload `55 FA` repeated eight times, targeting `192.168.50.10:502` over Modbus/TCP.
- `substation_log.json`: a startup entry with `manifest_seed: 137`, and at `2025-11-15T06:15:03Z` a `WARNING` — *"Unexpected Modbus FC 0x10 write to read-only registers 40001-40064"* — followed by `CRITICAL` entries for a Modbus TCP buffer overflow (247 bytes against a 128-byte limit), alarm threshold tampering, a firmware integrity failure, and an outage logged at `2025-11-15T06:30:00Z`.

That pinned three of the five preimage fields immediately: station `0x4A2E`, seed `137`, register `40001`. The other two — the firmware's first four bytes and the timestamp of the malicious write — had to come from raw binary artifacts, not text.

## Investigation

**Firmware header.** The spec explicitly warns the required input is the raw header bytes, not any decoded version string — a trap worth calling out, because the version string sits right next to the real answer:

```python
data = open('plc_firmware.bin','rb').read()
print(len(data), data[:16].hex(' '), data[:16])
```

```
1024  50 4c 43 31 56 33 2e 32 2e 31 00 00 7f 00 00 04  b'PLC1V3.2.1\x00\x00\x7f\x00\x00\x04...'
```

First four bytes: `50 4C 43 31`, ASCII `PLC1`, i.e. `0x504C4331`. `V3.2.1` sits immediately after — exactly the decoy the spec calls out by name, which made it easy to confirm I hadn't grabbed the wrong substring.

**Alarm file, second confirmation of the station ID.** `alarm_override.dat` opens with magic `ALRM`, then `2E 4A` — little-endian for `0x4A2E` — which matched the HMI's station ID from a second, independent source before I trusted it.

**PCAP, first attempt failed by design.** I tried a naive byte-pattern scan for the expected Modbus FC16 shape before parsing the capture container properly, and got nothing:

```
fc16 addr0 count64 hits: []
10 00 occurrences: 0
pcap magic: d4 c3 b2 a1
```

In hindsight the miss made sense — the real write bytes start `01 10 9C 41`, so no literal `10 00` sequence exists anywhere in the file. The lesson was to stop pattern-guessing and parse the container: the magic `d4 c3 b2 a1` identified a little-endian classic pcap, so I unpacked record headers with `<IIII`, walked Ethernet → IPv4 → TCP, and filtered on port 502 (already identified as the Modbus/TCP port from the HMI config).

That found 31 packets between `192.168.50.5` and the PLC at `192.168.50.10`. Packets 1–30 are identical FC03 polls every ten seconds; packet 31 is the outlier:

```
#31 ts=1763186703  192.168.50.5:40000 -> 192.168.50.10:502
    00 02 00 00 00 17 01 10 9c 41 00 40 10 55 fa 55 fa 55 fa [...]
```

Decoded: unit 1, function code `0x10` (write multiple registers), start address `0x9C41` = `40001`, count `0x40` = `64` registers, 16 data bytes of `55 FA × 8`. This matches the HMI's `HiddenModbusWrite` exactly on function code, register, count, and payload — independent confirmation from a third artifact.

## Exploitation

**The timestamp, and the one assumption that failed.** The log's `WARNING` entry for the FC16 write carries `2025-11-15T06:15:03Z`. I initially assumed the pcap's own epoch (`1763186703`) represented that same moment and wrote an assertion into the final script to confirm it. The assertion failed:

```
1763186703            -> 2025-11-15T06:05:03Z
1763186410            -> 2025-11-15T06:00:10Z
2025-11-15T06:00:00Z  -> epoch 1763186400
```

The capture's embedded clock runs on a compressed timeline relative to the log: the polling cadence (ten-second intervals across roughly five minutes of captured traffic) places the write at `06:05:03` in capture-time, while the log records `06:15:03Z`. The spec explicitly names the *log entry* as the timestamp source for the preimage, so this discrepancy doesn't change which value goes into the hash — it just means the pcap corroborates the write's existence and shape, not its wall-clock time. As a side check, the first `CRITICAL` entry (the buffer overflow) shares the same `06:15:03Z` timestamp as the `WARNING`, so either reading of "first critical timestamp" would have produced the same string anyway.

**Hash computation.**

```python
import hashlib
firmware_header_hex = '0x' + open('plc_firmware.bin','rb').read()[:4].hex().upper()  # 0x504C4331
station_hex         = '0x4A2E'                  # HMI config; alarm_override.dat bytes 2E 4A (LE)
log_timestamp_iso   = '2025-11-15T06:15:03Z'    # log WARNING: FC 0x10 write to 40001-40064
register_decimal    = '40001'                   # HMI start_address; pcap 0x9C41; log 40001-40064
seed_decimal        = '137'                     # HMI ManifestSeed; startup log manifest_seed

plaintext = ':'.join([firmware_header_hex, station_hex, log_timestamp_iso,
                      register_decimal, seed_decimal])
print('preimage :', plaintext)
print('FLAG     : CSCTF{' + hashlib.sha256(plaintext.encode()).hexdigest()[:8] + '}')
```

```
preimage : 0x504C4331:0x4A2E:2025-11-15T06:15:03Z:40001:137
sha256   : 12fcdb0d35f7fde4685d2f6995958f107ec9b5dd8a2ffd74e8fd44a6ff8ea85bFLAG     : CSCTF{12fcdb0d}
```

I did not independently verify this hash against a submission platform; this was a self-contained, offline constructed case with no live scoring step, so correctness here rests on format compliance and cross-artifact agreement rather than external acceptance.

## Root Cause

1. **The challenge's premise isn't a software flaw but an evidentiary reconstruction exercise** — each required field has at least two independent sources (XML, log, alarm file, or pcap), which is a deliberate design choice to let the solver cross-verify rather than guess.
2. **The one genuine trap is in the analysis, not the data:** the firmware version string sits immediately after the real header bytes, and the pcap's internal clock does not match the log's wall-clock reference. Both are "design choices that aren't themselves wrong but produce a wrong answer if the solver assumes rather than checks" — exactly the distinction the format calls for.

## Validation

**What was confirmed in testing:**
- Firmware header bytes: `50 4C 43 31` (`PLC1`), i.e. `0x504C4331`.
- Station ID `0x4A2E`, confirmed independently via the HMI config and the alarm file's little-endian bytes.
- Seed `137`, confirmed via both the HMI `ManifestSeed` and the log's startup `manifest_seed`.
- Register `40001`, confirmed via the HMI config, the pcap's FC16 write (`0x9C41`), and the log's register range.
- The malicious Modbus write is packet 31 of 31 in the capture, matching the HMI's hidden write on function code, address, count, and payload.
- The preimage `0x504C4331:0x4A2E:2025-11-15T06:15:03Z:40001:137` hashes (SHA-256, first 8 hex chars) to `12fcdb0d`.

**What was not confirmed in my own session, and must not be claimed:**
- No live submission or scoring confirmation exists for this flag; this was an offline constructed exercise with no platform to validate against.

## Conclusion

The chain here was cross-artifact corroboration rather than exploitation: five sources, five fields, and one deliberate false assumption about which clock to trust. The failed assertion on the pcap timestamp was the most useful moment in the whole session — it converted an unexamined guess into an explicit, checked decision, and it's the kind of mistake that silently produces a wrong flag if you don't bother to verify it against a second source.

## Flag

```
CSCTF{12fcdb0d}
```
