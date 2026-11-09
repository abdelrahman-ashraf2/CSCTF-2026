## 1. Title 
#Silent Orbit

## 2. Introduction
The challenge required reconstructing a CFDP NAK PDU from a raw CCSDS packet recording and a relay behavior profile.

## 3. Initial Reconnaissance
The archive contained `README.txt`, `mission-profile.txt`, and `civil_downlink.bin`. Checksums passed. The recording was a raw stream, not a PCAP.

The profile specified CCSDS eligibility rules, target transaction tuple `0x01 / 0x07 / 0x02`, and a state machine: wait for Metadata, collect File Data, snapshot at the first valid EOF, then generate a NAK.

## 4. Investigation
The parser consumed all 3,432 bytes as 188 CCSDS packets, with 187 eligible. Packet 0 used the wrong APID and was excluded.

The CFDP dialect used a seven-byte header, with the data-length field representing exact body length. Metadata established a file size of 192 bytes. Packet 187 was the first valid EOF and confirmed the same size.

A decoy transaction (`03 / 09 / 02`) carried apparently useful data but was excluded by the profile. Target File Data produced 13 maximal covered intervals. Their complement over `[0,192)` contained 12 single-byte missing ranges:

```text
(5,6), (19,20), (35,36), (51,52),
(68,69), (83,84), (101,102), (119,120),
(138,139), (154,155), (171,172), (187,188)
```

The outgoing direction flag was selected as `0x28`, though its polarity remained an explicit uncertainty because the capture did not demonstrate a varying direction bit.

## 5. Exploitation
The NAK body contained directive `0x08`, scope `[0,192)`, and the 12 missing ranges, each represented by two 4-byte big-endian offsets.

The resulting PDU was 112 bytes:
- Header: 7 bytes
- Body: 105 bytes
- Length field: `0x0069`

An independent set-based implementation reproduced the same missing ranges, and parsing the generated NAK reproduced the same scope and pairs.

No platform submission occurred. The flag wrapper was not claimed as remotely accepted.

## 6. What I Cannot Confirm
Author and team were not provided. Remote acceptance was not tested. The outgoing direction-bit interpretation remained uncertain.

## 7. Root Cause
This was a protocol-reconstruction challenge rather than a demonstrated application vulnerability. Correct state-machine ordering, transaction filtering, and interval complement calculation were essential.

## 8. Validation
Confirmed: archive checksums, full stream parsing, eligibility filtering, Metadata and EOF, target transaction filtering, interval merging, 12 missing ranges, independent set-based validation, and NAK parse-back.

Not confirmed: remote acceptance and direction-bit polarity.

## 9. Conclusion
The relay state machine was reconstructed and the NAK was independently validated locally. The decoy transaction was the main coverage trap. The PDU was not submitted, so remote acceptance remains unconfirmed.

## 10. AI Methodology
**AI contribution:** organized protocol analysis and preserved the direction-bit uncertainty.

**Personally verified:** checksum, CCSDS parsing, CFDP parsing, state-machine simulation, interval calculations, NAK construction, independent validation, and parse-back.

**Correctness statement:** Local validation passed; remote acceptance was not established.
