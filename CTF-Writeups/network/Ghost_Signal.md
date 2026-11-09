# Ghost Signal — CSCTF
- **Category:** Network

## 2. Introduction
The challenge supplied an SS7 capture, a Diameter capture, and a billing export. The goal was to correlate a common intrusion identity and calculate a SHA-256 marker using the briefing's serialization rule.

## 3. Initial Reconnaissance
Files:
- `billing_events.json`
- `diameter_capture.pcap`
- `ss7_capture.pcap`

The billing export contained 40 events: 30 normal, 5 attack, and 5 pivot events. Anomalous records shared IMSI `226012014000001` and a Diameter session suffix `49211`.

## 4. Investigation
Diameter analysis identified anomalous packets from `10.40.0.99`, with origin host `cscf.rogue.evil-domain.net`, IMSI `226012014000001`, and target SIP identity `sip:+40721000101@eastern-tele.ro`.

SS7 analysis found destination point code 1337 and anomalous originating point codes in packets 45–59. TBCD decoding of the global-title bytes `94 12 f1` yielded `49211`. MAP TBCD bytes decoded to the same IMSI.

The first anomalous billing timestamp was `1723740150`, and the full session ID was:

```text
hss.eastern-tele.ro;1723740150;49211
```

Two hash attempts using incorrect concatenation/separator variants failed. The briefing specified the exact rule:

```text
sha256("<imsi>:<full_diameter_session_id>:<unix_timestamp>")[:8]
```

## 5. Exploitation
The exact serialized input was:

```text
226012014000001:hss.eastern-tele.ro;1723740150;49211:1723740150
```

The SHA-256 digest began:

```text
28358943743f95eb
```

The resulting flag was:

```text
CSCTF{28358943}
```

## 6. What I Cannot Confirm
Author and team were not provided. A successful platform submission was not recorded. The serialization rule came from the briefing, not independent discovery.

## 7. Root Cause
This was a forensic correlation challenge, not a demonstrated software vulnerability. The common IMSI, global title, session suffix, and timestamp linked the three artifacts.

## 8. Validation
Confirmed: billing anomaly, Diameter AVPs, SS7 point codes, global-title TBCD, MAP IMSI decoding, matching identifiers, timestamp selection, and local SHA-256 calculation.

Not confirmed: platform acceptance.

## 9. Conclusion
Cross-artifact correlation identified the common telecom incident. The briefing's exact serialization rule resolved the remaining ambiguity and allowed calculation of the flag.

## 10. AI Methodology
**AI contribution:** organized the multi-protocol investigation and clarified TBCD and correlation.

**Personally verified:** billing parsing, Diameter analysis, SS7 analysis, TBCD decoding, timestamp selection, and digest calculation.

**Correctness statement:** The identifiers were corroborated across all three artifacts; the hash format followed the briefing.
