## 1. Title + Metadata
# Severed Link

## 2. Introduction
The challenge involved recovering a current MAVLink signing key from a captured key-rotation message, validating it against later traffic, and authenticating to a live uplink gateway.

## 3. Initial Reconnaissance
The supplied artifacts included a TLOG, a PCAP, and `ops_notes.txt`. The notes stated that the key rotation had been sent in-band over the captured console link.

The correct TLOG framing was an 8-byte big-endian timestamp followed by a MAVLink 2 frame. The MAVLink 2 header was 10 bytes, with an additional 13-byte signature on signed frames.

## 4. Investigation
After correcting two parser assumptions, 107 frames were parsed. Operator frames used `sysid=255`, `compid=190`, and `link_id=0`.

Frame 59 contained `SETUP_SIGNING` (message 256). Its payload held an initial timestamp of 2295, target system 1, target component 1, and a 32-byte secret signing key.

The recovered key reproduced captured post-rotation COMMAND_INT and COMMAND_LONG signatures byte-for-byte. The rotation frame itself was not validated under the old key.

Initial UDP attempts to port 33407 were silent. A replacement endpoint on port 33451 accepted TCP, not UDP. Its banner required a signed `COMMAND_INT DO_REPOSITION` from sysid 255 and stated that replayed frames were refused.

A missing heartbeat produced `send a HEARTBEAT first`. A stale timestamp produced the gateway's current link time.

## 5. Exploitation
The final sequence used the recovered key:
1. Send signed HEARTBEAT.
2. Obtain the current link time from the stale-timestamp response.
3. Send a fresh signed HEARTBEAT.
4. Send signed `COMMAND_INT DO_REPOSITION` (command 192).

The accepted command returned:

```text
CSCTF{mEJoHOOaaStQJeeuiReBdGcu}
```

## 6. What I Cannot Confirm
The previous signing key, original rotation-frame MAC, and gateway's internal freshness-window implementation were not recovered or inspected.

## 7. Root Cause
The operator transmitted the replacement symmetric signing key over the same link it protected. The gateway's timestamp requirement prevented stale replay, but its error response disclosed the current link clock.

## 8. Validation
Confirmed: 107 frames parsed, SETUP_SIGNING key extraction, byte-for-byte validation of post-rotation signatures, TCP gateway banner, heartbeat requirement, stale-timestamp response, fresh signed command acceptance, and audit receipt.

## 9. Conclusion
The captured rotation message exposed the current signing key. Offline signature reproduction validated it, and the gateway's timestamp response enabled a fresh signed reposition command.

## 10. AI Methodology
**AI contribution:** organized MAVLink framing, key validation, endpoint investigation, and timestamp reasoning.

**Personally verified:** frame parsing, key extraction, signature reconstruction, UDP/TCP tests, gateway responses, heartbeat, command acceptance, and receipt.

**Correctness statement:** The key was validated against captured signatures; live authentication was confirmed by the gateway's acceptance response.
