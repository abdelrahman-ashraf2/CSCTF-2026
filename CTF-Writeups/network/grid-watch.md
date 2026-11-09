## 1. Title 
# Grid Watch

## 2. Introduction
The challenge involved analyzing a MAVLink 2 recording and a field-provisioning note to recover the information needed to authenticate a new signing configuration and issue a reposition command.

## 3. Initial Reconnaissance
The recording used TLOG framing: an 8-byte big-endian timestamp followed by a MAVLink 2 frame. The MAVLink 2 header was 10 bytes, and signed frames included a 13-byte signature.

The provisioning note specified a 10-microsecond RTC timestamp and:

```text
prov_key = HKDF-SHA256(
    ikm  = serial_ascii || commissioning_epoch (uint64 LE, seconds),
    salt = session_nonce,
    info = "CX-PROV/v1",
    L    = 32
)
```

## 4. Investigation
The first parser incorrectly assumed a 12-byte MAVLink header. After correction, 24 records parsed with no leftover bytes. The drone serial was `CX-FALCON-9951`; all captured frames used link ID 249.

Decoded traffic included HEARTBEAT, STATUSTEXT, COMMAND_LONG, COMMAND_ACK, and GLOBAL_POSITION_INT. The live banner disclosed a session nonce. Unsigned probes were rejected.

A least-squares RTC model produced approximately 17 ppm drift. Combining capture and live observations yielded commissioning epoch `1733965123`.

Inspection of `pymavlink` showed the signing structure and MAC construction:

```text
SHA256(secret_key, header || payload || CRC16 || link_id || timestamp48)[:6]
```

## 5. Exploitation
The provisioning key was derived using the serial, epoch, live nonce, and specified HKDF parameters. A new signing key was installed through `SETUP_SIGNING`.

The first attempt reached provisioning and arming but used command ID 195, which was incorrect. The dialect identified `MAV_CMD_DO_REPOSITION` as 192.

A second connection provided a new nonce. The corrected sequence installed signing, entered GUIDED mode, armed, and issued command 192. The service returned:

```text
CSCTF{1ZNfUqGfAkLYf4f1wYntjT9g}
```

## 6. What I Cannot Confirm
The internal RTC implementation and HKDF implementation were not inspected. The lack of a static RTC offset was inferred from observed convergence and successful acceptance.

## 7. Root Cause
The serial, nonce, and commissioning epoch needed to derive the provisioning credential were recoverable from observable link data. The provisioning mechanism exposed the inputs required to reconstruct its authentication key.

## 8. Validation
Confirmed: 24 parsed records, serial extraction, live nonce, RTC model, epoch estimate, provisioning acceptance, new signing key activation, GUIDED and ARM acknowledgements, corrected reposition ACK, and returned flag.

## 9. Conclusion
Recovering the provisioning inputs enabled installation of a new signing key. Correcting the command identifier completed the reposition operation.

## 10. AI Methodology
**AI contribution:** organized MAVLink framing, RTC reasoning, HKDF explanation, and validation.

**Personally verified:** capture parsing, message decoding, RTC fit, nonce retrieval, unsigned rejection, signing-source inspection, provisioning, mode changes, arming, command acceptance, and flag.

**Correctness statement:** Key derivation was behaviorally confirmed by server acceptance; the final command was confirmed by ACK result 0 and the flag-bearing STATUSTEXT.
