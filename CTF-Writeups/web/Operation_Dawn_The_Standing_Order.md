## 1. Title + Metadata
#  Operation Down: The Standing Order
## 2. Introduction
The target was a relay console that issued an unauthenticated operator session. The challenge required reaching an administrator-only relay and then using it to query an internal provisioning service.

## 3. Initial Reconnaissance
Target: `http://w02.ctf.chronos-security.ro:33538/`

The cookie format was:

```text
hex(payload).signature
```

The decoded payload was:

```text
user=guest&role=operator
```

The signature was 40 hexadecimal characters, consistent with SHA-1. `/relay` required administrator access.

## 4. Investigation
A plain SHA-1 of the payload did not match. Payload tampering without a valid signature returned 403. Approximately 280 candidate secrets were tested against secret-prefix SHA-1, suffix SHA-1, HMAC-SHA1, and other variants without a match.

The remaining hypothesis was a secret-prefix SHA-1 construction vulnerable to length extension. The first implementation had message-schedule, register-rotation, and glue-padding bugs. After correction, the resumed hash implementation passed a self-test against `hashlib`.

The length sweep found an accepted candidate at secret length 16.

## 5. Exploitation
The extended payload appended:

```text
&role=admin
```

after the original payload and SHA-1 glue padding. The server accepted the extended signature, and `/relay` displayed administrator controls.

The page exposed internal nodes, the provisioning URL `http://127.0.0.1:9091/order`, and `/relay/probe?target=<node-url>`.

Literal loopback forms were refused. Several alternative representations were tested. The following returned the internal standing order:
- `127.1`
- `2130706433`
- `0177.0.0.1`

The final request used:

```text
http://127.1:9091/order
```

The response contained:

```text
CSCTF{3BrKPcchnay2Clm3Ju5z8BLo}
```

## 6. What I Cannot Confirm
Author and team were not provided. The exact backend MAC implementation and URL parser were not inspected. The internal resolution path for each successful loopback representation was not independently confirmed.

## 7. Root Cause
The session used secret-prefix SHA-1 rather than HMAC, enabling length extension. The application accepted duplicate role parameters and used the appended administrator value. The SSRF filter relied on blocking hostname strings rather than validating the resolved destination address.

## 8. Validation
Confirmed: cookie decoding, plain-SHA mismatch, tampering rejection, candidate-secret tests, SHA-1 self-test, accepted length extension, admin relay access, SSRF filter behavior, alternative loopback tests, and returned standing order.

## 9. Conclusion
The solve chained a SHA-1 length-extension weakness with an SSRF hostname-filter bypass. The hash self-test was important because it caught implementation errors before testing the server.

## 10. AI Methodology
**AI contribution:** organized the authentication and SSRF stages, explained length extension, and separated filter refusal from fetch failure.

**Personally verified:** cookie analysis, hash implementation and self-test, length sweep, forged session, relay access, SSRF tests, and flag retrieval.

**Correctness statement:** The length-extension code passed a `hashlib` self-test; administrator access and internal retrieval were confirmed by server responses.
