# CSCTF 2026 — Smuggler Writeup

**08/11/2026**

---

> **CTF:** CSCTF 2026  
>  **Challenge:** Smuggler  
>  **Category:** Web  
>  **Author:** Iulian Schifirnet  
>  **Team:** XREFctf  
>  **Writeup Author:** Mahmoud Adel

## Introduction

Hey everyone! My name is **Mahmoud Adel** — a cybersecurity enthusiast passionate about red teaming and CTFs. Today I’m walking through how I solved the **Smuggler** web challenge from **CSCTF 2026**.

The challenge presented a web application called **Meridian Reporting**, an internal reporting portal. The dashboard listed 16 returns, and one of them — *“Operation Dawn corridor logistics packet”* — was marked **Controlled** and **Withheld** instead of being open for download. The objective was to recover that withheld packet.

Let’s get right into it!

---

## Initial Reconnaissance

I opened the dashboard and examined the report table. Fifteen reports were listed as **Public** with a clickable `Open` action. The sixteenth was the logistics packet, marked **Controlled**, with the action column simply displaying `Withheld`. There was no link or button to interact with in the UI.

That was the first indicator: the report was not protected by a server-side authentication gateway or role check on the view; it was merely hidden from the rendered interface.

I inspected the HTML source and the inline JavaScript. The page embedded a `window.__CATALOG__` object that contained metadata for every report on the register, including the controlled one. The controlled report had an identifier:

```text
cfb85cc8f772b140
```

Because that identifier was already shipped to the client browser in the initial page payload, the restriction was purely cosmetic and client-side.

---

## Investigation and Exploitation

### Step 1 — Direct access to the report

I requested the report endpoint directly:

```http
GET /d/cfb85cc8f772b140 HTTP/1.1
Host: <instance>
```

The server returned the full report page with an HTTP `200 OK` status. There was no authentication challenge, no cookie required, and no authorization check. The “controlled, released on request” rule was enforced exclusively in the dashboard UI presentation logic, not on the backend endpoint.

### Step 2 — Inspecting the export structure

The recovered report page contained another inline JavaScript object responsible for client-side document rendering:

```javascript
window.__EXPORT__ = {
    parts: [ ... ],       // split Base64 string
    alphabet: "...",      // custom alphabet, not standard Base64
    seed: 123456789       // XOR keystream seed
};
```

Analyzing this structure revealed two layers of obfuscation:

1. **Custom Alphabet Base64:** The `parts` array held a Base64-encoded payload, but encoded using a shuffled custom alphabet instead of RFC 4648 standard Base64.
2. **PRNG Keystream XOR:** The `seed` initialized a **xorshift32** pseudo-random number generator (PRNG) to generate an XOR keystream against the decoded bytes.

Because both the algorithm and the key/seed were delivered directly to the client browser, this represented client-side obfuscation rather than real cryptography.

### Step 3 — Reversing the obfuscation

To recover the original packet, I reversed both transformations in opposite order:

1. Concatenate all elements of `parts` into a single continuous string.
2. Translate the custom alphabet mapping back to standard Base64 characters.
3. Base64-decode the translated string into raw ciphertext bytes.
4. Replicate the `xorshift32` PRNG sequence initialized with `seed` and XOR each byte.
5. Decompress the resulting bytes as a ZIP archive.

Here is the solve script:

```python
import base64, io, json, re, string, zipfile, requests

URL = "http://<instance>/d/cfb85cc8f772b140"
html = requests.get(URL).text
cfg = json.loads(
    re.search(r"window\.__EXPORT__\s*=\s*(\{.*?\});", html, re.S).group(1)
)

STD = string.ascii_uppercase + string.ascii_lowercase + string.digits + "+/"
alpha = cfg["alphabet"]

packed = "".join(cfg["parts"])
standard_b64 = "".join(
    "=" if ch == "=" else STD[alpha.index(ch)]
    for ch in packed
)

raw = base64.b64decode(standard_b64)

x = cfg["seed"] & 0xFFFFFFFF
def next_byte():
    global x
    x ^= (x << 13) & 0xFFFFFFFF
    x ^= x >> 17
    x ^= (x << 5) & 0xFFFFFFFF
    x &= 0xFFFFFFFF
    return x & 0xFF

plain = bytes(b ^ next_byte() for b in raw)

with zipfile.ZipFile(io.BytesIO(plain)) as z:
    print(z.namelist())
    for name in z.namelist():
        print(f"\n===== {name} =====")
        print(z.read(name).decode())
```

Running the script produced a valid ZIP stream — the leading magic bytes `50 4B 03 04` verified a clean archive.

### Step 4 — Extracting the packet

Inspecting the archive yielded three files:

```text
00-cover-note.txt
01-distribution.txt
02-release-authorization.txt
```

The first two files provided operational and contextual background matching the scenario briefing. The third file (`02-release-authorization.txt`) contained the authorization code:

```text
Authorization code: CSCTF{<REDACTED>}
```

---

## Root Cause \& Technical Explanation

The challenge chained two fundamental security mistakes:

1. **Client-side hiding confused with access control (IDOR):** The application relied on the frontend dashboard to withhold the download link for controlled items, while shipping the resource identifier (`cfb85cc8f772b140`) in global JavaScript scope (`window.__CATALOG__`). The backend `/d/<id>` handler performed no access-control checks on requests.
2. **Security through obscurity:** Delivering sensitive data to a client browser while relying on custom Base64 alphabets and seeded XOR PRNGs fails to provide confidentiality. Any algorithm and seed delivered to the user agent can be readily extracted and reversed.

---

## Final Result \& Flag

Executing the decoding routine extracted the archived files and retrieved the authorization token flag:

```text
CSCTF{<REDACTED>}
```

The flag format was verified against the challenge specification. *(Note: The live flag string has been redacted per competition rules).*

---

## Conclusion \& Key Takeaways

1. **Access control must be enforced on the server:** Hiding elements in the DOM or omitting links from frontend tables provides zero security. Every request to an object identifier must verify authorization on the backend.
2. **Never send confidential data with client-side decryption:** If the client possesses the ciphertext, the algorithm, and the key/seed, the data is effectively plaintext. Access controls must prevent unauthorized retrieval before transmission.

---

## AI Methodology

During this challenge, I used an AI assistant for:

- Analyzing the JavaScript `window.__EXPORT__` structure and understanding the custom alphabet and `xorshift32` generator.
- Drafting the initial Python decoding script.
- Organizing and formatting this technical writeup.

All requests were sent against the live instance manually from my workstation, and I personally inspected and confirmed the ZIP archive output and the flag in `02-release-authorization.txt`.

*No live flags, credentials, tokens, or instance URLs are included in this writeup.*

---

*Thanks for reading — hope this writeup helped someone learn something new. Happy hacking!*

[This post](https://m2hmoud2del.github.io/posts/csctf-2026-smuggler/) is licensed under [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/) by the author.
