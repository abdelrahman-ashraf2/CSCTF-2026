# Onion Deanon 2: Hash the Favicon Again — Chronos Security CTF

**Writeup Author:** [CONFIRM — not recorded]

## Introduction

Second deanonymization task in the same series, this time against a ransomware negotiation portal for a group called DarkPigeon. The ask was to produce a Shodan-style favicon hash for the portal's icon, and separately its MD5. The portal page was otherwise static and unremarkable, which pushed the whole exercise onto a single asset: whatever the favicon leaked. This writeup follows the actual order of operations, including the one place I had to second-guess which hashing convention Shodan actually uses.

## Initial Reconnaissance

Target: `http://schpqwdfzcmdcbim7w24jj5ph5h6fqvcbj5zhkhof3z3v75ydljkzsad.onion`, plain HTTP this time, not HTTPS. Tor was run the same way as the previous challenge — local build, poll for `Bootstrapped 100`, work, kill — with everything routed through the SOCKS port:

```bash
curl -s --socks5-hostname 127.0.0.1:9050 "http://$ONION/" -o portal.html
curl -s --socks5-hostname 127.0.0.1:9050 "http://$ONION/favicon.ico" \
  -o darkpigeon_favicon.ico
```

The page itself is a single static screen, titled "DarkPigeon | Negotiation Portal," served from plain nginx. A quick sweep of `/robots.txt`, `/sitemap.xml`, `/admin`, `/api`, `/victims`, and a handful of other guessed paths all came back 404. With nothing else on the server worth fingerprinting, the favicon was the only asset in play — a 6,434-byte multi-size `.ico` file, SHA-256 `195873a07c938f21ef8c016048230bc84861d08653e8c01ccf3620089c848dea`.

## Investigation

Shodan's favicon hash isn't a plain hash of the file — it's MurmurHash3 (x86_32 variant) computed over the file's bytes *after* they've been run through `base64.encodebytes`, with the result read as a signed 32-bit integer. Rather than depend on the `mmh3` package being available (or matching Shodan's exact build), I implemented the algorithm directly in Python so the result wouldn't depend on any third-party library behaving a particular way:

```python
import base64

def mmh3_x86_32(data: bytes, seed: int = 0) -> int:
    c1, c2 = 0xCC9E2D51, 0x1B873593
    h = seed & 0xFFFFFFFF
    for i in range(len(data) // 4):
        k = int.from_bytes(data[i*4:(i+1)*4], 'little')
        k = (k * c1) & 0xFFFFFFFF
        k = ((k << 15) | (k >> 17)) & 0xFFFFFFFF
        k = (k * c2) & 0xFFFFFFFF
        h ^= k
        h = ((h << 13) | (h >> 19)) & 0xFFFFFFFF
        h = (h * 5 + 0xE6546B64) & 0xFFFFFFFF
    tail = data[(len(data) // 4) * 4:]
    if tail:
        k = 0
        for i, b in enumerate(tail):
            k ^= b << (8 * i)
        k = (k * c1) & 0xFFFFFFFF
        k = ((k << 15) | (k >> 17)) & 0xFFFFFFFF
        k = (k * c2) & 0xFFFFFFFF
        h ^= k
    h ^= len(data)
    h ^= h >> 16; h = (h * 0x85EBCA6B) & 0xFFFFFFFF
    h ^= h >> 13; h = (h * 0xC2B2AE35) & 0xFFFFFFFF
    h ^= h >> 16
    return h - 0x100000000 if h >= 0x80000000 else h

print(mmh3_x86_32(base64.encodebytes(open('darkpigeon_favicon.ico','rb').read())))
```

The detail that actually mattered here was which base64 encoder to use. `base64.encodebytes` line-wraps its output (76 characters per line, trailing newline); `base64.b64encode` doesn't. Shodan's convention uses the line-wrapped form, and the two give different hashes — I checked this directly rather than assuming, and got `-209798607` from the wrapped encoding versus `-1362675922` from the flat one. Getting this wrong would have produced a confident-looking but useless pivot value.

## Exploitation

With the correct encoding, the favicon hash came out to `-209798607` (unsigned equivalent `4085168689`), and I cross-checked it against an independent pure-Python MurmurHash3 implementation, which agreed. The file's MD5 — the second value the challenge asked for — is `ad866421d43a616ab0e4dd089fc94b06`. This is the digest Shodan would index as `http.favicon.hash:-209798607`, and it ties the icon (not the onion address) to any other host serving the same file.

[CONFIRM — flag format]: My notes on the final flag are inconsistent. I initially wrote down `CSCTF{-209798607}` for the Shodan favicon hash, then noted that the expected wrapper actually wanted the favicon's MD5 instead, and the line recording that correction nested the wrapper (`CSCTF{CSCTF{ad866421d43a616ab0e4dd089fc94b06}}`) — clearly a copy/paste artifact rather than the intended string. The value I have actual confidence in is the plain MD5, so I'm reporting the flag as `CSCTF{ad866421d43a616ab0e4dd089fc94b06}`, with the understanding that I did not confirm this against a scoring platform in this session.

## Root Cause

1. A static asset served identically across deployments — here, a default or reused favicon — is a fingerprintable artifact independent of hostname or onion address, by design of services like Shodan that index exactly this.
2. The ambiguity in which base64 variant feeds the hash isn't a vulnerability in the target; it's a correctness trap in the *analysis tooling*, worth calling out because it's the kind of mistake that produces a plausible wrong answer rather than an obvious error.

## Validation

**What was confirmed in testing:**
- The portal's only fingerprintable asset is `favicon.ico`; all probed paths besides the homepage returned 404.
- The favicon's SHA-256 is `195873a07c938f21ef8c016048230bc84861d08653e8c01ccf3620089c848dea` and its MD5 is `ad866421d43a616ab0e4dd089fc94b06`.
- The Shodan-style MurmurHash3 hash, computed over `base64.encodebytes`-wrapped file bytes, is `-209798607`, cross-confirmed with an independent implementation.
- Using the flat (`b64encode`) base64 variant instead produces a different, incorrect hash (`-1362675922`), confirming the encoding choice is significant.

**What was not confirmed in my own session, and must not be claimed:**
- Which of the two values (favicon hash vs. MD5) the scoring platform actually expected in the flag wrapper — I have no recorded submission confirming either.
- Whether this favicon appears on any other indexed host; I didn't run that pivot.

## Conclusion

This task hinged entirely on reproducing Shodan's favicon-hashing convention exactly, not on breaking anything. The interesting part — and the one place that could silently go wrong — was the base64 encoding step feeding the MurmurHash3 input; the line-wrapped and flat variants diverge completely, and only one matches what Shodan actually indexes. Everything else was routine extraction and hashing over a Tor SOCKS proxy.
