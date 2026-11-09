# Onion Deanon 1: Fingerprint the Certificate — Chronos Security CTF

**Date:** [CONFIRM — exact solve date not recorded in my notes]
**CTF:** Chronos Security CTF *(inferred from the `CSCTF{}` flag prefix and the `*.ctf.chronos-security.ro` challenge infrastructure seen across this event; not stated explicitly anywhere in my notes)*
**Challenge:** Onion Deanon 1: Fingerprint the Certificate
**Category:** OSINT
**Author:** [CONFIRM — challenge author not recorded]
**Team:** [CONFIRM — team name not recorded]
**Writeup Author:** [CONFIRM — not recorded]

## Introduction

This one came out of a ransom note that pointed at a leak blog for a group calling itself ParsnipLocker, hosted as a hidden service that answers `https://` directly on the onion address itself. The prompt was simple on its face: pull the TLS certificate the service presents and turn it into a stable fingerprint. The implication is that the certificate survives independently of the onion address — a hidden service operator who reuses a key pair across infrastructure leaves a trail that scan datasets like Shodan or Censys can pick up later. This writeup follows the session in the order I actually worked it, and it's short because the task itself was short: fetch, parse, hash, done.

## Initial Reconnaissance

The onion address was `4uybrxybehxbf646wqbnyjxyjk2xis6mpvo4d57dv25zf5jsazf5tsad.onion`, reachable over `https://`. That detail matters on its own: a `.onion` address has no CA hierarchy behind it, so a hidden service terminating TLS is necessarily presenting a self-signed certificate the operator generated themselves. Trying to fetch the page without `-k` confirmed this immediately — `curl` refused with `SSL certificate problem: self-signed certificate` before I'd even looked at the cert.

Tor was run locally from a user-space build with a throwaway pattern I use for this kind of task: start the process, poll the notice log until it reports `Bootstrapped 100`, do the work, kill it. All requests went through the local SOCKS port:

```bash
curl -sk --socks5-hostname 127.0.0.1:9050 -D headers.txt \
  -o blog.html "https://$ONION/"
curl -sk --socks5-hostname 127.0.0.1:9050 -o /dev/null -w '%{certs}' \
  "https://$ONION/" > chain.pem
```

The index page came back `HTTP 200`, served by nginx, with `Last-Modified: Wed, 21 Oct 2026 16:34:49 GMT`. I kept that timestamp around — it turned out to matter later.

## Investigation

The chain pulled from `%{certs}` contained exactly one certificate, so there was no intermediate to worry about. Parsing the leaf:

```bash
openssl x509 -in leaf.pem -noout -subject -issuer -serial -dates \
  -fingerprint -sha256 -ext subjectAltName
```

```
subject=CN=4uybrxybehxbf646wqbnyjxyjk2xis6mpvo4d57dv25zf5jsazf5tsad.onion
issuer=CN=4uybrxybehxbf646wqbnyjxyjk2xis6mpvo4d57dv25zf5jsazf5tsad.onion
serial=6FDBE5407014B76F971FAFC7E888BD66FEC5D2FD
notBefore=Oct 21 16:16:20 2026 GMT
notAfter=Oct 18 16:16:20 2036 GMT
sha256 Fingerprint=14:BF:CD:53:D5:09:FE:DF:0C:A4:FE:7E:9A:3D:6F:E2:A0:45:1F:4E:DA:F7:76:39:EB:BC:0F:ED:93:EB:23:80
X509v3 Subject Alternative Name:
    DNS:4uybrxybehxbf646wqbnyjxyjk2xis6mpvo4d57dv25zf5jsazf5tsad.onion
```

Subject and issuer are identical, confirming a self-signed RSA-2048 certificate valid for ten years. The one thing worth flagging explicitly: `notBefore` sits at 16:16:20 UTC, about eighteen minutes before the blog's `Last-Modified` at 16:34:49 UTC, on the same day. That gap is small enough to suggest the certificate and the site content were generated in the same provisioning session — not proof of anything by itself, but a useful detail for a timeline if this were a real investigation rather than a lab exercise.

## Exploitation

There isn't really an exploitation step here in the pwn/web sense — the "primitive" being chained is just extraction and normalization. I took the SHA-256 fingerprint from the `openssl` output and normalized it to lowercase hex with no colons:

```
14bfcd53d509fedf0ca4fe7e9a3d6fe2a0451f4edaf77639ebbc0fed93eb2380
```

That's the value a Shodan `ssl.cert.fingerprint:` or Censys `services.tls.certificates.fingerprint:` query would pivot on, and it's independent of the onion address — if the operator reuses this key pair on a second hidden service, this hash is how the two get tied together.

[CONFIRM — flag wrapper]: My session notes record the fingerprint above as fully verified, but the `CSCTF{...}`-wrapped string I wrote down afterward reads `CSCTF{4bfcd53d509fedf0ca4fe7e9a3d6fe2a0451f4edaf77639ebbc0fed93eb2380}` — one hex character short of the fingerprint I actually computed (missing the leading `1`). I don't have a record of submitting either string to a scoring platform, so I can't say whether the short form was a transcription slip on my part or the literal expected answer. I'm reporting the fingerprint I verified against the certificate rather than asserting which wrapped form is correct.

## Root Cause

1. The hidden service terminates TLS itself with an operator-generated, self-signed certificate rather than relying on anything the Tor protocol provides for authentication — this is a design choice of the operator's setup, not a bug in Tor or in onion services generally, and it's exactly what makes the certificate a durable, capturable identifier.
2. The certificate's validity window overlapping the site's `Last-Modified` timestamp is incidental infrastructure behavior (both artifacts being generated in one provisioning pass), not something the operator set out to leak — but it's still useful corroborating evidence for a timeline.

## Validation

**What was confirmed in testing:**
- The onion service answers over HTTPS and refuses an unpinned TLS handshake without `-k`, consistent with a self-signed certificate.
- The presented chain contains exactly one certificate (the leaf, self-signed, subject == issuer).
- The SHA-256 fingerprint of that leaf, computed directly with `openssl`, is `14bfcd53d509fedf0ca4fe7e9a3d6fe2a0451f4edaf77639ebbc0fed93eb2380`.
- `notBefore` on the certificate precedes the site's `Last-Modified` header by roughly 18 minutes on the same calendar day.

**What was not confirmed in my own session, and must not be claimed:**
- Whether the `CSCTF{...}`-wrapped string is supposed to contain the full fingerprint or some truncated/altered form of it — I did not submit either variant to a scoring system during this session.
- Whether this exact certificate or key pair appears anywhere else in scan data (Shodan/Censys); I didn't run that pivot, only noted that it's the intended next step for a real investigation.

## Conclusion

The chain here was short on purpose: an `https://` onion service hands over a self-signed certificate during the TLS handshake, and that certificate's SHA-256 fingerprint is a stable identifier independent of the .onion address itself. The only mildly interesting wrinkle was timing — the certificate's issue time sat just ahead of the site's last-modified timestamp, suggesting both were generated in the same setup pass. The main lesson for future dark-web recon is procedural rather than technical: grab the certificate chain alongside the content on every hidden service visited, since `openssl`/`curl` over a SOCKS proxy is all the tooling this requires.
