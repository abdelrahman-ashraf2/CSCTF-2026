# Carrier Shadow — Chronos Security CTF


## Introduction

The bundle for this challenge simulates an AWS Lambda environment for a fictional "GridLink Dispatch" load-shedding authorization service, preserved as an evidence set after a hostile campaign: CloudTrail events, two CloudWatch log groups, function and layer version history, IAM policies, and the actual zip artifacts for three layer families and two functions. The brief is phrased as incident response — figure out what changed after a "routine deployment" — but the decisive step turned out to be disassembling shipped bytecode by hand. This writeup follows the investigation in the order I actually worked it, including the one inverted-condition mistake that nearly produced a wrong key.

## Initial Reconnaissance

```console
$ unzip -l shadow-dispatch.zip        # 57 files
$ unzip -o shadow-dispatch.zip -d work/
```

Two Lambda functions matter here: `gridlink-order-authorizer` (10 published versions) and `gridlink-order-signer` (2 versions). The `prod` alias points at authorizer version 9. A quick script summarizing the config history surfaced the first real anomaly:

```
- 1  2026-10-30T21:51:03  size 7628  sha WALoln3mPtohuwqw  layers: ['1','1','1']
- 9  2026-10-30T22:27:21  size 7628  sha WALoln3mPtohuwqw  layers: ['9','4','4']
```

All ten authorizer versions share one `CodeSha256` — the function's own code never changed — while the three attached layers (`auth-utils`, `observability-common`, `dispatch-runtime`) churn constantly across versions. That pointed the investigation at the layers rather than the function code itself. Layer zip sizes gave a second clue: `dispatch-runtime` holds steady at 6,328 bytes, `observability-common` grows once at v3 (5,355 → 5,489 bytes), and `auth-utils` alternates — 4,522 bytes on odd versions, 5,305–5,311 bytes on even versions 4, 6, 8, 10.

## Investigation

**Source diffs ruled out the obvious explanation.** Extracting every layer version and diffing them showed `observability-common`'s v2→v3 change is just a new `BASE_DIMENSIONS` constant and a redaction tweak; `dispatch-runtime`'s diffs are rule-set version bumps. The `auth-utils` *source* diff across all ten versions is a single comment line (`# build: auth-utils 1.9.0` → `1.10.0`) — nothing that would explain a 700-byte size swing. But the MD5 of every version's `__pycache__/_authlog.cpython-312.pyc` differs too, and a comment-only source change doesn't account for that on its own (pyc headers embed timestamps, so this alone wasn't conclusive either — just enough to keep looking).

**Comparing shipped bytecode against a fresh compile of the source.** I read `_authlog.py` first, since whatever was happening clearly ran through its interface. The module emits a per-invocation "telemetry" token that encodes two bytes of a 16-byte "beacon" (an XOR-keystream-and-CRC construction keyed on the request ID and a salt), and on a clean module the beacon is just `sha256(_authlog.py)[:16]` — i.e., a self-hash with no hidden payload.

No decompiler was available (`pycdc`/`uncompyle6`: not installed), so I used stdlib `marshal` and `dis` against Python 3.12.16, which matches the `cpython-312` pyc tag. Comparing module-level constants in each shipped `.pyc` against a fresh compile of its matching `.py`:

```
auth-1  match=False  consts_diff=[... nested-code digests only ...]
auth-4  consts_diff=[... "('/gridlink/portal-session-secret', '/gridlink/order-hmac-key',
                           '/gridlink/db-readonly-password', '/gridlink/metrics-api-token') ...", "'ssm'"]
auth-6, auth-8, auth-10: same SSM tuple
```

Even-numbered `auth-utils` versions (4, 6, 8, 10) carry an SSM parameter tuple in their bytecode that has no corresponding constant anywhere in the source. That's unambiguous: the shipped `.pyc` for those versions doesn't match what the `.py` would compile to. Disassembling v10 directly gave the full implant logic — it calls `boto3.client('ssm')` every fifth invocation (`order_id % 5`) and exfiltrates one of four secrets selected by a build-specific index (`_PICK`), falling back to the legitimate self-hash on the other four out of five calls. `_PICK` reads as 0, 2, 1, 3 for versions 4, 6, 8, 10 respectively — so version 8, live on function version 8 (published 22:21 UTC), was targeting `/gridlink/order-hmac-key`: the order-signing key.

To make sure the "clean" odd versions weren't backdoored more subtly, I recompiled their sources and compared normalized disassembly (stripping the runtime addresses that had produced false mismatches on my first pass). Version 9's pyc is byte-for-byte identical to version 1's, and both match a fresh compile of the source minus the docstring. Clean.

**Recovering the key from the logs.** The authorizer's log group carries lines like:

```
[INFO]  2026-10-30T21:51:23.525Z  3ee23efc-...  telemetry order_id=912000 correlation=009bdd5047639c91e7307fb417e94e5a
```

The token format is `index(1) || ct(2) || crc(2 BE) || salt(11)`. Decoding all 1,174 logged tokens, stripping the keystream with each line's own request ID, produced zero CRC failures across the board — the encoding scheme was fully understood at this point.

[CONFIRM — polarity bug caught before submission]: My first pass at classifying "decoy" vs. "secret" chunks assumed the branch `order_id % 5 == 0` meant the self-hash path. The result was immediately suspicious — every extracted "secret" exactly equaled the corresponding self-hash, and twenty records per implant window failed the decoy check. Re-reading the disassembly showed `POP_JUMP_IF_FALSE` jumps on falsy, so `order_id % 5 == 0` actually falls *through* to the SSM branch, not away from it. I had the condition backwards. After swapping the classification, every decoy chunk matched the self-hash and every secret chunk voted unanimously — the empirical inconsistency is what caught the bug, not a code review.

## Exploitation

With the branch polarity corrected, recovering the key per invocation of function version 8 is a straightforward majority vote across 100 telemetry samples, validated chunk-by-chunk against the CRC and index fields embedded in each token:

```
ks = hashlib.sha256(request_id.encode('ascii') + salt).digest()[:2]
pt = bytes(a ^ b for a, b in zip(ct, ks))
assert crc16(bytes([i]) + pt + salt) == int.from_bytes(crc_field, 'big')
assert i == order_id % 8
(secret if order_id % 5 == 0 else decoy)[i][pt] += 1
key = b''.join(secret[i].most_common(1)[0][0] for i in range(8))
```

```
RECOVERED /gridlink/order-hmac-key = b6b0881524852112e5d422f75053d324   (32 hex chars)
```

The other three implant windows yielded the other three secrets the same way (`portal-session-secret`, `db-readonly-password`, `metrics-api-token`), confirming the mechanism generalizes rather than being a one-off coincidence. CloudTrail corroborates the whole story without contradicting any of it: every `PublishLayerVersion`/`UpdateFunctionConfiguration` event came from the legitimate CI/CD role (no rogue identity involved anywhere), but `GetParameter` bursts with `WithDecryption=true` line up exactly with the four implant windows, and the non-key secrets show 81 reads each — one per implant invocation — while `/gridlink/order-hmac-key` shows 375 (81 implant plus legitimate signer reads). I did not independently verify the HMAC key against a live signing operation outside this evidence bundle; acceptance of the decode is based on internal self-consistency (unanimous votes, clean CRCs) rather than an external oracle, since this was an offline case with no live service to confirm against.

## Root Cause

1. **Supply-chain trust boundary broke silently:** the Lambda layer's shipped `.pyc` was allowed to diverge from the `.py` source it was built from, and nothing in the deployment pipeline checked that they matched. That divergence is the actual vulnerability — the function code itself (and the "clean" layer versions) were never touched.
2. **A structured logging format became a covert channel by construction, not by accident of the bug.** The telemetry token's design — index, XOR keystream from the request ID, salt, CRC — was invertible once understood, which is a design choice (logging detail for debugging) that happened to be exactly the channel the implant needed. That's worth separating from root cause #1: the logging format isn't itself a bug, but it's what made the implant's exfiltration path free and hard to notice in a log review.
3. **A custom PRNG-free module hashing its own file at runtime** (the self-beacon) is a pattern worth alerting on specifically, since it's exactly the kind of thing that looks like integrity-checking but can be repurposed as a decoy path.

## Validation

**What was confirmed in testing:**
- All ten `gridlink-order-authorizer` versions share one `CodeSha256`; the function code never changed.
- `auth-utils` versions 4, 6, 8, and 10 contain bytecode constants (an SSM parameter tuple) with no corresponding source-level constant.
- Versions 1 and 9 of `auth-utils` produce byte-identical bytecode to a fresh compile of their own source.
- Decoding 1,174 logged telemetry tokens produced zero CRC failures.
- The majority-vote recovery over 100 samples of function version 8 produced a unanimous result per chunk for `/gridlink/order-hmac-key = b6b0881524852112e5d422f75053d324`.
- CloudTrail `GetParameter` burst timing lines up with the four implant windows; all layer/function publish events came from the legitimate CI/CD role.

**What was not confirmed in my own session, and must not be claimed:**
- No live signing service existed to independently verify the recovered key against a real signature; correctness rests on internal decode consistency, not an external check.
- No submission platform was part of this case, so there is no recorded acceptance of the flag beyond its format matching the stated `CSCTF{<32 lowercase hex>}` pattern.

## Conclusion

The chain here was a Lambda layer whose shipped bytecode didn't match its own source — an implant hiding behind a legitimate-looking telemetry log line that doubled as its exfiltration channel. The subtle part, and the one that nearly produced a wrong flag, was a jump-condition polarity I misread on first pass; the fix came from noticing the decoded "secrets" were suspiciously identical to known self-hashes, not from re-reading the bytecode more carefully the first time. On categorization: this challenge straddles forensics (the evidence-bundle triage, timeline correlation across CloudTrail/CloudWatch) and reverse engineering (the pyc-vs-source bytecode divergence was the actual turning point) — if a platform requires a single tag, forensics is the more defensible choice given how much of the work is artifact correlation, but reverse engineering is the more honest description of the decisive step.

## Flag

```
CSCTF{b6b0881524852112e5d422f75053d324}
```
