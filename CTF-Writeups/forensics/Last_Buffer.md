# Last Buffer

**Category:** Forensics

## Solution

### 1. Separate the incident swap from the drill

I compared the saved Markdown file, `.swo`, `.swp`, `audit-timeline.jsonl`, `shell-journal.jsonl`, and case context. The incident document was `/home/opnight/incident-2026-10-07.md`, associated with `pts/4`.

The timestamps separated the two sessions:

| Session | Evidence | Interpretation |
|---|---|---|
| PID 8124, `pts/7` | Captured at `02:11:51Z`; exited normally at `02:12:18Z` | Drill |
| PID 8442, `pts/4` | Swap write at `02:19:38Z`; `SIGHUP` at `02:19:46Z`; capture at `02:19:47Z` | Incident |

### 2. Recover the unsaved incident revision

I placed the incident swap beside a copy of the saved document, using the hidden swap name `.incident-2026-10-07.md.swp`, and recovered its unsaved contents.

The recovered revision said `INC-4471/R18`, `status: UNSAVED-AT-DISCONNECT`, and `authorization_encoding: base64url`. Its `base_file_sha256` matched the saved document:

```text
01c2a034f1a47e4cb5536d66394c4774a1f1c568ff4e34c0de7f654aa42bc849
```

The `.swo` instead said `INC-4471/R16-DRILL` and `PERIODIC-SNAPSHOT`; it decoded to `retired-training-readback-16`.

### 3. Decode the incident authorization

I decoded the R18 authorization value with Base64URL:

```python
import base64
s = 'Q1NDVEZ7bGFzdF9idWZmZXJfNDA1MWM5ZjZiMGQ5NjIyNDc5Nzg1ZjYxM2IwNjM5MTZ9'
print(base64.urlsafe_b64decode(s + '=' * (-len(s) % 4)).decode())
```

## Flag

```text
CSCTF{last_buffer_4051c9f6b0d9622479785f613b063916}
```
