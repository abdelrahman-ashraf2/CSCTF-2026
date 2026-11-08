# Last Buffer

**Category:** Forensics

## Solution

1. I compared the saved Markdown, two Vim swap files, audit timeline, and shell journal. The incident document was `/home/opnight/incident-2026-10-07.md`, opened on `pts/4`.
2. I separated the drill from the incident. PID `8124` on `pts/7` exited normally; PID `8442` on `pts/4` wrote its swap at `02:19:38Z` and received `SIGHUP` at `02:19:46Z`.
3. I recovered the incident `.swp` beside a copy of the saved file. Revision `INC-4471/R18` said `UNSAVED-AT-DISCONNECT` and used `authorization_encoding: base64url`. The `.swo` was revision `R16-DRILL`, with a retired training readback.
4. I checked the base-file hash against the journal, then decoded the authorization. This saved value still decodes to the flag:

   ```python
   import base64

   s = 'Q1NDVEZ7bGFzdF9idWZmZXJfNDA1MWM5ZjZiMGQ5NjIyNDc5Nzg1ZjYxM2IwNjM5MTZ9'
   print(base64.urlsafe_b64decode(s + '=' * (-len(s) % 4)).decode())
   ```

## Flag

```text
CSCTF{last_buffer_4051c9f6b0d9622479785f613b063916}
```

> **Note:** I rechecked the Base64URL decoding. The original swap files and timeline are absent, so I could not repeat the recovery.
