# Redline

**Category:** Forensics

## Solution

### 1. Read the DOCX package directly

I opened `CC-11_excursion_directive.docx` as a ZIP archive and inspected `word/document.xml`. The final visible document showed an edited order, so I checked the tracked revisions as well.

### 2. Compare deleted and inserted text

I looked for `w:del` and its `w:delText` children, then compared them with `w:ins`. The deleted text retained the earlier excursion authorization.

The change metadata showed author `s.kessler`, time `2026-10-07 02:41 UTC`, and revision IDs 107 and 108. Those fields connected the removed authorization to the replacement directive.

### 3. Recover the original authorization

I kept the authorization from the deleted revision rather than the inserted order. That gave me the flag below.

## Flag

```text
CSCTF{redline_21ee9b19d342e06432165fb2b6f64e06}
```

> **Note:** My notes also mention a conflicting `dispatch_...` value. I retained the flag recorded as the original authorization; resolving the conflict requires the original DOCX.
