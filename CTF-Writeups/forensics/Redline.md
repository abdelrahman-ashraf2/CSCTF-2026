# Redline

**Category:** Forensics

## Solution

1. I opened `CC-11_excursion_directive.docx` as a ZIP archive and read `word/document.xml`.
2. I inspected the Track Changes elements `w:del`, `w:delText`, and `w:ins`. Reading only the final visible document would have missed the deleted authorization.
3. I compared the deleted text with the inserted order. Revisions `107` and `108` were linked to `s.kessler` at `2026-10-07 02:41 UTC`.
4. I recovered the original excursion authorization from the deleted text and kept that value as the flag.

## Flag

```text
CSCTF{redline_21ee9b19d342e06432165fb2b6f64e06}
```

> **Note:** My notes mention conflicting values, including a `dispatch_...` value. I kept the flag recorded as the original authorization, but the DOCX is absent, so I could not resolve that conflict by inspecting it again.
