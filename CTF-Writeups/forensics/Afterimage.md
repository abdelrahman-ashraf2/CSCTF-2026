# Afterimage

**Category:** Forensics

## Solution

1. I checked the PNG chunks, the `IHDR` height, and the data beyond the visible image. The displayed picture did not show the full stored content.
2. I reconstructed the missing lower rows from the remaining image data. This exposed roughly 200 extra rows.
3. The recovered area contained `RELAY RECOVERY KEY`. I read the complete flag beneath that label.

## Flag

```text
CSCTF{6f86acdd1d10e0d8a5a541bb}
```

> **Note:** Another historical note calls this flag “Relay Snapshot.” I kept one Afterimage writeup; the records do not establish whether the titles refer to the same artifact.
