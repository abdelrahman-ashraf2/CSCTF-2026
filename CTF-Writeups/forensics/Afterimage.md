# Afterimage

**Category:** Forensics

## Solution

1. I checked the PNG chunks, the height in `IHDR`, and the data beyond the visible image. The displayed picture did not contain the full image content.
2. I reconstructed the missing lower rows from the remaining image data. My notes record roughly 200 recovered rows, but do not preserve the exact repair command.
3. I found `RELAY RECOVERY KEY` in the recovered area and copied the flag beneath it.

## Flag

```text
CSCTF{6f86acdd1d10e0d8a5a541bb}
```

> **Note:** I only have the saved solution, so I could not repeat the PNG repair. Another old note calls the same result “Relay Snapshot”; I kept this as one Afterimage writeup because the notes do not establish that both challenge titles refer to the same artifact.
