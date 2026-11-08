# Operation Dawn: The Medic's Phone

**Category:** Forensics

## Solution

1. I read the Android backup header: version `5`, compression enabled, and no encryption. I decompressed the remaining zlib stream and opened the TAR data.
2. I found `apps/org.unit43.courier/db/messages.db` and `messages.db-wal`. The 4,152-byte WAL held one frame for SQLite page 4, with a 4,096-byte page body.
3. I copied the database and replaced page 4 with the WAL page at offset `(page_no - 1) * 4096`. This recovered the older message without changing the original database.
4. I read message ID `14` in the `signals` conversation. Its `pb` data was Protobuf; field 5, tagged `0x2a`, held a raw DEFLATE stream. I decompressed that field with `zlib.decompress(data, -15)`.
5. The message said to board the hospital train. The text after `Assignment follows:` contained the complete flag.

## Flag

```text
CSCTF{03_at_platform_two_6f57d7}
```

> **Note:** I retained the recovery from my saved notes. The Android backup is absent, so I could not repeat the database reconstruction.
