# Operation Dawn: The Medic's Phone

**Category:** Forensics

## Solution

### 1. Unpack the Android backup

I read the Android backup header: version 5, compression enabled, and encryption `none`. I decompressed the remaining zlib payload and opened the TAR data.

The files I needed were under `apps/org.unit43.courier/db/`: `messages.db` and `messages.db-wal`.

### 2. Recover the older page from the WAL

The WAL was 4,152 bytes: a 32-byte header, one 24-byte frame header, and a 4,096-byte page. The page number in the frame header at offset 32 was 4.

I worked on a database copy and placed the frame's page body at `(4 - 1) * 4096 = 12288`. The WAL page body begins after the two headers, at byte 56. This recovered the older message state without modifying the original database.

### 3. Decode the message body

I read message ID 14 in the `signals` conversation. Its `pb` column held a Protobuf message. Field 5 was length-delimited, with tag `0x2a`, and carried a raw DEFLATE stream.

After locating that field's bytes, I decompressed them with `zlib.decompress(data, -15)`. The negative window value selects raw DEFLATE rather than a zlib-wrapped stream.

### 4. Read the assignment

The recovered message began `Movement order. Board the hospital train. Assignment follows:` and ended with an instruction to acknowledge receipt and destroy the message. The complete flag was in that assignment text.

## Flag

```text
CSCTF{03_at_platform_two_6f57d7}
```
