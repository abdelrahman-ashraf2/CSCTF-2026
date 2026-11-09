# FLOTSAM — Chronos Security CTF

## Introduction

The bridge of the MV Ortelia wrote a chart frame — a PNG showing the vessel's last known fix — to a voyage data recorder. The recorder's capsule survived; its controller didn't. What's left is a chip-off flash dump: raw bytes, no allocation tables, no filesystem at all. The task is to carve the PNG by hand and read the recovery key printed on it, with an explicit warning baked into the brief: "a file that opens is not the same as a file that is whole." That line turned out to be the entire challenge in one sentence.

## Initial Reconnaissance

```console
$ file recorder-sectors.img
recorder-sectors.img: data
$ ls -l recorder-sectors.img
-rwxrwxrwx 1 root root 35840 ... recorder-sectors.img
```

35,840 = 70 × 512 — a raw sector dump, no partition table, no filesystem signature. A signature scan across the whole image produced the single most important fact of the whole challenge:

```
PNG sigs at: [26624]
IEND at: [24215]
IHDR at: [26636]
JPEG-SOI [11264]  JPEG-JFIF [11270]
total len 35840
```

The only `IEND` marker sits at offset 24,215 — *before* the only PNG signature, at 26,624. A PNG whose end marker precedes its own start marker isn't truncated; it's been split and scattered across the disk. That's precisely the trap the brief's warning points at.

A per-sector map (non-zero byte count, printable ratio, first bytes) filled in the layout:

```
sector   0-2   NMEA text: $GPRMC,060000.00,A,4406.5886,N,02912.3001,E,... [...]
sector   3-20  binary
sector  21     zeros
sector  22-33  binary, starts ffd8ffe000104a464946 (JPEG)
sector  34     zeros
sector  35-41  binary
sector  42-43  zeros
sector  44-46  binary
sector  47     partial: only 125 non-zero bytes
sector  48-51  NMEA text: $GPRMC,060000.00,A,4410.2616,N,02824.7957,E,... [...]
sector  52-67  binary, starts 89504e470d0a1a0a (PNG signature)
sector  68-69  zeros
```

The two NMEA logs (Black Sea positions, 14 Mar 2026) weren't needed for the objective, so I dumped them for completeness and set them aside.

## Investigation

**Is the JPEG a complete, unrelated file?** Checking for its end marker: `EOI found at relative 5846 -> abs 17110` — a closed, 5,848-byte JPEG sitting entirely within its own sector run. The remaining binary regions (sectors 3–20, 35–41, 44–47, 52–67) roughly matched the size a scattered PNG would need. This suggested the JPEG was a self-contained decoy, and that every other binary sector belonged to the PNG — a hypothesis worth confirming rather than assuming.

**Walking the PNG chunk structure from the signature at 26,624.** My first walk produced garbage (`type=\r\n\x1a\n len=2303741511`) because I'd started parsing the length field at offset 0 instead of skipping the 8-byte signature first. Starting at offset 8 instead:

```
rel  8 abs 26632 type=IHDR len=13  crc stored=94d20dad calc=94d20dad MATCH   IHDR: 760x520 bitdepth=8 colortype=2 interlace=0
rel 33 abs 26657 type=IDAT len=22630  <-- implausible
   next bytes: 00 00 58 66 49 44 41 54 78 9c ed dd 77 7c [...]
```

The `IHDR` is intact and its CRC matches — an undamaged header. But the declared `IDAT` length, 22,630 bytes, would end the chunk around offset 49,311 — well past the 35,840-byte image. The file is simply larger than the dump, so the `IDAT` has to continue somewhere else in the image. A search for chunk-type strings elsewhere in the dump found exactly one `IHDR`, one `IDAT`, and one `IEND` — no second, partially-overwritten PNG header hiding anywhere. One fragmented file, not two competing ones.

**Finding the tail.** A hexdump around the orphan `IEND`:

```
005e80  00 80 6a 11 74 00 00 80 6a fd 3f 27 e2 1e fb 55
005e90  b7 31 67 00 00 00 00 49 45 4e 44 ae 42 60 82 00
```

The four bytes before the `00 00 00 00` `IEND` marker are `55 b7 31 67` — an `IDAT` chunk CRC — and `ae 42 60 82` is the standard `IEND` CRC. So the genuine end of the PNG (`IDAT` tail plus `IEND`) sits roughly 2.4 KB *before* the PNG's own header in the raw dump. The repeating `00 80 6a 11 74` pattern above it is live compressed-stream bytes, not padding of any kind.

**How far does the zlib stream decode contiguously?** The stream starts at offset 26,665 with the `78 9c` zlib header. Feeding it byte-by-byte into `zlib.decompressobj()`:

```
reached end of data without error; consumed 9175
eof: False unused: 0
```

All 9,175 bytes to the sector boundary decoded without a single error, and without the stream itself reaching EOF. One caveat I had to account for: the decoder also happily swallowed the all-zero sectors 68–69 (deflate tolerates zero runs for a while), so this contiguity test alone couldn't locate where the head region's true data actually ends — it only established that the head *is* contiguous.

**Byte accounting pinned down every remaining piece.** With 22,630 stream bytes starting at 26,665 and ending right before the `IDAT` CRC at 24,207:

```
PNG total = 8 (sig) + 25 (IHDR) + 8 + 22,630 + 4 (IDAT) + 12 (IEND) = 22,687 bytes
Head run 26624–34816 (sectors 52–67) = exactly 8,192 bytes -> 8,151 stream bytes
Remainder = 22,630 − 8,151 = 14,479 stream bytes = exactly 28 full sectors (sectors 3–20, 35–41, 44–46 -> 14,336 B) + a 143-byte tail (24064–24207)
Cross-check: 22,687 − 8,192 = 14,495 = 14,336 + 143 + 4 (IDAT CRC) + 12 (IEND)   ✓
```

Every number fit, including the partial sector 47 (143 stream bytes + 4 CRC + 12 IEND = 159 bytes). An earlier rough count of the binary regions had come up 16 bytes short; using the exact chunk boundaries (stream starting at 26,665, ending at 24,207) closed that gap and confirmed the sector-granular model was right. The only remaining unknown was the order of the 28 scattered sectors.

## Exploitation

I reassembled the deflate stream with a depth-first search that uses `zlib` itself as the splice oracle: from the known head, try each unused 512-byte sector as the next piece and keep it only if the decompressor accepts it without error. The finished stream must end exactly at the known tail, reach EOF (which validates the Adler-32 checksum), and inflate to `520 × (1 + 760 × 3) = 1,186,120` bytes — the exact filtered-scanline size for a 760×520 RGB image.

```python
import zlib
data = open('recorder-sectors.img', 'rb').read()
HEAD = data[26665:34816]   # contiguous head of the stream
TAIL = data[24064:24207]   # final 143 stream bytes, ends at the adler32
POOL = list(range(3, 21)) + list(range(35, 42)) + list(range(44, 47))  # 28 sectors
EXPECTED_OUT = 520 * (1 + 760 * 3)

solution = None
def dfs(order):
    global solution
    if solution is not None: return
    remaining = [s for s in POOL if s not in order]
    if not remaining:
        stream = HEAD + b''.join(data[s*512:(s+1)*512] for s in order) + TAIL
        d = zlib.decompressobj()
        try:
            out = d.decompress(stream)
        except zlib.error:
            return
        if d.eof and len(out) == EXPECTED_OUT:
            solution = order
        return
    for s in remaining:
        prefix = HEAD + b''.join(data[x*512:(x+1)*512] for x in order)
        d2 = zlib.decompressobj()
        try:
            d2.decompress(prefix + data[s*512:(s+1)*512])
        except zlib.error:
            continue
        dfs(order + [s])
dfs([])
```

```
SOLUTION order (sectors): [3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16,
                           17, 18, 19, 20, 35, 36, 37, 38, 39, 40, 41, 44, 45, 46]
nodes explored: 29
stream length: 22630 (expect 22630)
inflated: 1186120 bytes (expect 1186120)
```

The scattered sectors turned out to be in their natural ascending order the whole time — sector 3 was the first candidate tried at every single step, so the search finished in 29 nodes with zero backtracking. Wrong splices tend to fail fast: a 512-byte chunk in the wrong place almost always raises `zlib.error` within that same chunk.

I rebuilt the file and verified every integrity marker the format offers:

```python
png = data[26624:26665] + stream + data[24207:24211] + b'\x00\x00\x00\x00IEND\xae\x42\x60\x82'
idat_chunk = png[33:33 + 8 + 22630]      # IDAT chunk starts at offset 33 in the rebuilt file
crc = zlib.crc32(idat_chunk[4:]) & 0xffffffff
```

```
IDAT CRC calc=55b73167 stored=55b73167 MATCH
PNG size: 22687 bytes
PIL opened: (760, 520) RGB
```

One mistake worth recording honestly: my first CRC check sliced the *rebuilt* buffer using the *original dump's* absolute offsets (`png[26657:...]`), which reported a false mismatch. The `IDAT` chunk in the rebuilt file actually starts at offset 33 (after the signature and `IHDR`), not at the dump's position 26,657. Fixing the slice made the CRC match, giving independent proof the splice was byte-perfect, on top of the Adler-32 check already passed by `zlib.eof`.

The reconstructed chart rendered correctly: a "VDR CHART FRAME — RECOVERED" plot with a track line, a last-fix marker, and a recovery key printed along the bottom. I cropped the key band and upscaled it 2× before transcribing it, rather than trusting a single read of the full-size render.

## Root Cause

1. **The PNG was deliberately split-and-scattered across non-contiguous sectors**, with its end marker physically preceding its signature in the raw dump — not a case of truncation or corruption, which is the actual trap the brief's own warning names directly.
2. **A naive signature-to-EOF carve would have produced a file that opens but is incomplete or wrong** (exactly the "opens but isn't whole" scenario) because a signature-to-EOF approach ignores both the scattered sectors before the signature and the correct chunk boundaries entirely.

## Validation

**What was confirmed in testing:**
- The image contains exactly one `IHDR`, one `IDAT`, and one `IEND`, confirming one fragmented PNG rather than two competing ones.
- The `IHDR`'s own CRC validates against its declared contents (760×520, bit depth 8, color type 2).
- The reconstructed deflate stream reaches `zlib`'s EOF (validating the Adler-32 checksum) and inflates to exactly the expected filtered-scanline size for a 760×520 RGB image (1,186,120 bytes).
- The rebuilt `IDAT` chunk's CRC matches its stored value when computed against the chunk's correct offset in the *rebuilt* file.
- `PIL` opens the reassembled file successfully as a 760×520 RGB image.

**What was not confirmed in my own session, and must not be claimed:**
- Nothing outstanding for the carving itself — every independent integrity check (IHDR CRC, Adler-32 via `zlib.eof`, IDAT CRC, successful decode) passed. The recovery key transcription from the rendered image is a manual read, not an automated extraction, so it's worth flagging as the one step without a machine-checkable confirmation beyond visual legibility.

## Conclusion

This challenge turned entirely on taking its own warning literally: the file that "opens" after a naive carve is not the same as the file that's actually whole, because the real PNG was deliberately scattered across sectors in a way that puts its end marker before its start marker in the raw dump. Comparing marker positions before carving anything, using `zlib` itself as a splice oracle instead of guessing sector order, and validating the reconstruction against every integrity check the PNG format offers (CRCs, Adler-32, a successful decode) together turned an unknown 28-sector permutation into a search that never had to backtrack.

## Flag

```
CSCTF{flotsam_0e91019a8e70267f550895930247d088}
```
