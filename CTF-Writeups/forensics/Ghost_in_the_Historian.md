# ghost-in-the-historian — Chronos Security CTF


## Introduction

A substation historian's configuration files were encrypted in place, and the encryptor was deleted afterward. The evidence is a 64 MiB VM disk image of the historian host, and the goal is to recover the original configuration's `SAFETY_INTERLOCK_TOKEN`. The brief is explicit about three constraints up front: the volume itself is constructed, not a real acquisition; the ext4 filesystem was built on 29 October while the incident records inside it represent 2 October; and recovered programs must be analyzed strictly as data — no execution, no mounting. Those constraints shaped the whole approach, since half the usual forensic toolkit (mounting, running anything recovered) was off the table by design.

## Initial Reconnaissance

```console
unzip -o ghost-in-the-historian.zip -d extracted
cd extracted && sha256sum -c manifest.sha256
```

```
README_FOR_RESPONDERS.md: OK
evidence-flat.vmdk: OK
evidence.vmdk: OK
```

The descriptor `evidence.vmdk` declares a single flat extent, so `evidence-flat.vmdk` *is* the whole disk:

```
evidence-flat.vmdk: Linux rev 1.0 ext4 filesystem data, UUID=c8461941-..., volume name "HISTORIAN01"
                    (extents) (64bit) (large files) (huge files)
```

A raw ext4 filesystem, not a partitioned disk — no partition offset to worry about. My sandbox had no root access (`apt-get install e2fsprogs` failed on the dpkg lock), so `debugfs`/`e2fsck` weren't available. I switched to `pip install pytsk3` (Sleuth Kit bindings), which parses ext4 read-only entirely from userspace and satisfies the no-mounting constraint directly. Two API mismatches cost a few minutes getting pytsk3 working: the `Img_Info` subclass needed the base `__init__` call plus a `get_size()` override, and `File.read_buffer`/`File.read` don't exist on this binding — `dir(pytsk3.File)` showed the actual method is `read_random`.

## Investigation

**Filesystem enumeration.** Walking the filesystem in memory and printing every entry with its four ext4 timestamps:

```
FILE         74  cr=2026-10-29 17:54:59 mt=2026-10-02 04:13:05 at=2026-10-02 04:13:05  /var/historian/node_status.json.enc    inode=23
FILE        235  cr=2026-10-29 17:54:59 mt=2026-10-02 04:13:05 at=2026-10-02 04:13:05  /var/historian/grid_topology.cfg.enc   inode=28
FILE         64  cr=2026-10-29 17:54:59 mt=2026-10-02 04:13:05 at=2026-10-02 04:13:05  /var/historian/historian_cache.dat.enc inode=22
FILE         94  cr=2026-10-29 17:54:59 mt=2026-10-29 17:54:59                          /var/log/historian.log
[...]
```

The two clocks mentioned in the brief show up exactly as described: `crtime` (29 Oct) is the volume build date; `mtime`/`atime` (2 Oct) are the incident data itself. Reading the live files via `open_meta` + `read_random`:

```
/var/log/historian.log:
2026-10-02 04:13 historian_enc[2764964]: starting encryption sweep, target_dir=/var/historian
```

`/root/.bash_history` (`ls`, `uptime`, `df -h`) and `/etc/hostname` (`mga-hist-07`) were unremarkable, and `/tmp` was empty. Two details stood out here: the log names both the encryptor and its PID, and the three `.enc` files share an identical `mtime` and `atime`, down to the second.

**Deleted-file hunt.** Allocated inodes run 11–20, 22, 23, 25, 26, 28 — gaps at 21, 24, 27. Probing those directly with `fs.open_meta`:

```
inode 21 type 1 size 0
inode 24 type 1 size 0
inode 27 type 1 size 0
```

All three exist but TSK reports size 0, and `/$OrphanFiles` was empty — inode-based recovery was a dead end here. Hypothesis: the deleted encryptor's bytes are still sitting in unallocated blocks, which meant going to the raw image directly instead of through the filesystem layer.

[CONFIRM — a self-inflicted debugging dead end]: my first probe script printed nothing at all, twice in a row. A broad `try/except: pass` was silently swallowing an `AttributeError` *inside the print statement itself*. Only rewriting the probe inline with explicit exception output surfaced the facts above — a reminder not to blanket-catch exceptions in analysis scripts.

**Locating and carving the encryptor.** A `strings -a` sweep over the whole extent showed ransom-note text (`Your historian node has been encrypted.`, `Contact ref: 7F3A-RECOVERY (this is NOT a decryption key)`) alongside libc symbol names (`scandir`, `unlink`, `gmtime_r`, `strftime`) — an embedded ELF. A Python regex scan for the ELF magic found exactly one candidate:

```python
for m in re.finditer(rb'\x7fELF', data): print(hex(m.start()), m.start())
```

```
0xa1c000 10600448
```

A first carve, cut to the section span computed from the header (12,615 bytes), produced a broken binary — `readelf` complained `missing section headers at 14408`. The first cut was simply too short. Re-carving 8 aligned 4 KiB blocks instead:

```console
dd if=evidence-flat.vmdk of=historian_enc.elf bs=4096 skip=2588 count=8
file historian_enc.elf
```

```
ELF 64-bit LSB pie executable, x86-64, ..., BuildID[sha1]=2996103d4ee27f073cac8be4b6d97e93ee7c3b61,
for GNU/Linux 3.2.0, stripped
```

To rule out additional hidden content, I mapped every non-zero 4 KiB block of the extent. The remaining regions were ordinary ext4 metadata, directory blocks, and the live files' own data — nothing else worth carving.

**Static analysis of `historian_enc`.** `readelf --dyn-syms` listed file I/O (`fopen`/`fread`/`fwrite`/`fclose`/`fseek`/`ftell`/`malloc`/`free`), directory traversal (`scandir`, `strcmp`), and process/time functions (`getpid`, `time`, `gmtime_r`, `strftime`, `utime`, `unlink`, `stat`) — notably, no `rand`/`srand` and no crypto library at all. Whatever encrypts the data has to be arithmetic sitting directly in `.text`. `.rodata` confirmed the observable behavior strings. Disassembling `.text` (~1.2 KB) with `objdump -d -M intel` reconstructed the full algorithm.

Seed derivation, at the top of `main`:

```
130a: call   time@plt          ; t0 -> rbx
131f: call   getpid@plt        ; pid -> ebp
1326: mov    eax,0xa5a5a5a5
132b: cmp    ebx,ebp
132d: je     1337              ; t0 == pid -> seed stays 0xa5a5a5a5
132f: xor    ebx,ebp
1331: imul   eax,ebx,0x9e3779b1
1341: mov    DWORD PTR [rip+0x2ccd],eax   ; global state at .bss 0x4014
```

`seed0 = ((t0 ^ pid) * 0x9e3779b1) mod 2^32`. (`t0` is also duplicated into a stack buffer via `movaps [rsp],xmm0` before this — worth remembering for later, since it reappears.)

The per-file keystream is XORed 4 bytes at a time, each chunk advancing the state first (a Marsaglia xorshift32: the shift pattern is 13, 17, 5):

```
1550: mov    eax,r8d
1553: shl    eax,0xd           ; x << 13
1556: xor    eax,r8d           ; x ^= x<<13
1559: mov    edx,eax
155b: shr    edx,0x11          ; >> 17
155e: xor    eax,edx           ; x ^= x>>17
1560: mov    r8d,eax
1563: shl    r8d,0x5
1567: xor    r8d,eax           ; x ^= x<<5
156a: mov    DWORD PTR [rsp+0x500],r8d    ; keystream dword, little-endian in memory
```

The buffer bytes are XORed with each dword's four bytes in memory order (LSB first), clipped at EOF, and — critically — the state is written back to `0x4014` after each file, so the PRNG chains continuously across files. File processing order comes from a `scandir` comparator that's a plain `strcmp`, i.e. alphabetical: `grid_topology.cfg` → `historian_cache.dat` → `node_status.json`.

The timestamps close the loop: after writing each `.enc` file, the program restores the saved `(t0, t0)` pair and calls `utime` on the output before `unlink`-ing the original:

```
1615: movdqa xmm1,XMMWORD PTR [rsp]      ; the (t0, t0) pair saved at startup
1622: movaps XMMWORD PTR [rsp+0x30],xmm1
1627: call   utime@plt
162f: call   unlink@plt
```

`utime` is handed `(t0, t0)`, so the encryptor stamps its own *start* time into both `atime` and `mtime` of every output file — exactly why all three `.enc` files showed identical `atime == mtime == 2026-10-02 04:13:05`. That gives `t0 = 1790914385` precisely (the log's `strftime("%Y-%m-%d %H:%M")` only pins the minute; the file's own `mtime` gives the second). The log's own `historian_enc[2764964]` line supplies the PID. No brute force needed anywhere — the seed is fully determined by artifacts the malware left behind about itself.

## Exploitation

```python
import struct
T0, PID = 1790914385, 2764964          # .enc atime/mtime ; historian.log
MASK = 0xffffffff
def xs32(x):
    x ^= (x << 13) & MASK
    x ^= x >> 17
    x ^= (x << 5) & MASK
    return x

state = ((T0 ^ PID) * 0x9e3779b1) & MASK   # seed0 = 0x40d8e565
for name in ["grid_topology.cfg.enc",        # strcmp order
             "historian_cache.dat.enc",
             "node_status.json.enc"]:
    data = open(name, "rb").read()
    ks = bytearray()
    for off in range(0, len(data), 4):       # one step per 4-byte chunk
        state = xs32(state)
        ks += struct.pack("<I", state)[:min(4, len(data) - off)]
    open(name[:-4], "wb").write(bytes(a ^ b for a, b in zip(data, ks)))
```

```
=== grid_topology.cfg (235 bytes) -> state after file 0x48840c9b ===
# Meridian Grid Authority -- Historian Node 07
# Topology Safety Configuration (internal use only)
# instance=csctf
NODE_ID=MGA-HIST-07
SAFETY_INTERLOCK_TOKEN=CSCTF{xorshift_ghost_in_the_historian_d2c19434a637}
CHECKSUM=pending-resync
=== historian_cache.dat (64 bytes) -> state after file 0xd60317d9 ===
2026-10-02T04:11Z,PRESS,41.2,OK
2026-10-02T04:12Z,PRESS,41.3,OK
=== node_status.json (74 bytes) -> state after file 0xa7292dd0 ===
{"node":"MGA-HIST-07","status":"nominal","last_sync":"2026-10-02T04:12Z"}
```

This ran cleanly on the first attempt, producing coherent plaintext for all three files. Because the PRNG state chains across files, each file's plaintext confirms the seed and the *next* file's decryption simultaneously — a wrong seed or a wrong processing order would have produced garbage for every file after the first, not just the final one.

## Root Cause

1. **The seed was derived entirely from `time()` XOR `getpid()`, both of which are recoverable after the fact from artifacts the malware itself leaves behind** — `utime()` stamping the encryptor's own start time onto its output files, and the log printing the PID directly. A custom PRNG seeded only from values this recoverable is effectively unkeyed in any forensic sense.
2. **PRNG state persisting across files in a fixed, alphabetical processing order** means the ciphertexts form one continuous keystream rather than independent ones — decrypting file N correctly requires knowing the exact lengths of every file processed before it, not their contents, which is a design detail easy to overlook if you try to decrypt files independently.

## Validation

**What was confirmed in testing:**
- The three `.enc` files share identical `mtime`/`atime` values, matching the model that `utime()` stamps each output with the encryptor's own start time.
- `T0 = 1790914385` and `PID = 2764964` (from the log) combine via the disassembled seed formula to produce a state that correctly decrypts all three ciphertexts in `scandir`'s alphabetical order.
- All three decrypted outputs are coherent and mutually consistent: a config file referencing `MGA-HIST-07`, telemetry timestamps matching the sweep window in the log, and a `node_status.json` that parses cleanly as JSON.
- The recovered token's format and content (`xorshift_ghost_in_the_historian`) are consistent with a correctly recovered value, matching the challenge's own naming.

**What was not confirmed in my own session, and must not be claimed:**
- Nothing outstanding — the decryption's internal consistency across three independently-sourced ciphertexts, chained through one PRNG state, is itself strong confirmation rather than an inference from a single data point.

## Conclusion

The ransomware here made a classic mistake that's easy to spot once you know to look: stamping its own output files with its own start time via `utime()` handed over the exact seed input it should have kept secret, and the accompanying log line handed over the other half (the PID). Combined with a deleted binary that TSK's inode layer couldn't recover but a raw magic-byte scan found immediately, this turned into a fully deterministic decryption rather than any kind of brute force.

## Flag

```
CSCTF{xorshift_ghost_in_the_historian_d2c19434a637}
```
