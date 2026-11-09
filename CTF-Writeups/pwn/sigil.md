# Sigil — Chronos Security CTF

## Introduction

No binary was handed out for this one — just a netcat target and three lines of banner text ending in "the kernel remembers every frame you show it," which is a pretty direct hint toward `sigreturn`-oriented programming (SROP) once you notice it. This writeup follows the session in solve order and is explicit about where it stops: the live instance expired before I got a shell, so there is no flag at the end of this one. I'd rather say that plainly than reconstruct a plausible ending that I didn't actually see.

## Initial Reconnaissance

```console
$ nc w01.ctf.chronos-security.ro 43906
~~ sigil ~~
the kernel remembers every frame you show it.
speak the sigil: hello
silence.
```

Short input, or 72 bytes of padding, both produce the same "silence then clean exit." Seventy-three bytes kills the connection outright — no message, no EOF greeting, just a closed socket, which reads as a stack smash: the saved RIP sits at offset 72, and from byte 73 onward my input lands directly on top of it.

With no handout, there's no `checksec`, no `objdump`, no `ROPgadget` — but "no binary" doesn't mean "no information." RIP control is its own oracle. The addresses in play looked like the default non-PIE load address (the `0x400000` region), so I flood-filled offset 72 with candidate code addresses, one per connection, and watched for anything other than "prompt, then die":

```python
payload = b"A" * 72 + addr.to_bytes(8, "little") + b"B" * extra
```

Sweeping the page around `0x401000` with a few dozen parallel connections, three addresses answered distinctly:

- `0x401030` — reprints `speak the sigil:` and reads again. The prompt loop.
- `0x401086` — replays the full banner. `_start`.
- `0x4010c6` — prints `silence.` and exits. The rejection path.

That sketches the whole program in three data points: `_start` prints the banner and falls into a loop at `0x401030` that does `write(prompt) → read(0, buf, N) → check → ret`. A couple hundred bytes of hand-written assembly, confirmed non-PIE — and, critically, that loop ends in a plain `ret` that I now controlled.

## Investigation

Three facts fell out of poking at that loop, and together they make up the entire exploit. None of them required the binary.

**1. RAX holds my syscall number for free.** Hand-written assembly has no epilogue to clobber `RAX`, so at the point the loop's `ret` executes, `RAX` still holds whatever `read()` returned — the exact number of bytes I sent. If a `syscall` instruction sits at whatever address that `ret` pops, sending exactly 15 bytes makes `RAX = 15 = __NR_rt_sigreturn`. No `pop rax` gadget needed anywhere; the read length *is* the register loader.

**2. The check depends on buffer content, not just length.** Short first reads always die with `silence.`, but a second read of exactly 15 bytes sails straight past whatever that check is. Something in the buffer's actual content decides the branch, not merely the byte count — which happened to be convenient, since 15 bytes is exactly what the sigreturn trigger needs anyway.

**3. The `ret` consumes my own data as its return address.** The decisive test: a 400-byte second read with the loop address `0x401030` planted at several offsets (`{0, 72, 80, 88}`) produced a third prompt — meaning that iteration's `ret` popped one of my qwords as its return target. Planting `0x4010c6` instead produced `silence.` again. So the return address on this `ret` is attacker-supplied data, and the simplest model that fits is also the cleanest: the `ret` pops the first qword of the second read's buffer, leaving `RSP` sitting at `buf+8` — exactly where a sigreturn frame needs to start.

Put together, the chain writes itself:

1. First read (≥73 bytes): overflow offset 72 with the loop address `0x401030` so the program re-arms instead of crashing, and park a forged `sigcontext` at `buf+8`.
2. Second read: exactly 15 bytes. The first 8 bytes are the address of a `syscall` instruction (the `ret` pops it as its target); the remaining 7 bytes only touch the frame's `uc_flags` field, which is zero anyway.
3. `RAX = 15`, `RIP = syscall` → `rt_sigreturn` → the kernel rebuilds every register from the frame I planted.
4. The restored state executes one syscall of my choosing — and "the kernel remembers every frame you show it" stops being flavor text.

## Exploitation

The whole technique lives or dies on one struct — the `sigcontext` the kernel parses at `RSP` when `sigreturn` fires. Offsets taken from the kernel's own `asm/sigcontext.h`:

| Frame offset | Field |
|---|---|
| 0–39 | `uc_flags`, `uc_link`, `uc_stack` (24 bytes) — all zero |
| 40–152 | `r8`…`r15`, `rdi`, `rsi`, `rbp`, `rbx`, `rdx`, `rax`, `rcx` |
| 160 | `rsp` |
| 168 | `rip` |
| 176 | `eflags` — a full 8-byte field |
| 184 / 186 / 188 / 190 | `cs` / `gs` / `fs` / `ss` = `0x33` / `0` / `0` / `0x2b` |

This is where I burned most of the session's time, and I'd rather document the mistakes than gloss over them. I hand-built that struct twice and got it wrong both times, in two different ways. First pass: I packed the `ucontext` header as 36 bytes instead of 40 (`uc_stack` is a full 24-byte `stack_t`, not 20), which shifted every register down by 4 bytes. Second pass: "fixing" the mismatch, I packed `eflags` as 4 bytes and squeezed `cs` in at offset 180 — which actually lands inside the `eflags` qword and leaves the *real* `cs` slot at offset 184 reading zero. A restored frame with `CS = 0` dies the instant the kernel returns to user mode, and from the outside it's indistinguishable from a plain sweep miss: connection closes, no output, nothing to debug against. I settled it the boring but reliable way — compiled a ten-line C file against the actual kernel header and printed `offsetof(struct sigcontext, cs)` directly, rather than trusting my memory of the layout again.

With the frame correct, the trigger itself is small:

```python
buf = bytearray(b"Q" * 600)
buf[72:80]     = struct.pack("<Q", 0x401030)   # read#1 ret -> stay in the loop
buf[8:8+248]   = srop_frame(...)               # sigreturn frame, RSP lands here
send(bytes(buf))                               # read #1
send(struct.pack("<Q", opcode) + b"C" * 7)     # read #2: exactly 15 bytes
                                                # RAX=15 -> ret pops opcode -> sigreturn
```

The plan from there: first restore should do something that proves the primitive *and* hands back ground truth at the same time — `write(1, 0x401000, 0x1000)` dumps the entire code page back over the socket, which would have shown the real syscall/`ret` byte offsets and whatever writable segment the binary owns. From that dump, every further restore is one syscall per prompt round, since a frame can set `RIP` straight back to `0x401030` and re-arm the loop for another 15-byte read. The intended endgame was either `read(0, rw, 8)` to drop `/bin/sh\0` into the non-PIE writable page followed by `execve(rw, 0, 0)`, or skipping the shell entirely and doing an open-read-write on the flag file directly: `open("flag.txt", 0)`, `read(3, rw, 128)`, `write(1, rw, 128)`.

[CONFIRM — never executed against the live service]: Everything up to and including the corrected `sigcontext` layout was verified against the kernel header, not against a live run of the exploit. I do not have a captured transcript of a successful `sigreturn` firing, a code-page dump, or a shell on the actual target. The consolidated exploit tooling (sweep / verify / dump / execve modes) exists as `sigil_pwn.py`, but I don't have confirmation it ran end-to-end before the instance died.

## Root Cause

1. **Hand-rolled assembly with no function prologue/epilogue leaves `RAX` holding the live syscall return value at every `ret`**, which is itself a design property of writing raw asm rather than a classic memory-safety bug — but it's exactly what removes the need for a `pop rax` gadget in this exploit.
2. **The loop's `ret` consumes attacker-controlled stack content as its own return address**, which is the actual memory-corruption bug: an overflow that reaches a controlled return slot, same underlying class as a classic stack-based buffer overflow, just in hand-written assembly instead of C.
3. A correctly-implemented `rt_sigreturn` restore from a forged frame is a powerful primitive specifically *because* the kernel trusts the frame's contents completely — that's a property of the `sigreturn` syscall's design, not a bug in this binary, but it's what turns a 15-byte write into full register control once the overflow delivers RSP to the right place.

## Validation

**What was confirmed in testing:**
- Input of 72 bytes or fewer produces `silence.` and a clean exit; 73+ bytes crashes the connection with no output, consistent with a saved-RIP overwrite at offset 72.
- Flood-filling offset 72 with candidate addresses around `0x401000` (non-PIE) identified three distinct behaviors at `0x401030` (prompt loop), `0x401086` (`_start`/banner replay), and `0x4010c6` (rejection path).
- A second read of exactly 15 bytes passes the service's check where shorter reads do not.
- Planting the loop address at various offsets in a 400-byte second read reproduces a third prompt, consistent with that iteration's `ret` consuming attacker-supplied stack data as its target.
- The `sigcontext` field offsets used in the final frame were verified directly against the running kernel's own header (`offsetof` printed from a compiled C snippet), not from memory.

**What was not confirmed in my own session, and must not be claimed:**
- I did not observe a successful `rt_sigreturn` firing against the live service, a dumped code page, or a working shell.
- I do not have the flag for this challenge. The instance expired (30-minute timer) while I was finalizing the corrected `sigcontext` frame, and a fresh instance was not available before I stopped working on it.
- I have no basis for asserting any specific `CSCTF{...}` string as this challenge's flag, and I am deliberately not including one.

## Conclusion

This challenge mapped a completely unknown binary's control flow from RIP behavior alone, then built a sigreturn-oriented exploit around a register (`RAX`) that was free for the taking because the target was hand-written assembly with no calling convention to preserve it. The subtlety that actually cost time was getting the kernel's `sigcontext` layout exactly right by hand — two different wrong guesses produced the same silent failure mode as a sweep miss, and the only way out was to stop guessing and compile against the real header. I never got to run the finished exploit against a live instance before it timed out, so I'm not claiming a flag I didn't see.
