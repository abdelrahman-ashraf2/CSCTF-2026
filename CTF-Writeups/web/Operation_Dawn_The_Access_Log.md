# Operation Dawn: The Access Log

**Category:** Web

## Solution

### 1. Find the character guesses

I inspected the 2,927-line Nginx log and found repeated requests from `198.51.100.66` to `/api/status`. They tested individual token characters:

```text
/api/status?unit=43'+AND+IF(SUBSTR(token,27,1)='b',SLEEP(2),0)--+-
```

`IF` ran `SLEEP(2)` when the guessed character matched. The HTTP status could still be 200 for both correct and incorrect guesses, so I used the `rt=` field.

### 2. Select the slow guesses

Position 27 was guessed as `b` with `rt=2.024`, and position 23 as `g` with `rt=2.003`. Incorrect guesses usually took around `0.002–0.006` seconds.

I kept matching requests with `rt > 1.5`, extracted the one-based character position, and URL-decoded the guessed character. That decoding mattered for `%7B` and `%7D`, the opening and closing braces.

### 3. Rebuild the token in position order

I checked for conflicting guesses and missing positions before joining the characters. I found 41 slow guesses covering positions 1–41 without gaps.

I used this extractor to put them in order:

```python
import re
from urllib.parse import unquote

found = {}
pat = re.compile(r"SUBSTR\(token,(\d+),1\)='([^']+)',SLEEP\(2\).*?rt=([\d.]+)")
with open('access.log', encoding='utf-8') as f:
    for line in f:
        m = pat.search(line)
        if m and float(m.group(3)) > 1.5:
            pos = int(m.group(1))
            c = unquote(m.group(2))
            if pos in found and found[pos] != c:
                raise ValueError(f'Conflicting evidence at position {pos}')
            found[pos] = c

positions = range(1, max(found) + 1)
assert len(found) == 41 and all(i in found for i in positions)
flag = ''.join(found[i] for i in positions)
print(flag)
```

Joining the characters gave me the complete flag.

## Flag

```text
CSCTF{07_beacon_tow_vigil_bollard_8c0371}
```

> **Note:** My original notes called this Annex 07 — Canal Checkpoint Status Portal. The flag was recorded at 2026-11-06 13:20:52 UTC, nine seconds before the team’s Access Log solve. This supports the title match, but does not prove it directly.
