# Operation Dawn: The Access Log

**Category:** Web

## Solution

1. I read the Nginx access log and found repeated requests from `198.51.100.66` to `/api/status`. The requests tested one token character at a time with `SUBSTR` and delayed correct guesses using `SLEEP(2)`:

   ```text
   /api/status?unit=43'+AND+IF(SUBSTR(token,27,1)='b',SLEEP(2),0)--+-
   ```

2. I used response time rather than HTTP status. Correct guesses took about two seconds; ordinary guesses took roughly `0.002–0.006` seconds.
3. I kept matching requests with `rt > 1.5`, decoded the guessed characters, and indexed them by token position. The saved extractor was:

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

   positions = range(1, 42)
   assert len(found) == 41 and all(i in found for i in positions)
   print(''.join(found[i] for i in positions))
   ```

4. My saved result records all 41 positions without gaps. That includes URL-encoded braces `%7B` and `%7D`; joining the decoded characters gave the flag.

## Flag

```text
CSCTF{07_beacon_tow_vigil_bollard_8c0371}
```

> **Note:** My historical title was Annex 07 — Canal Checkpoint Status Portal. The flag was recorded at 2026-11-06 13:20:52 UTC, nine seconds before the team’s Access Log solve. I kept this strong historical attribution, but the original log and a direct platform acceptance response are absent, so I could not confirm the title match or rerun the extraction.
