# Phantom Drift

**Category:** Forensics

## Solution

1. I compared the approved waypoint `(47.2591, 19.0402)` with the diverted position `(47.2600, 19.0450)`.
2. I formatted the latitude and longitude offsets as `0.000900` and `0.004800`. Using Haversine with Earth radius `6378137 m`, I got about `376.2257 m`, which became `376.2`.
3. I joined the fields without separators, using the exact decimal formatting from the brief, and calculated SHA-256:

   ```bash
   echo -n "47.259119.04020.0009000.004800376.2" | sha256sum
   ```

4. I used the first 16 hex characters for the flag. The full digest ends in `dc6836a2`, which matches the recorded flight TAG.

## Flag

```text
CSCTF{5dc7cdf826f74515}
```

> **Note:** My historical case title was Valkyrie-9. Its recorded solution at 2026-11-07 13:44:05 UTC precedes the team’s Phantom Drift solve by 20 seconds, and the notes name a `phantom-drift` generator. I rechecked the calculation, but this title attribution remains a strong historical inference; I do not have a direct accepted-flag transcript under the official title.
