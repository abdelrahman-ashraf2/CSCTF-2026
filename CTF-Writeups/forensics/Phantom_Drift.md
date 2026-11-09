# Phantom Drift

**Category:** Forensics

## Solution

### 1. Compare the approved and diverted positions

I read the approved waypoint from the mission manifest and compared it with telemetry:

| Field | Latitude | Longitude |
|---|---:|---:|
| Approved waypoint | 47.2591 | 19.0402 |
| Diverted position | 47.2600 | 19.0450 |
| Offset, formatted to six decimals | 0.000900 | 0.004800 |

### 2. Calculate the distance and preserve formatting

I used Haversine with Earth radius `6378137 m`. The distance is about `376.2256716 m`, which becomes `376.2` at one decimal place.

I joined the approved coordinates, formatted offsets, and distance without separators. The exact digest input was:

```text
47.259119.04020.0009000.004800376.2
```

The decimal widths mattered: changing trailing zeros, inserting separators, or adding a newline would change the digest.

### 3. Derive the flag and compare the TAG

I hashed that exact string without a trailing newline:

```bash
echo -n "47.259119.04020.0009000.004800376.2" | sha256sum
```

The complete digest was:

```text
5dc7cdf826f74515c03f45611f58fabd2edc04382d6cf9f8696f9d83dc6836a2
```

The first 16 hex characters form the flag. The final eight, `dc6836a2`, match the flight TAG; the TAG itself is not part of the hash input.

## Flag

```text
CSCTF{5dc7cdf826f74515}
```

> **Note:** My original case title was Valkyrie-9. I recorded the solution at 2026-11-07 13:44:05 UTC, 20 seconds before the team’s Phantom Drift solve, and the notes name a `phantom-drift` generator. The title match is a strong historical inference, rather than a directly documented platform acceptance.
