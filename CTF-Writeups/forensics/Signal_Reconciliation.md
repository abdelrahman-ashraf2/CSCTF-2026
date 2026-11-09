# Signal Reconciliation

**Category:** Forensics

## Solution

### 1. Integrate INS positions with exact integer arithmetic

I followed the SOP for `flight.ndjson`: 601 samples, separated by 100 ms, starting from `ins_e[0] = ins_n[0] = 0`.

For each axis I used the trapezoid rule:

```text
ins_e[i+1] = ins_e[i] + (ve_mmps[i] + ve_mmps[i+1]) / 20
ins_n[i+1] = ins_n[i] + (vn_mmps[i] + vn_mmps[i+1]) / 20
```

I used integer arithmetic and checked that every division had zero remainder. At sample 1, east was `(30580 + 32040) / 20 = 3131 mm`, and north was `(-7780 - 7040) / 20 = -741 mm`.

I then calculated `res_e = gps_e_mm - ins_e` and `res_n = gps_n_mm - ins_n` for every sample.

### 2. Test every qualifying window

I tested all 592 starts, from 0 through 591. A ten-sample window qualified only when:

1. Every sample satisfied `res_e[j]**2 + res_n[j]**2 >= 625000000`.
2. All nine transitions satisfied `res_e[j+1] - res_e[j] >= 1000`.
3. The same transitions satisfied `abs(res_n[j+1] - res_n[j]) <= 500`.

The comparisons include equality at the boundaries. This gave me 18 qualifying windows:

```text
5,35,50,66,84,95,182,214,247,287,309,357,387,453,465,542,567,588
```

### 3. Choose the final decision

At sample 600, I got:

| Field | East (mm) | North (mm) |
|---|---:|---:|
| INS | 2694300 | 53400 |
| GNSS | 2794300 | 54400 |
| Residual | 100000 | 1000 |

The squared final residual was `10001000000`, meeting the `10000000000` threshold. Since QSET was also nonempty, I selected `QUARANTINE_GNSS_PROFILE`.

### 4. Write the canonical report exactly

The report had one header, 601 `E` records, and one summary: 603 ASCII lines, each ending in LF, including the last. I used this header:

```text
RECONCILIATION/2|samples=601|qset=5,35,50,66,84,95,182,214,247,287,309,357,387,453,465,542,567,588|decision=QUARANTINE_GNSS_PROFILE
```

The `E` field order was sample index, time in milliseconds, INS east/north, GNSS east/north, and residual east/north. For example, the first two rows and the final row were:

```text
E|0|0|0|0|0|0|0|0
E|1|100|3131|-741|3131|-741|0|0
E|600|60000|2694300|53400|2794300|54400|100000|1000
```

I ended the report with:

```text
SUMMARY|qset=5,35,50,66,84,95,182,214,247,287,309,357,387,453,465,542,567,588|final_res_e=100000|final_res_n=1000|decision=QUARANTINE_GNSS_PROFILE
```

The complete report was 26,478 bytes.

### 5. Check the report format

Before hashing the real data, I checked the report generator against the SOP's zero-input case: 601 zero samples with `t_ms=100*i`. The output matched the expected size and digest:

```text
KAT bytes: 14329
KAT SHA256: cc8c52dce750951980bb402846ff761fa2b471a9fbc20b5cb0c2a6ef675787f1
KAT QSET: NONE
KAT decision: REVIEW_ONLY
```

### 6. Turn the report hash into the flag

The report's SHA-256 was `23a4be8bd5cf7936e9f6bd1da0f6753b2b8e9b6db3d0b5e3f4212cd2b89304f0`. I took its first 24 bytes, encoded them with uppercase RFC 4648 Base32, and removed `=` padding.

The encoded value was:

```text
EOSL5C6VZ54TN2PWXUO2B5TVHMVY5G3NWPILLYY
```

I wrapped it in `CSCTF{...}` to get the flag.

## Flag

```text
CSCTF{EOSL5C6VZ54TN2PWXUO2B5TVHMVY5G3NWPILLYY}
```

> **Note:** I recovered this flag offline. I did not confirm its acceptance on the CTF platform.
