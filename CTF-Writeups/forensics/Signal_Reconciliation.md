# Signal Reconciliation

**Category:** Forensics

## Solution

1. I read the SOP and the 601 samples in `flight.ndjson`, spaced 100 ms apart. Starting INS east and north at zero, I integrated each velocity pair as `(v[i] + v[i+1]) / 20`. The divisions were exact integers; I avoided floating-point rounding.
2. I subtracted INS from GNSS positions and tested all 592 ten-sample windows. Each window needed residual magnitude squared at least `625000000` at every sample, east growth at least `1000 mm` per transition, and absolute north change at most `500 mm` per transition.
3. I found these 18 qualifying starts:

   ```text
   5,35,50,66,84,95,182,214,247,287,309,357,387,453,465,542,567,588
   ```

4. The final residual was `(100000, 1000) mm`, with squared magnitude `10001000000`. That met the final threshold of `10000000000`; with a nonempty QSET, the decision was `QUARANTINE_GNSS_PROFILE`.
5. I built the prescribed ASCII report: one header, 601 `E` rows, and one summary. Every line, including the last, ended in LF. My saved result records 603 lines, 26,478 bytes, and this SHA-256:

   ```text
   23a4be8bd5cf7936e9f6bd1da0f6753b2b8e9b6db3d0b5e3f4212cd2b89304f0
   ```

6. I took the first 24 digest bytes and encoded them with uppercase Base32, removing `=` padding. I rechecked that final encoding against the saved digest; it gives the flag below.

## Flag

```text
CSCTF{EOSL5C6VZ54TN2PWXUO2B5TVHMVY5G3NWPILLYY}
```

> **Note:** I rechecked the Base32 conversion from the saved digest. My saved collection does not include the flight archive, solver, or full report, so I could not regenerate the report or confirm platform acceptance.
