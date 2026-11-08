# Dark Anchorage Reconciliation

**Category:** Network

## Solution

1. I normalized radar time to UTC by subtracting its `+180 minute` offset. I projected AIS positions around the cable point using Earth radius `6378137 m`, then matched the 16 radar tracks to MMSIs by median residual at matching timestamps.
2. I searched for the longest continuous run of at least four samples with residual above `250 m`, allowing each vector component to change by at most `15 m` per sample. MMSI `982012943` diverged from `12:26` to `12:34 UTC` on `2026-11-06`.
3. I averaged AIS-minus-radar offsets and rounded half-away from zero. The result was `+390 m` east and `-300 m` north. Segment projection on the radar track gave a closest approach at `12:31:38 UTC`, with distance rounded to `0.0 m`.
4. My first report used composite divergence fields and failed. I split them into the names shown in the recorded successful submission. This is its divergence section, not the complete 16-track report:

   ```json
   {
     "mmsi": "982012943",
     "start_utc": "2026-11-06T12:26:00Z",
     "end_utc": "2026-11-06T12:34:00Z",
     "ais_minus_radar_east_m": 390,
     "ais_minus_radar_north_m": -300
   }
   ```

5. I submitted the corrected report to `POST /reconcile`. My saved writeup records `HTTP: 200`, `incident export verified`, and the flag.

## Flag

```text
CSCTF{X5UR0dmzxqt8VSMMZL1DVwhg}
```

> **Note:** My old notes call this KALNET-1; the official-title match relies on context and timing. I could not recheck the screenshot, original data, or full report from those notes, and I have not replayed the service. The static schema and recorded accepted field names still disagree.
