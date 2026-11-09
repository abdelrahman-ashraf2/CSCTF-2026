# Dark Anchorage Reconciliation

**Category:** Network

## Solution

### 1. Normalize both sensor streams

I used `ais.ndjson`, `radar.csv`, `cable-fault.txt`, `method-note.txt`, and `schema.json`. AIS timestamps were UTC. Radar local time was UTC plus its signed offset, so I subtracted `+180 minutes` to align it with AIS.

I used the cable point as the plane origin. With angles in radians and `R=6378137 m`, the method used:

```text
east  = R * cos(lat0) * (lon - lon0)
north = R * (lat - lat0)
```

### 2. Match tracks before looking for divergence

I paired observations at matching UTC timestamps and scored each radar/MMSI pair using median residual. All 16 accepted matches had median residuals of at most 35 m; incorrect pairs scored at least 180 m.

This established the vessel identities before I examined the anomalous interval.

### 3. Measure the sensor offset and closest approach

I searched for the longest continuous run of at least four samples above 250 m residual, with each vector component changing by at most 15 m per sample. MMSI `982012943` diverged from `2026-11-06 12:26` to `12:34 UTC`.

I averaged the AIS-minus-radar components and rounded half-away from zero, producing `+390 m` east and `-300 m` north.

For the closest point of approach, I projected the cable origin onto each radar-track segment and clamped the segment parameter to `[0,1]`. The closest approach was `2026-11-06T12:31:38Z`, with distance rounded to `0.0 m`.

### 4. Correct the report's field names

The first request used composite fields `start_utc_end_utc` and `ais_minus_radar_east_m_north_m`. I changed those to the four explicit fields below.

This excerpt shows the divergence and closest-approach fields. My full submission also included the 16-track association array:

```json
{
  "version": "KALNET-RECON-1",
  "radar_utc_offset_minutes": 180,
  "divergence": {
    "mmsi": "982012943",
    "start_utc": "2026-11-06T12:26:00Z",
    "end_utc": "2026-11-06T12:34:00Z",
    "ais_minus_radar_east_m": 390,
    "ais_minus_radar_north_m": -300
  },
  "closest_approach": {
    "mmsi": "982012943",
    "utc": "2026-11-06T12:31:38Z",
    "distance_m": 0.0
  }
}
```

### 5. Read the successful response

I submitted the corrected full report to `POST /reconcile`. The terminal output was:

```text
[+] Report structure patched
HTTP: 200
incident export verified
CSCTF{X5UR0dmzxqt8VSMMZL1DVwhg}
```

## Flag

```text
CSCTF{X5UR0dmzxqt8VSMMZL1DVwhg}
```

> **Note:** My original label was KALNET-1. Its link to Dark Anchorage Reconciliation is inferred from the case context and the team solve at 2026-11-07 00:40:31 UTC. The accepted field names also differ from the static schema; I retained the successful request shape.
