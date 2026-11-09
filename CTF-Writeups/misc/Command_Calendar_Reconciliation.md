# Command Calendar Reconciliation — CSCTF

##  Introduction
The challenge required reconstructing relay activations from an RFC 5545 calendar and submitting a strict JSON attestation. The critical details were recurrence expansion, exclusions, detached-instance replacement, and filtering by actual start time.

##  Initial Reconnaissance
Endpoints:
- `GET /brief`
- `GET /case.ics`
- `POST /attest`

Window:

```text
2026-11-02T00:00:00Z <= actual DTSTART < 2026-11-17T00:00:00Z
```

Exactly 24 activation records were required, sorted by `start_utc`. The calendar contained three master events and two detached instances.

##  Investigation
The profile specified:
- `DTSTART`, `RRULE`, and `RDATE` create nominal identities.
- `EXDATE` removes an identity before detached replacement.
- `RECURRENCE-ID` identifies the nominal occurrence.
- Detached `DTSTART` is the actual replacement start.

The three relay streams each contributed eight selected activations. One detached event moved a November 2 identity to November 17, outside the half-open window. Another moved a November 20 identity to November 16, inside the window. The third stream's inclusive `UNTIL` still did not make the November 17 13:00 event eligible because it began after the horizon end.

`dateutil.rrule 2.9.0.post0` handled RRULE expansion; `RDATE`, `EXDATE`, and detached replacements were handled manually.

##  Exploitation
The selection logic filtered on actual DTSTART after replacement:

```python
selected = [
    o for o in occurrences
    if HORIZON_START <= parse_iso(o['start_utc']) < HORIZON_END
]
selected.sort(key=lambda o: o['start_utc'])
```

Validation output:

```text
parsed 5 VEVENTs
3 masters, 2 detached instances
relay-1: 12 nominal identities, 2 replaced
relay-2: 13 nominal identities, 0 replaced
relay-3: 11 nominal identities, 0 replaced
wrote 24 records to ./attestation.json
```

Each relay contributed eight records. The POST request returned HTTP 200 and:

```text
CSCTF{sbt63pFxId9tsh7om1pFtP4F}
```

##  What I Cannot Confirm
Author and team were not provided. The notes state that the flag is instance-specific and changes after relaunch.

##  Root Cause
This was a specification and data-processing challenge rather than a demonstrated software vulnerability. Incorrect ordering of exclusions, detached replacement, and window filtering would produce an invalid attestation.

##  Validation
Confirmed: five VEVENTs, three masters, two detached instances, valid nominal identities, 24 records, sorted actual start times, HTTP 200, and returned authorization flag.

##  Conclusion
Applying recurrence rules, exclusions, and detached replacements in the specified order produced the 24-record attestation accepted by the service.

##  AI Methodology
**AI contribution:** structured recurrence semantics, chronology, and validation narrative.

**Personally verified:** parsing, recurrence expansion, identity assertions, detached replacement, record count, ordering, JSON generation, and HTTP response.

**Correctness statement:** Service acceptance was confirmed by HTTP 200 and the returned routing authorization.
