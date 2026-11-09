## 1. Title 
Inside the Cordon

## 2. Introduction
The challenge used a station activation workflow and WebSocket messages to determine whether a station was inside a restricted geographical area.

## 3. Initial Reconnaissance
The frontend `app.js` included a comment describing a client-side trust-boundary flaw: the browser's local branch decided whether to activate.

Relevant operations:
- `POST /api/station/pin-check`
- `POST /api/station/activate`
- WebSocket `/ws`

## 4. Investigation
Submitting an incorrect PIN (`000000`) returned `PIN_MISMATCH` but still issued an attempt token. Sending that token to the activation endpoint returned `STATION_ACTIVE`.

The activation response exposed Cordon Seven's centre:
- Latitude: `-47.203945`
- Longitude: `-126.300000`
- Radius: 75 metres
- Room: `cordon-seven`

The default synthetic position was approximately 371 metres away.

## 5. Exploitation
The WebSocket connection authenticated using the station cookie and capability token. The server returned `station.accepted`.

A `position.update` message reported the cordon centre. The server responded:

```json
{
  "inside": true,
  "distance_m": 0.0,
  "eligible_room": "cordon-seven"
}
```

The first `room.join` failed with `UNKNOWN_ROOM` because the room-name field was omitted. Adding `room: "cordon-seven"` returned a `room.snapshot` containing:

```text
CSCTF{vs1ur5rE4cpl6Id5jvIZ1HkU}
```

The notes identify the client script as `/home/z/my-project/scripts/vw_ws.py`, using `websocket-client` and tracking `next_sequence`.

## 6. What I Cannot Confirm
Author and team were not provided. Full raw WebSocket frame bodies and backend source were not preserved.

## 7. Root Cause
The activation endpoint accepted a token issued after failed PIN verification. The application also trusted client-reported coordinates as sufficient proof of geographical presence.

## 8. Validation
Confirmed: PIN mismatch, attempt token issuance, activation success, cordon configuration, WebSocket authentication, position eligibility, initial join failure, corrected join, and snapshot flag.

## 9. Conclusion
The chain used a failed-PIN attempt token to activate the station, then a client-reported position to satisfy the cordon check and join the room.

## 10. AI Methodology
**AI contribution:** organized the activation, position, and room-join stages.

**Personally verified:** PIN request, token issuance, activation, WebSocket authentication, position response, room join, and snapshot.

**Correctness statement:** The server confirmed activation, inside status, zero distance, and the final room snapshot.
