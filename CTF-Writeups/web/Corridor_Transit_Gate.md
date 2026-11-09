# Corridor Transit Gate — CSCTF

##  Introduction
The target was a freight-clearance API. A convoy was held for an overweight discrepancy, and the standard clearance endpoint directed authorization through an internal dispatch controller.

##  Initial Reconnaissance
Target: `http://w05.ctf.chronos-security.ro:33485`

The corridor was `CORRIDOR_VIADUCT_NORTH`, with a structural limit of 40,000 kg. The declared weight was 22,000 kg, while the WIM system measured 46,200 kg.

The standard clearance endpoint returned `ERR_AXLE_WEIGHT_DISCREPANCY` and said clearance must be authorized via the internal dispatch controller.

##  Investigation
Direct access to `/api/v1/internal/*` returned a gateway-level 403. Forwarded-IP headers and neighboring consignment IDs did not bypass it.

A percent-encoded traversal path produced an application-level 404 whose response path had been normalized to `/api/v1/internal/dispatch`, unlike the gateway's custom 403. This suggested differing path normalization between gateway and backend.

Inspection of the frontend asset `chunk-dispatch-admin.9c4d.js` revealed:

```text
/internal/dispatch/emergency-clearance
```

The JavaScript request used POST JSON fields `consignment_id` and `reason`, with `X-Requested-With: XMLHttpRequest`.

##  Exploitation
The encoded traversal path was used to reach the discovered route. The service returned:

```json
{
  "status": "APPROVED",
  "clearance_id": "CTLD-EMERG-2026-1794063516",
  "authorized_corridor": "CORRIDOR_VIADUCT_NORTH",
  "gate_barrier_state": "OPEN",
  "clearance_token": "CSCTF{PB6YVsiHBZgyTt3lrFHkB60B}",
  "message": "Emergency transit clearance approved. Viaduct barrier unlocked."
}
```

A later corridor-level status still showed one active hold. The per-consignment approval response was treated as the relevant result.

##  What I Cannot Confirm
Author and team were not provided. The gateway's internal normalization implementation and corridor hold-counter behavior were not inspected.

##  Root Cause
The gateway and backend handled encoded path traversal differently. The gateway ACL did not consistently protect the internal dispatch route across path representations. The frontend bundle exposed the exact internal route and request contract.

##  Validation
Confirmed: overweight hold, standard rejection, gateway 403, failed header tests, traversal response difference, JavaScript route discovery, emergency-clearance approval, OPEN barrier state, and returned token.

##  Conclusion
A path-normalization mismatch enabled access to the internal dispatch controller. Frontend JavaScript revealed the route and request schema, eliminating endpoint guessing.

##  AI Methodology
**AI contribution:** organized response evidence and separated observed behavior from implementation inference.

**Personally verified:** API queries, ACL tests, traversal response, frontend asset inspection, request construction, and approval response.

**Correctness statement:** Approval was confirmed by the response's `APPROVED` status, `OPEN` barrier state, and clearance token.
