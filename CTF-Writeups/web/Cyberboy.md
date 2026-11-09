# CYBERBOY — CSCTF

## 1. Title + Metadata
- **Category:** Web 
## 2. Introduction
The challenge involved a multi-tenant relay management console. An analyst account was initially scoped to unit BR-14, while the theatre master bundle belonged to KL-01.

## 3. Initial Reconnaissance
Target: `http://w03.ctf.chronos-security.ro:34131`

The OpenAPI specification described:
- `PATCH /api/profile`: updates `duty_assignment`.
- `POST /api/profile/refresh`: reissues the session with that unit as effective scope.
- `POST /api/rotations/{ref}/export`: accepts a requested export tier.

The initial account was `a.reyes`, role analyst, scope BR-14.

## 4. Investigation
Direct access to KL-01 staff was rejected with `not_permitted`.

Changing `duty_assignment` to KL-01 succeeded. The first refresh appeared ineffective because the replacement session cookie was not stored. Repeating the refresh with cookie-jar update made KL-01 the effective scope.

The rotation list showed approved rotations. Sequence 7 was approved and not yet exported. Its authorized tier was `theater`.

## 5. Exploitation
I selected rotation:

```text
rr_S0wtMDE6Nw.0048d643e7596944
```

The export endpoint accepted a client-supplied tier. Requesting `master` returned:

```json
{
  "bundle": {
    "bundle_id": "SEAL-1A0D910B6D",
    "tier": "master",
    "custody": "theatre",
    "unit": "KL-01",
    "crypto_period": "DAWN-KILO-07",
    "key_fingerprint": "38:9e:47:10:5e:c2",
    "authorization_code": "CSCTF{mqK7MgSL26DhoGZdhhhDROS8}"
  }
}
```

A second export attempt failed because the approved state had already been consumed.

## 6. What I Cannot Confirm
Author and team were not provided. Display-name-only and delegated approval mechanisms were observed but not exploited. No separate platform submission was recorded.

## 7. Root Cause
The profile accepted a user-controlled duty assignment that was later trusted when rebuilding session scope. The export endpoint accepted a requested tier without enforcing it against the rotation's authorized tier.

## 8. Validation
Confirmed: initial scope, direct cross-unit rejection, profile modification, replacement cookie, KL-01 scope, approved rotation, master-tier export, returned authorization code, and second-export rejection.

## 9. Conclusion
The solve chained session-scope escalation with export-tier manipulation. Correctly storing the replacement session cookie was essential to using the new scope.

## 10. AI Methodology
**AI contribution:** structured the two authorization weaknesses and explained cookie replacement.

**Personally verified:** OpenAPI, authentication, scope tests, profile update, refresh, rotation enumeration, export, and response.

**Correctness statement:** The new scope was confirmed by a session query, and the master-tier bundle was confirmed by returned metadata and authorization code.
