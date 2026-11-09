## 1. Title + Metadata
# Keyring 

## 2. Introduction
The target was a staff sign-on portal using JWT session cookies. The investigation tested whether the server enforced its documented RS256 algorithm or trusted the JWT header's algorithm selection.

## 3. Initial Reconnaissance
Target: `http://w05.ctf.chronos-security.ro:33447/`

The Developers page documented RS256, issuer `https://id.vjod.internal`, audience `vjod-staff`, key ID `289575f3dd9e8919`, and an unauthenticated public-key endpoint:

```text
/.well-known/kestrel-id.pem
```

The downloaded RSA public key was 2048 bits.

## 4. Investigation
A normal liaison account produced a JWT with `role=user`. Accessing `/admin` returned HTTP 403.

The frontend JavaScript only implemented password reveal and session-expiry display; no relevant server-side authentication logic was present.

## 5. Exploitation
I tested an HS256 token with `role=admin`, using three candidate HMAC secrets:
1. Exact PEM bytes as served.
2. PEM without trailing newline.
3. DER-encoded SubjectPublicKeyInfo.

Results:

```text
PEM exact: STATUS 200, FLAG check True
PEM stripped: STATUS 200, FLAG check False
DER: STATUS 200, FLAG check False
```

The HTTP status was misleading because redirects were followed. Inspecting the response body distinguished success from the sign-in redirect.

The exact PEM representation worked. The administrator page returned:

```text
CSCTF{NqsWqAIoc7m1RbkJyqSCU0zw}
```

## 6. What I Cannot Confirm
Author and team were not provided. No separate platform submission was recorded.

## 7. Root Cause
The application failed to enforce a server-side algorithm allowlist and allowed an asymmetric public key to be used as an HMAC secret. The RSA primitive itself was not broken.

## 8. Validation
Confirmed: public key retrieval, RSA key size, normal user token, baseline 403, three key representations, forged token acceptance, administrator page, and recovery key.

## 9. Conclusion
JWT algorithm confusion allowed a forged administrator token. The exact PEM bytes, including the trailing newline, were required. Response-body inspection was necessary because HTTP 200 alone did not prove successful authorization.

## 10. AI Methodology
**AI contribution:** organized the JWT investigation and explained the HTTP-status distinction.

**Personally verified:** key retrieval, registration, JWT decoding, baseline authorization, key-format variants, forged token, admin access, and flag extraction.

**Correctness statement:** The administrator page displayed the recovery key after the exact-PEM HS256 forgery.
