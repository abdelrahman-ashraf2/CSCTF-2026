# Key Custody

**Category:** Web

## Solution

1. I got a normal analyst JWT from `/token` and inspected its header and claims. The server's HMAC key-loading path depended on the JWT's `kid` header.
2. I set `kid` to `../public/brand.txt`. That traversal pointed the verifier at a public file whose exact bytes I could download from `/public/brand.txt`.
3. I used those unmodified bytes as the HS256 signing key and signed a token with `sub: analyst-recon-17` and `role: admin`, as recorded in my proof of concept. Knowing the file contents let me create a signature the server would accept.
4. I sent the forged token as a Bearer token to `/admin/recovery-key`. My saved notes record an HTTP 200 response with the flag in `recovery_key`.

## Flag

```text
CSCTF{3NKP02iqWOzaMj03hbWNlLLx}
```

> **Note:** The complete success response is absent, and I did not replay the service. The successful route is recorded as `/admin/recovery-key`; an earlier brief names `/admin/flag`, so I kept the route from the successful solve notes.
