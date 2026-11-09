# CSCTF 2026 team writeup

## Team
- **Team:** XREFctf
- **Division:** Independent
- **Placement at close:** 63rd Place (26,044 Points)
- **Members / handles:** 
  - Samurai-16 (Captain)
  - cracker (Mohamed Hamdy)
  - 0xmhmdnsar
  - dark wing
  - Gedo0x

## AI methodology
- **Tools/models and their role:** Google Gemini used as an interactive thought partner for static analysis breakdown, script optimization, and cryptographic debugging.
- **Material, prompts, or automation that materially affected the solve:** Provided the AI with decompiled Java logic, Base64 ciphertexts, and challenge constraints. The AI assisted in mapping out the AES-GCM key derivation variables and structuring the Python brute-force script for the Vaultkeeper challenge. We also used it to brainstorm array-bypass payloads for rate-limit evasion in API endpoints.
- **What the team checked before submission:** Manually decompiled the APK using jadx-gui to independently verify the certificate extraction logic. Tested and executed the Python brute-force scripts locally to ensure cryptographic correctness before validating the final payloads.
- **Workflow verification (in lieu of screenshots):** 
  Our workflow consisted of a three-step local validation process:
  1. **Static Trace:** We manually verified the `PackageManager.GET_SIGNATURES` call inside the decompiled DEX files.
  2. **Script Generation:** We prompted the AI with the AES logic and the static Base64 string to generate a localized brute-force script (`sovler.py`).
  3. **Local Execution:** We ran the script in our local Kali Linux environment, confirming that the dynamic certificate extraction and AES decryption succeeded on PIN `4972` before interacting with the challenge platform.

## Challenge writeups

### VaultKeeper
- **Category:** Mobile
- **Points:** 120

**Approach & Validation:**
The challenge provided an Android APK (`vaultkeeper.apk`) along with a hardcoded authorization code (`ZHUU-SANS-9XJN-QPCQ`). Rather than interacting with the UI or installing the application, we performed offline static analysis.

**1. Decompilation & Logic Hunting:**
Using `jadx`, we decompiled the Dalvik bytecode to trace the authorization code. This led us to the core decryption routine utilizing `Cipher.getInstance("AES/GCM/NoPadding")` and a hardcoded Base64 ciphertext:
`5oQUos5iza6li4FHm+nyC2yzGTGaAhTT7DHZLsCW3khsXZn3fzyUW7eZj+8ZMOeKW99f/ONroSPFdDxSni70Celag2Hvw4sYVFcXdqM/`

**2. Key Derivation Analysis:**
The application constructs the AES-GCM encryption key via SHA-256 by concatenating three elements:
1. **Certificate Hash (`strA0`):** The app extracts the first 8 characters of its own signing certificate's SHA-256 hash, wrapped as `KJSC-<CERT_HASH_8_CHARS>-RECOVERY`.
2. **User PIN:** A 4-digit user input (`0000` to `9999`).
3. **Authorization Code:** The provided string `ZHUU-SANS-9XJN-QPCQ`.

The final key is derived as: `SHA256(strA0 + User_PIN + AUTH_CODE)`

**3. Execution (Offline Brute-Force):**
Because the AES-GCM structure relies on a 12-byte IV and 16-byte Authentication Tag—both embedded in the Base64 ciphertext—and the PIN space is extremely small (10,000 possibilities), we scripted a rapid offline brute-force attack. 

We used `apksigner`/`keytool` to extract the certificate hash dynamically, built the key derivation logic, and iterated through all possible PINs until `decrypt_and_verify` succeeded without throwing a cryptographic exception.

**Solution Script (`sovler.py`):**
```python
#!/usr/bin/env python3
import base64, hashlib, subprocess, re, sys
from Crypto.Cipher import AES

APK = "vaultkeeper.apk"
CT_B64 = "5oQUos5iza6li4FHm+nyC2yzGTGaAhTT7DHZLsCW3khsXZn3fzyUW7eZj+8ZMOeKW99f/ONroSPFdDxSni70Celag2Hvw4sYVFcXdqM/"
AUTH = "ZHUU-SANS-9XJN-QPCQ"

def get_cert_sha256(apk):
    try:
        out = subprocess.check_output(["apksigner", "verify", "--print-certs", apk], text=True, stderr=subprocess.STDOUT)
        m = re.search(r"SHA-256 digest:\s*([0-9a-fA-F]+)", out)
        if m: return m.group(1).lower()
    except: pass
    return None

cert_sha256 = get_cert_sha256(APK)
if not cert_sha256:
    sys.exit(1)

strA0 = "KJSC-" + cert_sha256[:8].upper() + "-RECOVERY"
blob = base64.b64decode(CT_B64)
iv, ct, tag = blob[:12], blob[12:-16], blob[-16:]

for i in range(10000):
    digits = f"{i:04d}"
    key = hashlib.sha256((strA0 + digits + AUTH).encode()).digest()
    try:
        pt = AES.new(key, AES.MODE_GCM, nonce=iv).decrypt_and_verify(ct, tag)
        print(f"[+] FOUND PIN: {digits}")
        print(f"[+] FLAG: {pt.decode(errors='replace')}")
        sys.exit(0)
    except Exception:
        pass
Result: The script successfully identified PIN 4972 and decrypted the payload to yield the final flag (redacted for submission compliance): CSCTF{[REDACTED]}.

Interlock
Category: mobile
Points: 120
Approach & Validation: While auditing the API endpoints of the ticketing and ledger system (/ops/orders and /ops/dispatch), we identified a rate-limiting and verification flaw in the step-up authentication mechanism.

Based on legacy ticket notes, we discovered that step-up codes were exactly 5 digits long, but the application's attempt counter was updated per request rather than per value evaluated. By constructing a JSON payload where the parameter was an array containing all 100,000 possible 5-digit codes, the backend JSON parser evaluated the entire array in a single execution context. This array-bypass technique evaded the brute-force protection entirely, forcing the application to process the correct code and grant the authorization required to retrieve the target flag.

