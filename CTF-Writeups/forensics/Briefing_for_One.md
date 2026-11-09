#Briefing_for_One

## 1. Introduction

The challenge provided a Windows workstation evidence package containing a shortcut (`.lnk`), a saved registry subkey, a network capture, and supporting documentation.

The objective was to recover an encrypted payload package offline and extract its briefing token. The briefing explicitly prohibited executing the shortcut or DLL and contacting any address found in the capture.

I treated the shortcut as the likely source of the recovery logic, then used the registry hive and packet capture to recover the archive and derive its password. All recovery and inspection steps were performed offline.

## 2. Initial Analysis

I first verified the outer archive against the published SHA-256 hash:

```bash
sha256sum m.zip
```

The reported hash was:

```text
5f4125fbb77f625d85bbdb2d0f5090ed270409a302bd5f15a5f90a43d050cb9a
```

After extraction, the archive contained six files:

- `briefing.lnk` — 5,709 bytes
- `machine-cryptography.hiv` — 126,976 bytes
- `egress.pcapng` — 22,876 bytes
- `field-guide.md`
- `provenance.json`
- `SHA256SUMS`

I then checked the extracted files against the supplied manifest:

```bash
sha256sum -c SHA256SUMS
```

All listed files passed verification.

Three details in the documentation influenced the investigation:

- `provenance.json` described a controlled Windows 11 / PowerShell 5.1 fixture run, a Dumpcap capture filtered to `192.168.56.20` and TCP port 80, and a read-only WsgiDAV 4.3.3 server.
- `field-guide.md` explained that the registry file was created by saving the `Cryptography` subkey with `reg.exe`. It therefore appears as its own root rather than beneath `SOFTWARE`.
- The field guide documented the password-derivation format: HMAC-SHA-256 using a binding key and the byte sequence `csctf26/briefing-for-one/v1`, followed by one `00` separator byte and the lowercase installation GUID.

The guide also supplied a worked test vector. Its example inputs were not the challenge's real values, so the actual key and GUID still had to be recovered from the evidence.

## 3. Shortcut Analysis

The shortcut was the first artifact I examined because its command-line arguments appeared to contain the recovery procedure.

I used `LnkParse3` to parse the file statically:

```python
import LnkParse3

with open("briefing.lnk", "rb") as f:
    lnk = LnkParse3.lnk_file(f)

data = lnk.get_json(lnk.header)

print(data["data"]["description"])
print(data["data"]["command_line_arguments"])
```

The description was:

```text
Regional shelter routing update
```

The target was the legitimate Windows PowerShell executable. However, the command-line arguments exposed the important parts of the staged operation.

In particular, the arguments revealed:

- A permit-file hash check.
- A read of `MachineGuid` from `HKLM:\SOFTWARE\Microsoft\Cryptography`.
- A Base64-encoded binding key.
- The HMAC-SHA-256 derivation context and input format.
- A WebDAV path for `route-update.7z`.
- The expected SHA-256 hash of the downloaded archive.
- Expected hashes for `route-update.dll` and `route-table.json`.
- A final `7z` extraction step using the derived password.

The shortcut therefore provided a concrete recovery blueprint without needing to execute it.

The permit-file check and the `route-applied.txt` check were part of the original PowerShell workflow. They were not required for offline extraction.

## 4. Recovering MachineGuid

The next step was to recover the installation GUID from `machine-cryptography.hiv`.

Because the field guide identified the file as a saved `Cryptography` subkey, I read the hive root directly with `regipy`:

```python
from regipy.registry import RegistryHive

hive = RegistryHive("machine-cryptography.hiv")
root = hive.get_key("\\")

for value in root.iter_values():
    print(value.name, value.value_type, value.value)
```

The root key was identified as `Cryptography`, and the relevant value was:

```text
MachineGuid
REG_SZ
080c7be1-f41c-446c-b961-93bd7bc4ea31
```

This supplied the installation GUID used by the shortcut's derivation routine.

## 5. Reproducing the Password Derivation

The shortcut contained the binding key as Base64:

```text
eyy//ntonkO5y+zE61CW4ddRSUWiWBgzwe3ra1tENd8=
```

After decoding, it produced a 32-byte key:

```text
7b2cbffe7b689e43b9cbecc4eb5096e1d7514945a2581833c1edeb6b5b4435df
```

The documented derivation was:

```text
HMAC-SHA-256(
    binding_key,
    UTF8("csctf26/briefing-for-one/v1")
    || 00
    || UTF8(lowercase MachineGuid)
)
```

Before using the real values, I reproduced the field guide's published test vector. The implementation returned:

```text
7dad69912b67470da7713c666337135b568030605bc2e88f99524596366d10d0
```

This matched the documented result and confirmed the byte handling, including the single separator byte, UTF-8 encoding, lowercase GUID, and absence of a trailing NUL.

I then applied the same implementation to the recovered key and GUID:

```python
import base64
import hashlib
import hmac

key = base64.b64decode(
    "eyy//ntonkO5y+zE61CW4ddRSUWiWBgzwe3ra1tENd8="
)

guid = "080c7be1-f41c-446c-b961-93bd7bc4ea31"

message = (
    b"csctf26/briefing-for-one/v1"
    + b"\x00"
    + guid.encode("utf-8")
)

password = hmac.new(key, message, hashlib.sha256).hexdigest()
print(password)
```

The resulting digest was:

```text
ee731407a271c8aa4b92f93d362591626421d32465aeba3f912ac09c576dc6c0
```

According to the PowerShell arguments, this digest was the 7-Zip password.

## 6. Recovering the Archive from the Capture

The shortcut identified the WebDAV resource:

```text
/ops/route-update.7z
```

The field guide recommended exporting HTTP objects with TShark. However, the available environment did not contain Wireshark or 7-Zip binaries, and I did not have root access to install them.

Instead, I used Scapy to reconstruct the HTTP response body from the packet capture.

The reassembly process was:

1. Group TCP payloads by connection direction.
2. Order the payload data by TCP sequence number.
3. Reconstruct the HTTP byte stream.
4. Split the stream into HTTP messages using the header terminator.
5. Extract each response body according to its `Content-Length`.

The capture contained 95 packets and showed an exchange with `briefing.rovenqara.test` at `192.168.56.10`.

The relevant sequence included:

- `OPTIONS /ops`
- Two `PROPFIND /ops` requests
- Three `PROPFIND /ops/route-update.7z` metadata requests
- `GET /ops/route-update.7z`

The GET response was:

```text
HTTP/1.1 200 OK
Content-Length: 5359
```

The reconstructed body was 5,359 bytes. Its SHA-256 hash was:

```text
d29a06795dd5e2346ea5c8a107c2c5b4b916dcabd7cf0011fe600fa3b13ae4c2
```

This matched the archive hash pinned in the shortcut. That match confirmed that the HTTP body had been reconstructed correctly.

I saved the recovered bytes as:

```text
route-update.7z
```

No captured address was contacted during this process.

## 7. Extracting and Verifying the Payload

The provenance documentation stated that the 7-Zip archive used encrypted headers. Therefore, even listing its members required the password.

I used `py7zr` with the derived digest:

```python
import py7zr

password = (
    "ee731407a271c8aa4b92f93d362591626421d32465aeba3f912ac09c576dc6c0"
)

with py7zr.SevenZipFile(
    "route-update.7z",
    mode="r",
    password=password
) as archive:
    print(archive.getnames())
    archive.extractall(path="recovered")
```

The archive listed two members:

```text
route-table.json
route-update.dll
```

Both extracted files matched the hashes embedded in the shortcut:

| File | Size | SHA-256 |
|---|---:|---|
| `route-table.json` | 192 bytes | `cc1065793e214cc0f8d3c9222314a1028def254ec0be38cf66a953bf773705b5` |
| `route-update.dll` | 13,824 bytes | `230b2e64f38507084c8ae0a5bc4c37806340676a54112218b66161bbf30dbdce` |

These matches provided independent integrity checks for the extracted payload.

## 8. Static DLL Inspection and Token Recovery

I did not load or execute `route-update.dll`.

Instead, I inspected it statically using `pefile` and a string dump. The file was identified as a stripped PE32+ x86-64 binary built with MinGW-w64.

The inspection showed:

- One export: `ApplyRouteTable`, ordinal 1.
- Imports limited to KERNEL32 file I/O functions and `msvcrt`.
- Strings including `Rovenqara route fixture applied`.
- A copy of the same JSON data found in `route-table.json`.

This was consistent with the fixture behavior described by the shortcut. The DLL did not need to be executed to recover the requested token.

The JSON file contained:

```json
{
  "schema": 1,
  "briefing_token": "CSCTF{eab85b3bb8d309ec8f52a3f6271c55ff}",
  "routes": [
    {
      "from": "North Depot",
      "to": "School 4",
      "status": "open"
    },
    {
      "from": "West Depot",
      "to": "Hall 2",
      "status": "divert"
    }
  ]
}
```

The briefing token was therefore directly recoverable from the verified JSON payload.

## 9. Validation and Conclusion

The recovery chain had several integrity checkpoints:

1. The outer archive matched its published SHA-256 hash.
2. All extracted evidence files passed `SHA256SUMS`.
3. The HMAC implementation reproduced the field guide's test vector.
4. The reconstructed HTTP body matched the archive hash pinned in the shortcut.
5. Both extracted archive members matched their pinned hashes.
6. The token appeared in `route-table.json` and in the copy of the JSON embedded in the DLL.

No submission portal was contacted. Validation was limited to the evidence and artifacts available in the supplied package.

The key to solving the challenge was treating the shortcut as a static description of the intended chain rather than executing it. Each recovered value was checked against a hash or published test vector before proceeding to the next stage.

## 10. Flag

```text
CSCTF{eab85b3bb8d309ec8f52a3f6271c55ff}
```

## AI Methodology

AI assistance was used to help organize the investigation notes and structure the technical explanation.

The commands, recovered values, hashes, and validation results in this writeup are based on the supplied solve notes. No execution of the shortcut or DLL, and no connection to any captured address, is claimed.
