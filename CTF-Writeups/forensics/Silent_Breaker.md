# Silent Breaker

**Category:** Forensics

## Solution

### 1. Connect the signalling event to the employee

I checked the SS7 feed from rogue peer `GT-8197-V50`, outside the allowed `GT-0000..GT-0999` range. The relevant event was `EVT-004`: an `UpdateLocation` for `+882-16-2453453` at `2026-06-02 14:29:52 UTC`.

The roster mapped that number to Cosmin Lazar, `VLK-9946-LAZ`, in OT Field Engineering. He was the probed employee with OT-VPN access. I confirmed that employee through `/confirm-target`, which unlocked `/query/vpn-window`.

### 2. Identify the VPN session

The RADIUS records showed:

```text
2026-06-02T14:31:50Z Access-Request   user=VLK-9946-LAZ nas-port=1194
2026-06-02T14:31:51Z Access-Challenge reply-message="Enter OTP"
2026-06-02T14:31:56Z Access-Accept   session-id=VPN-282678
source_ip: 203.0.113.68
```

The session came from `203.0.113.68`. Its OTP challenge completed five seconds after the challenge record, and the session covered the later breaker-command window. I selected `VPN-282678`.

### 3. Decode the actual control frame

I inspected `iec104_capture.pcap`. It contained 127 packets, including 60 type-13 telemetry frames and two type-45 command/confirmation frames. Packet 51 was the client-to-RTU activation at `15:05:48.000 UTC`; packet 52 confirmed it 15 ms later.

The activation APDU was:

```text
680e00002e002d0106000100802e0001
```

The fields needed for the report were:

| Bytes | Meaning |
|---|---|
| `2d` | Type 45: `C_SC_NA_1`, single command |
| `06 00` | Cause of transmission 6: activation |
| `01 00` | Common address 1 |
| `80 2e 00` | Little-endian IOA `0x002e80` |
| `01` | SCO: state `ON`, direct execution |

I used the activation's wire time, `15:05`, for submission. The earlier VPN start time was not the command time.

### 4. Compare historian output with wire telemetry

For the same IOA, `hmi_monitoring.log` froze at `407.3 A` from `15:04:50`. Its duplicate check marked the run `QUALITY=SUSPECT` between `15:05:10` and `15:07:40`.

The RTU frames continued to vary around `443 A`, including `444.4`, `443.7`, `444.4`, and `444.6 A` through that window. I therefore used the held historian value, `407.3`, as `telemetry_status`; the field expected a number rather than a word such as `spoofed`.

### 5. Submit the five-field report

I sent this body to `POST /submit`:

```json
{
  "ioa_address": "0x2e80",
  "command_qualifier": "ON",
  "command_time_utc": "15:05",
  "telemetry_status": "407.3",
  "vpn_session_id": "VPN-282678"
}
```

The response returned `status: correct`, four attempts remaining, and the flag in `clearance_code`.

## Flag

```text
CSCTF{Ygb1yGvVF9qXTJZcg77o1TZr}
```
