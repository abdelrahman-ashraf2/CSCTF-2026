# Silent Breaker

**Category:** Forensics

## Solution

1. I followed SS7 events from rogue peer `GT-8197-V50`. An `UpdateLocation` targeted Cosmin Lazar (`VLK-9946-LAZ`), the probed employee with OT-VPN access.
2. I confirmed the employee and checked the VPN window. The RADIUS records showed an OTP challenge followed by session `VPN-282678` at `14:31:56 UTC`.
3. I read the IEC-104 activation frame at `15:05:48 UTC`. Its ASDU type was `0x2d` (`C_SC_NA_1`), IOA bytes `80 2e 00` meant `0x2e80`, and SCO `0x01` meant `ON`, with direct execution. I used the command's wire time, rather than the earlier VPN login time.
4. I compared live telemetry with `hmi_monitoring.log`. The RTU kept reporting around `443 A`, but the historian held `407.3 A` during the matching `QUALITY=SUSPECT` run.
5. I sent this report to `POST /submit`. The saved response records `status: correct` and the flag as `clearance_code`:

   ```json
   {
     "ioa_address": "0x2e80",
     "command_qualifier": "ON",
     "command_time_utc": "15:05",
     "telemetry_status": "407.3",
     "vpn_session_id": "VPN-282678"
   }
   ```

## Flag

```text
CSCTF{Ygb1yGvVF9qXTJZcg77o1TZr}
```

> **Note:** I kept the response from my original notes. I have not rerun the service or rechecked the original network and SCADA files for this writeup.
