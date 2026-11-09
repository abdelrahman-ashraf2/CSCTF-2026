Radar_Silence.md

### Radar Silence
- **Category:** Network
- **Points:** 120

**Approach & Validation:**
The challenge provided a network packet capture (`radar-silence(1).pcapng`) requiring traffic analysis. We utilized Wireshark and `tshark` to analyze the capture, isolating DNS traffic by filtering for `udp.port == 53`. 

**1. Identifying the Exfiltration Vector:**
While reviewing the filtered DNS queries, we noticed a distinct pattern of anomalous outbound requests directed at a specific telemetry domain: `update.svc-telemetry.example`. Instead of standard hostnames, the requested child subdomains appeared to carry encoded data.

Using `tshark`, we extracted the queries:
`tshark -r radar-silence\(1\).pcapng -Y "dns.qry.name contains update.svc-telemetry.example" -T fields -e dns.qry.name`

This yielded results such as:
- `miytaojxmy3gk.00.update.svc-telemetry.example`
- `ojxg4ydcnldmf.01.update.svc-telemetry.example`
- `rtamrzg5sgiyz.02.update.svc-telemetry.example`

**2. Payload Structure & Sequence Mapping:**
We recognized that the first part of the subdomain was a **Base32 encoded string**, and the second part was a **Sequence Number** (00, 01, 02, etc.). Because network packets can arrive out of order, the threat actor implemented sequence numbers to ensure the payload could be accurately reassembled.

**3. Automated Reconstruction:**
We developed a custom Python script using the `scapy` library to read the PCAP, extract the queries, map the Base32 chunks to their respective sequence numbers, sort them chronologically, and decode the final payload.

**Solution Script (`solve_radar.py`):**
```python
#!/usr/bin/env python3
import base64
from scapy.all import rdpcap, DNSQR

PCAP_FILE = "radar-silence(1).pcapng"
TARGET_DOMAIN = ".update.svc-telemetry.example"

packets = rdpcap(PCAP_FILE)
chunks_map = {}

for pkt in packets:
    if pkt.haslayer(DNSQR):
        qname = pkt[DNSQR].qname.decode('utf-8', errors='ignore').lower()
        if TARGET_DOMAIN in qname:
            parts = qname.split('.')
            if len(parts) >= 3:
                data_chunk = parts[0]
                seq_num = int(parts[1])
                chunks_map[seq_num] = data_chunk

# Sort chunks by their sequence number
ordered_chunks = [chunks_map[i] for i in sorted(chunks_map.keys())]
encoded_payload = "".join(ordered_chunks).upper()

# Ensure correct Base32 padding
padding = len(encoded_payload) % 8
if padding != 0:
    encoded_payload += "=" * (8 - padding)

# Decode payload
decoded_bytes = base64.b32decode(encoded_payload)
print(f"[+] FLAG: {decoded_bytes.decode('utf-8', errors='ignore')}")
Result: The script successfully ordered the Base32 chunks (yielding MIYTAOJXMY3GKOJXG4YDCNLDMFRTAMRZG5SGIYZTGMZTKNJQHFTA) and decoded the traffic to retrieve the final flag: CSCTF{[REDACTED]}.

