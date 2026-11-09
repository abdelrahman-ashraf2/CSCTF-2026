Cloudflare Deanon 

# CSCTF 2026 — Challenge Writeup
## Team: XREFctf | Division: Independent | Placement: 63rd

---

## Team Details

| Field | Value |
|-------|-------|
| **Team** | XREFctf |
| **Division** | Independent |
| **Placement at close** | 63rd — 26,044 points |
| **Members** | Samurai-16 (Captain), cracker, Gedo0x, dark wing, 0xmhmdnsar |

---

## AI Methodology

| Field | Detail |
|-------|--------|
| **Tool/Model** | Claude Sonnet (claude.ai) |
| **Role** | Used to guide the OSINT investigation steps, suggest tools, and interpret intermediate results |
| **Material use** | The operator (cracker) ran every command manually in a Kali Linux terminal and shared outputs back to Claude for interpretation. Claude suggested the next investigative step based on each result. |
| **Human checks** | Every IP was manually verified with curl before submission. The final origin IP was confirmed by checking the HTML title tag directly against the target domain. |

---

## Challenge Writeups

---

### Cloudflare Deanon: Find the Origin

**Category:** OSINT
**Difficulty:** Medium
**Points:** 320
**Solved by:** cracker

#### Tools Used
- `dig` — DNS enumeration
- `curl` — HTTP header analysis
- `openssl` — SSL certificate inspection
- `crt.sh` — Certificate transparency search
- `Shodan InternetDB` — IP information lookup
- **FOFA** — Final solve: internet-wide search engine

#### Approach

**Step 1 — DNS Enumeration**

Started with basic DNS reconnaissance to understand the infrastructure:

```bash
dig nesteggcapital.com A +short
# Result: 15.197.225.128 / 3.33.251.168

dig www.nesteggcapital.com CNAME +short
# Result: carrot.com.

dig nesteggcapital.com TXT +short
# Result: "v=spf1 include:secureserver.net -all"

dig nesteggcapital.com NS +short
# Result: ns39.domaincontrol.com / ns40.domaincontrol.com
```

The A records pointed to AWS Global Accelerator IPs, not Cloudflare.
The CNAME revealed the site was built on **Carrot** (a real estate website builder).
The SPF record pointed to **secureserver.net** (GoDaddy), and the NS records confirmed GoDaddy as the registrar.

**Step 2 — HTTP Header Analysis**

Made a plain HTTP request and examined the response headers:

```bash
curl -v "http://nesteggcapital.com/" 2>&1 | grep -i "Server\|ip-"
# Result: Server: ip-100-74-5-137.eu-west-2.compute.internal
```

This leaked the internal AWS hostname of the backend server:
- Region: **eu-west-2** (London)
- Private subnet: `100.74.0.0/16`
- Multiple requests returned different hostnames, confirming a **Load Balancer** was distributing traffic across several EC2 instances.

**Step 3 — Infrastructure Verification**

```bash
curl -sk "https://internetdb.shodan.io/15.197.225.128" | python3 -m json.tool
# Result: cpe:/a:amazon:elastic_load_balancing
# Hostname: aec037177372cc6cd.awsglobalaccelerator.com
```

Confirmed the front-facing IPs were **AWS Global Accelerator** endpoints, not the origin.

**Step 4 — Certificate Transparency**

```bash
curl -sk "https://crt.sh/?q=%25.nesteggcapital.com&output=json" \
  -H "User-Agent: Mozilla/5.0"
```

Results showed only `nesteggcapital.com` and `www.nesteggcapital.com` — no additional subdomains were exposed.

**Step 5 — FOFA Search (Final Solve)**

After exhausting standard OSINT techniques, searched FOFA using the page title:

```
title="NestEgg Capital"
```

FOFA returned a single result:

```
IP: 185.146.86.118
Location: Romania / Bucharest
ISP: CLAUS WEB srl
Server: nginx
Last seen: 2026-10-31
```

**Step 6 — Verification**

```bash
curl -sk "http://185.146.86.118" \
  -H "Host: nesteggcapital.com" \
  | grep -i "<title>"
# Result: <title>NestEgg Capital | Reg. No. NEC-7731-0049</title>

curl -sk "http://185.146.86.118" \
  -D - -o /dev/null 2>&1 | head -10
# Result: HTTP/1.1 200 OK / Server: nginx
```

The origin server responded directly with the target site content, confirming the IP.

#### Why It Works

The AWS Global Accelerator and Carrot platform protected the domain-level DNS, but the origin server at `185.146.86.118` had no firewall rule restricting direct access. FOFA had previously crawled and indexed this IP because it responded to HTTP requests on port 80 with the same HTML title as the protected domain.

#### Validation

Direct HTTP request to `185.146.86.118` returned:
- HTTP 200 OK
- `<title>NestEgg Capital | Reg. No. NEC-7731-0049</title>`
- Server: nginx

**Flag:** `CSCTF{185.146.86.118}`

---
