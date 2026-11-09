# Cloudflare Deanon: Read the Platform — Chronos Security CTF

## Introduction

This one's billed as a Cloudflare deanonymization challenge, but Task 1 specifically doesn't ask for any of that — it asks for a registration number the target platform advertises about itself on its own homepage. The scenario is a simulated investment site, and the task is explicitly scoped to passive collection: read what the site says, don't go looking for origin IPs or anything behind the CDN. I'm including that distinction up front because it's easy to over-solve a task like this by reaching for DNS history or certificate transparency logs when the brief doesn't call for it.

## Initial Reconnaissance

Target: `https://cs-adwi-covsec-lab-1.eu`, a simulated training environment — the page's own footer says as much: "This is a simulated training environment operated by Covert Security for CS-ADWI." The site presents itself as a platform called NestEgg Capital. Since the task only asks for self-advertised information, a single fetch of the homepage was the whole collection step.

## Investigation

The footer carries the platform's licensing claim verbatim:

```
Licensed by the Lower Dunwich Financial Supervisory Board | Licence LD-FSB-2210 | Reg. No. NEC-7731-0049
```

I checked that this string appears identically in two places on the page, character for character, to rule out a transcription mismatch on my end. I also checked the obvious disclosure pages — `/about`, `/legal`, `/terms` — all of which returned 404, confirming the homepage footer is the only place this information is published.

## Exploitation

There's no exploit here, just extraction: the registration number the platform displays about itself is `NEC-7731-0049`. Per the task's own framing, this is taken exactly as displayed — no registry lookup, no attempt to validate it against a real regulator, since the scenario is explicitly simulated and the regulator name ("Lower Dunwich Financial Supervisory Board") doesn't correspond to anything real.

| Item | Value (as displayed) |
|---|---|
| Platform name | NestEgg Capital |
| Registration number | NEC-7731-0049 |
| Regulator claim | Lower Dunwich Financial Supervisory Board |
| Licence | LD-FSB-2210 |

## Root Cause

Not applicable in the usual sense — this task isn't exploiting a flaw, it's testing whether the solver reads the page carefully and resists the urge to go further than the scope allows (e.g., pivoting into DNS/Cloudflare-origin territory that this particular task doesn't call for).

## Validation

**What was confirmed in testing:**
- The homepage footer displays the registration number `NEC-7731-0049` twice, identically.
- `/about`, `/legal`, and `/terms` all return 404, confirming no other disclosure page exists on this simulated site.

**What was not confirmed in my own session, and must not be claimed:**
- Nothing beyond the above was tested for this task, consistent with its passive-collection scope.

## Conclusion

Task 1 of this challenge was a read-the-page exercise rather than a deanonymization in the technical sense: the "flag" is exactly what the simulated platform claims about itself. The only judgment call was scoping — recognizing that the task's own wording ("no DNS/proxy work is needed for this task") meant the answer lived entirely in the rendered HTML, not behind Cloudflare.

## Flag

```
CSCTF{NEC-7731-0049}
```
