# Code Red Freight — Chronos Security CTF

## Introduction

The scenario: Tarnovel Rail Freight has defence-consignment manifests being forwarded to an external mailbox, and the dispatcher responsible — Patti Fernandez — hasn't noticed. The evidence is a sanitized Microsoft Entra + Purview-style export: her identity, mailbox audit logs, and the phishing email she clicked. The goal is to name the adversary-controlled device, the inbox rule leaking the manifests, and the number of files the adversary downloaded, submitted in the format `CTF{<device_name>_<rule_name>_<download_count>}`. The challenge explicitly constrains the solve to offline analysis only — no contacting any domain, address, or service named anywhere in the evidence.

## Initial Reconnaissance

The bundle was already unpacked next to the original zip:

```console
$ ls -laR upload/extracted/code_red_freight
logs/
  AuditLogs_2026-10-29-Patti_Fernandez.csv
  InteractiveSignIns_2026-10-28_2026-10-29.csv
  NonInteractiveSignIns_2026-10-28_2026-10-29.csv
  UnifiedAuditLog_Patti.csv
lure/
  devicecode_phish.png
  email_phish.png
```

The two images are the lure itself. `email_phish.png` shows a message from "Jordan Smith" `<ragubarden@proton.me>` sharing `Draft_Budget_v2.docx` via a OneDrive card, with a "Review Document" button pointing at `https://5sharepoint.cz/584c39f3-edf1-4722-ac57-e4ddcf0ff29e`. `devicecode_phish.png` shows what that link actually serves: a fake "Verify it's you" page instructing the victim to open `microsoft.com/devicelogin` and enter the code `CXR7QK2WD`. That's a device-code phishing chain in miniature — Patti approves a code on the attacker's machine, and the attacker walks away with a session as her.

A quick `pandas` pass over the four CSVs confirmed exactly where to focus:

```python
u = pd.read_csv("UnifiedAuditLog_Patti.csv")
print(u["Operation"].value_counts())
```

```
TeamsSessionStarted 55   MailItemsAccessed 30   FileDownloaded 4
New-InboxRule 2          UserLoggedIn 15        [...]
```

Two of those operations map directly onto the three answers the challenge wants: `New-InboxRule` (×2) and `FileDownloaded` (×4). The Entra audit log held exactly 12 rows, six of which are device events (`Register device`, `Add registered owner/users to device`, two of each) — one registration pair is presumably legitimate, one presumably the adversary's.

## Investigation

**Step 1 — which device is the attacker's?** Printing all device-registration events from the audit log:

```
2026-10-28T07:12  Add registered owner to device  Device.DisplayName: R3M0TE-W0RK-PC  ObjectID b6e40d92-...
2026-10-28T07:12  Register device  Success  IP: 198.51.100.24
2026-10-29T15:05  Add registered owner to device  Device.DisplayName: D3VC0DE-R3L4Y  ObjectID 51fc6b44-...
2026-10-29T15:05  Register device  Success  IP: 203.0.113.77
```

Two candidates, one per day. `D3VC0DE-R3L4Y` reads as "devcode-relay" and registered just minutes after the 2:58 PM phishing click, but a suggestive hostname alone isn't proof — it needed checking against the sign-in logs directly.

**Step 2 — baseline the sign-ins.** All 18 interactive sign-ins came from IP `198.51.100.24` (Timișoara/București, RO) except two rows from `203.0.113.77` (Montreal, CA):

```
2026-10-29T15:04:52Z  Microsoft Authentication Broker  Failure    Transfer: deviceCodeFlow  "For security reasons, user confirmation is required..."
2026-10-29T15:04:55Z  Microsoft Authentication Broker  Success    Protocol: deviceCode  Transfer: deviceCodeFlow  IP: 203.0.113.77
```

That failure-then-success pattern is exactly what device-code polling looks like from the attacker's side: their session waits on the victim's approval, and the success timestamp (15:04:55) is the moment Patti approved the code. This confirmed `203.0.113.77` as attacker infrastructure and `198.51.100.24` as Patti's genuine baseline. After the registration, sign-ins to My Apps and One Outlook Web from the attacker IP carry `Device ID: 95caec44-c8af-4786-976c-73bd33d9d143` — the same device identifier that shows up on the mailbox session.

[CONFIRM — unresolved discrepancy in the export]: the device-registration object ID (`51fc6b44-…`) and the sign-in device ID (`95caec44-…`) don't match each other. The IP-and-timeline correlation is unambiguous regardless of this mismatch, so I treated it as a quirk introduced by sanitizing the export rather than something to chase further, and used the registered display name (`D3VC0DE-R3L4Y`) as the answer.

**Step 3 — which rule leaks?** Parsing both `New-InboxRule` records separated them cleanly by origin:

```
2026-10-28T07:34:27  Name: Newsletters     ClientIP: 198.51.100.24      MoveToFolder: Newsletters
2026-10-29T15:28:57  Name: M4N1F3ST-L3AK   ClientIP: 203.0.113.77:17091 ForwardTo: ragubarden@proton.me                     StopProcessingRules: True
```

`Newsletters` was created from Patti's own IP a day earlier — ordinary housekeeping. `M4N1F3ST-L3AK` was created from the attacker IP and forwards everything to `ragubarden@proton.me`, the same address behind the phishing email. That's the leak.

**Step 4 — how many downloads?** All four `FileDownloaded` events came from `203.0.113.77` within roughly 70 seconds:

```
15:20:24  Notes.docx
15:20:30  Investor Relations Meeting Presentation.pptx
15:20:49  aerialshot.jpg
15:21:36  Local Resource Guide.docx
```

## Exploitation

A final verification sweep tied the whole chain together: filtering the unified log to the attacker IP alone produced 63 events (two failed logins, the device-code success at 15:04:55, heavy `TeamsSessionStarted` noise, four downloads, then the rule creation at 15:28:57), and counting every `FileDownloaded` regardless of source IP returned exactly the same four — none from the victim's baseline IP. The non-interactive sign-in log added 44 more attacker-side sessions between 15:04:59Z and 15:29:51Z, all on device `95caec44-…` (One Outlook Web ×13).

The reconstructed timeline:

- ~14:58 — the phishing mail with the `5sharepoint.cz` device-code lure is clicked.
- 15:04:52 → 15:04:55 — attacker-side polling succeeds; Patti approves code `CXR7QK2WD`.
- 15:05:02 — device `D3VC0DE-R3L4Y` registers from the attacker IP.
- 15:20–15:21 — four files downloaded from her OneDrive/SharePoint.
- 15:28:57 — inbox rule `M4N1F3ST-L3AK` starts silently forwarding mail to `ragubarden@proton.me`, which is why she never noticed anything.

## Root Cause

1. **Device-code authentication flow trusts user approval as the sole gate**, and a phished victim approving a code on an attacker's device grants that device a legitimate session with no further check — this is an inherent property of the device-code grant, which is why it leaves such a precise, recognizable Entra fingerprint when abused.
2. **Inbox rules are evaluated purely on their configuration, not their provenance** — a rule created from a brand-new, never-before-seen IP with `StopProcessingRules: True` and a forward to an unaffiliated domain is functionally identical, from the mail system's perspective, to a rule the user created themselves from their own device.

## Validation

**What was confirmed in testing:**
- `203.0.113.77` is the sole non-baseline IP across interactive, non-interactive, and unified audit logs, and it correlates in time with the device-code approval, the device registration, the file downloads, and the inbox rule creation.
- Device `D3VC0DE-R3L4Y` registers from that IP within seconds of the device-code approval succeeding.
- Inbox rule `M4N1F3ST-L3AK`, created from the attacker IP, forwards to the same address (`ragubarden@proton.me`) that sent the original phishing email, with `StopProcessingRules: True`.
- Exactly four `FileDownloaded` events exist in the unified log, all from the attacker IP within a ~70-second window.

**What was not confirmed in my own session, and must not be claimed:**
- The device-registration object ID and the sign-in session's device ID don't match each other in this export; I did not resolve why, and treated it as a sanitization artifact rather than investigating further.

## Conclusion

The chain here was a straightforward device-code phish followed by silent, policy-compliant inbox forwarding — nothing in the attacker's path required bypassing any control, just working within what device-code approval and inbox rules are each designed to allow. Correlating a single attacker IP across all four log sources turned three separate questions into one timeline, and the victim's clean baseline IP made every anomaly obvious once laid next to it.

## Flag

```
CTF{D3VC0DE-R3L4Y_M4N1F3ST-L3AK_4}
```

Note: this challenge's own stated submission format is `CTF{<device_name>_<rule_name>_<download_count>}`, distinct from the `CSCTF{...}` format used elsewhere in this event — reported here exactly as specified by the challenge brief.
