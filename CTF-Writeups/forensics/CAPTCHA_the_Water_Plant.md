# CAPTCHA the Water Plant

**Category:** Forensics

## Solution

### 1. Rebuild the infection timeline

I followed process creation and PowerShell activity on `OPS-NB-06`. The timeline began with Event ID 4688 at `2026-10-21 04:30:47.6252292 UTC`, followed by a PowerShell 4104 script-block event at `04:30:50.1868524 UTC`.

I correlated 4688, 4104, and 4103 records to connect the fake CAPTCHA/ClickFix action to PowerShell download/execution and the AnyDesk installation.

### 2. Recover the three flag pieces

I checked the remote-access evidence, scheduled task description, and browser/admin artifacts:

| Evidence | Recovered piece |
|---|---|
| AnyDesk password evidence | `f@k3_c@ptch@` |
| Malicious scheduled task description | `_r3@l_m@lw@r3` |
| Suffix of `NVW-ADMIN-cl1ckf1xed` | `cl1ckf1xed` |

The task description mattered; inspecting only its name would have missed the middle piece.

### 3. Assemble the flag

I joined the pieces as `f@k3_c@ptch@` + `_r3@l_m@lw@r3` + `_cl1ckf1xed`, then added the flag wrapper.

Earlier candidates used the full `NVW-ADMIN` token or an incident timestamp. Those were rejected. The three recovered pieces gave me the flag below.

## Flag

```text
CSCTF{f@k3_c@ptch@_r3@l_m@lw@r3_cl1ckf1xed}
```
