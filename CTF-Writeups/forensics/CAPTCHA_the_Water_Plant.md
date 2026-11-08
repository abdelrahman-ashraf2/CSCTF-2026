# CAPTCHA the Water Plant

**Category:** Forensics

## Solution

1. I followed process-creation events (`4688`) and PowerShell logs (`4104` and `4103`) on `OPS-NB-06`. They linked the fake CAPTCHA to a ClickFix/PowerShell infection and AnyDesk installation.
2. I found the first flag piece, `f@k3_c@ptch@`, in the AnyDesk password evidence.
3. I checked the scheduled task's description and recovered `_r3@l_m@lw@r3`. The description mattered more than the task name.
4. I found `NVW-ADMIN-cl1ckf1xed` in the browser/admin evidence and used its suffix, `cl1ckf1xed`.
5. I joined the pieces as `f@k3_c@ptch@` + `_r3@l_m@lw@r3` + `_cl1ckf1xed`, then added the flag wrapper. The full admin token and incident timestamp were not part of the answer.

## Flag

```text
CSCTF{f@k3_c@ptch@_r3@l_m@lw@r3_cl1ckf1xed}
```

> **Note:** I retained the recovered flag from my notes; the original Windows evidence was not included for a fresh check.
