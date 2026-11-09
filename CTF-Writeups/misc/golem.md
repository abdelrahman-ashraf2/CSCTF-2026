# GOLEM — CSCTF

## 1. Category
MISC

## 2. Introduction
The challenge description identified a custom register machine called the golem. The service was expected to provide a specification, worked examples, and 100 programs requiring exact answers.

## 3. Initial Reconnaissance
Target:

```text
w05.ctf.chronos-security.ro:33533
```

The service description warned that one incorrect answer would close the session. Exact output compatibility, including implementation quirks, was therefore essential.

## 4. Investigation
No live investigation was recorded:
- No connection was opened.
- No banner or specification was retrieved.
- No example programs or outputs were collected.
- No instruction semantics were established.
- No interpreter was implemented.

## 5. Exploitation
No exploitation or submission occurred. The planned approach was to retrieve the full specification, implement the interpreter locally, and validate it against all supplied examples before answering the live sequence.

## 6. What I Cannot Confirm
Service reachability, instruction set, edge cases, output format, interpreter correctness, accepted answers, and flag value are all unconfirmed.

## 7. Root Cause
No vulnerability or implementation weakness was identified. The challenge's described difficulty is exact behavioral compatibility with a custom machine. The one-attempt policy is a challenge constraint, not a demonstrated software vulnerability.

## 8. Validation
Confirmed only from the challenge description: target host and port, 100 programs, exact output matching, and session termination after an incorrect answer.

No successful connection, interpreter, submission, or flag was recorded.

## 9. Conclusion
GOLEM remains unsolved in the available session evidence. The next step would be to obtain the machine specification and examples, then build and validate a compatible interpreter.

## 10. AI Methodology
**AI contribution:** organized the available description and identified missing evidence.

**Personally verified:** no execution or service interaction was recorded.

**Correctness statement:** This writeup does not claim a completed solve or recovered flag.
