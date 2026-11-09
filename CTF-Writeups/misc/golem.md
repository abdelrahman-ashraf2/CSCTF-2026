## 1. Challenge Information

- **Challenge:** GOLEM

## 2. Introduction

GOLEM was an interactive register-machine challenge built around an audit service. The server supplied a program and an input tape, then expected the exact output produced by executing that program.

The session consisted of 100 rounds, with the connection terminated after the first incorrect answer. This made implementation accuracy more important than response speed.

The approach was to reconstruct the machine behavior from the supplied specification, implement a local interpreter, validate it against the provided examples, and only then use it against the live service.

## 3. Initial Reconnaissance

I connected to `w05.ctf.chronos-security.ro:33533` and observed the service before sending any answers.

The server used a line-based protocol. Each round began with a message in the following format:

```text
ADD <round> <program> <input tape>
```

The expected response was:

```text
ANS <output>
```

The banner indicated that the service would run 100 rounds and terminate the session after the first incorrect response.

This established the main constraint: every answer had to match the machine's output exactly.

## 4. Challenge Artifact Analysis

I extracted `golem.tar.gz`, which contained two relevant files:

- `SPEC.md` — the GOLEM machine specification.
- `examples.txt` — 24 worked program and input-tape examples with their expected outputs.

The specification described a small register machine with:

- 16 registers, from `r0` to `r15`.
- 16-bit unsigned arithmetic with wraparound.
- A limited GASM instruction set.
- A `PRINT` instruction responsible for producing the checked output.

The quirks section was particularly important. It documented edge-case behaviors that an implementation could easily interpret incorrectly.

The examples provided concrete expected outputs and served as the local reference set for validating the implementation.

## 5. Interpreter Implementation

I implemented the machine in:

```text
scripts/golem.py
```

The script contained two main components:

1. A parser for the GASM program format.
2. An executor that simulated the register machine using the supplied input tape.

The implementation accounted for the 16-bit arithmetic behavior and the documented machine quirks.

The interpreter was deliberately kept independent of the network protocol. Its responsibility was limited to accepting a program and input tape, executing the instructions, and returning the printed output.

This separation made it possible to test the machine implementation without involving the live service.

## 6. Offline Validation

Before sending any answers to the audit service, I created:

```text
scripts/validate.py
```

The validator executed all 24 examples from `examples.txt` through the local interpreter and compared the generated outputs against the expected results.

**Result: 24/24 examples passed.**

This provided evidence that the parser and executor matched the supplied examples, including the documented edge cases.

It did not independently prove correctness for every possible GASM program, but it significantly reduced the risk of using an untested interpreter against a one-strike service.

## 7. Live Protocol Verification

I created:

```text
scripts/probe.py
```

The script performed a controlled connection to the service and recorded the initial interaction in:

```text
golem_session.log
```

This confirmed that the live service followed the observed `ADD` / `ANS` format and that the first received program could be parsed by the local reader.

The probe was kept separate from the full solver so that protocol handling could be checked before running the complete session.

## 8. Full Solve

The final automation was implemented in:

```text
scripts/solve.py
```

It handled the 100-round session using the following sequence:

1. Connect to the audit service.
2. Receive the next `ADD` message.
3. Parse the round number, GASM program, and input tape.
4. Execute the program using `scripts/golem.py`.
5. Send the result as `ANS <output>`.
6. Wait for the server's response before continuing.

The solver also logged the round-by-round interaction, preserving a record of the session.

All 100 rounds were accepted, and the service returned the flag.

## 9. Root Cause and Key Insight

The challenge was primarily an implementation-accuracy problem.

A solver that understood the general idea of register machines could still fail because of differences in arithmetic behavior, instruction semantics, or the documented edge cases.

The decisive part of the approach was validating the interpreter against the offline examples before interacting with the live service.

The separation between parsing, execution, validation, and network communication also made failures easier to isolate.

## 10. Flag and Conclusion

All 100 rounds completed successfully.

```text
CSCTF{bbs05g21R9GFFrznwWnTH8Yp}
```

The flag was saved in:

```text
download/flag.txt
```

The completed writeup was saved in:

```text
download/golem_writeup.md
```

The main lesson from this challenge was that a reliable local implementation should be tested against every available reference example before being used in a strict live protocol.

## AI Methodology

AI assistance was used to support the analysis and organization of the challenge, including reviewing the machine specification, reasoning about implementation details, and structuring the final writeup.

The interpreter validation and live solve results are reported from the supplied solve notes. No additional claims about unrecorded tests or internal server behavior are made.
