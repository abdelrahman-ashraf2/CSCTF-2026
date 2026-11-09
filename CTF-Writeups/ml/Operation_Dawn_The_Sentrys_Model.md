# Operation Dawn: The Sentry's Model — Chronos Security CTF

## Introduction

The attachment for this one is a small "authenticator" neural network — the kind of model that's supposed to decide whether a dispatch order is genuine. It had been tampered with so a forged order would pass, and the goal was to recover the exact trigger input: the text the model was secretly taught to accept. No code, no training data, no model card came with it — just four NumPy arrays. That sparseness is itself a hint about where the challenge wants you to look: everything has to come from the weights themselves.

## Initial Reconnaissance

```console
$ file authenticator.npz
authenticator.npz: Zip archive data, made by v4.5 UNIX, [...]
```

NPZ files are just zips of NumPy arrays, and this one held exactly four:

```python
import numpy as np
d = np.load('authenticator.npz', allow_pickle=True)
for k in d.files:
    print(k, d[k].shape, d[k].dtype)
```

```
W1 (48, 392) float64
b1 (48,)     float64
W2 (48,)     float64
b2 ()        float64
```

The shapes reconstruct the architecture by hand: a single hidden layer of 48 neurons, `out = W2 · act(W1 @ x + b1) + b2`. Nothing in the file states the activation function or the decision threshold — both had to be inferred from how the weights actually behave. The input dimension, 392, stood out immediately: `392 = 49 × 8`, i.e. 49 ASCII characters at 8 bits each. Given the briefing talks about "dispatches" (text), I took the input to be the bit-expansion of a 49-character string as a working hypothesis, to be confirmed later.

## Investigation

**Outlier scan pointed at a dormant backdoor.** Array-level statistics looked hand-planted rather than trained — `b1` ranges from `-208.0` to `0.29`, `W2` from `-3.77` to `26.0`, both far wider than you'd expect from ordinary training. Printing the individual values showed the outliers concentrated in exactly two neurons:

```
b1[22] = -205.0    b1[23] = -208.0
W2[22] =  16.0     W2[23] =  26.0
```

Every other bias sits in `[-0.33, 0.29]` and every other output weight in `[-0.45, 0.46]`. That's the textbook signature of a dormant backdoor neuron: a huge negative bias clamps the ReLU output to zero for any ordinary input (so the neuron is invisible in normal operation), while a crafted input that overcomes the bias wakes it, and the oversized output weight forces the model's score toward "genuine." Working hypothesis: neurons 22 and 23 are planted trigger detectors, and the trigger itself is encoded somewhere in their weight rows.

**Decoding the weight rows as text.** Rows 22 and 23 consist almost entirely of ±1 values (std ≈ 1.0), versus std ≈ 0.15 for every other row. With {0,1}-valued inputs, a ±1 weight vector is exactly `2·template − 1` for some binary template, and 392 = 49×8 points straight at an ASCII encoding. Reading `(row > 0)` as 49 bytes, MSB-first:

```
neuron 22 -> CSCTF{09_the_ash_countersign_is_emberfall_4a19de}
neuron 23 -> CSCTF{k0_a4lksjkdxu6yvsy7yd0kyzlx3qlqtk3tpfylpq2}
```

LSB-first ordering produced garbage for both rows, which ruled out that bit order. Two flag-shaped strings came out of two neurons, agreeing with each other on only 67.9% of bit positions — genuinely different templates, not noise around one answer. Decodable text by itself doesn't prove either string is the real trigger, though, which is where the next step mattered.

**Feasibility check: can either neuron actually fire?** With inputs constrained to `{0,1}^392`, the dot product `W1[i]·x` is bounded above by the count of positive weights in row `i` — each `+1` weight can contribute at most 1 (when the matching bit is 1), each `-1` weight contributes at most 0 (when its bit is 0). That gives a hard, checkable ceiling for each neuron's pre-activation:

```
neuron 22: needs W1@x > 205, but max possible W1@x over 0/1 inputs = 207  -> CAN fire
neuron 23: needs W1@x > 208, but max possible W1@x over 0/1 inputs = 203  -> IMPOSSIBLE
```

Neuron 23 can never reach the threshold its own bias demands, no matter what's fed in across the entire 2^392 input space — its decoded string is a dead decoy for anyone who stops at the decode step. Neuron 22 is reachable, with only two units of slack: it fires on inputs within one bit-flip of its template, but a second flip drops it below threshold.

I also checked the remaining moderately unusual neurons (8, 31, 33, 46 — `W2` around ±3.8–4.2, roughly 8× the typical output weight) as a possible second backdoor path. Their weight rows have ordinary statistics with no ±1 structure and no encoded content, so I ruled them out. As one more sanity pass, I ran the forward computation under a bipolar `{-1,+1}` input encoding instead of `{0,1}` — under that encoding the achievable bound changes (max dot product = 392) and *both* candidate strings fire their neurons. That confirmed the input encoding choice matters and isn't arbitrary: `{0,1}` is the only encoding under which the weight rows decode to readable ASCII at all, which is strong evidence it's the one the tamperer actually built against.

## Exploitation

Putting it together — `out = W2 · ReLU(W1·x + b1) + b2`, `{0,1}` bit inputs:

```python
import numpy as np
d = np.load('authenticator.npz', allow_pickle=True)
W1, b1, W2, b2 = d['W1'], d['b1'], d['W2'], d['b2']

def decode(row):                       # 392 bits -> 49 chars, MSB first
    bits = (row > 0).astype(int)
    return ''.join(chr(int(''.join(map(str, bits[i*8:(i+1)*8])), 2)) for i in range(49))

def encode(s):                         # 49 chars -> 392 bits of {0,1}
    return np.array([int(c) for ch in s.encode() for c in format(ch, '08b')], float)

flag = decode(W1[22])
x = encode(flag)
print('W1[22] stores 2*bits-1 of the trigger:', np.array_equal(W1[22], x*2 - 1))
h = np.maximum(W1 @ x + b1, 0)
print('h[22] =', h[22], ' h[23] =', h[23], ' output =', round(W2 @ h + b2, 3))
```

```
W1[22] stores 2*bits-1 of the trigger: True
h[22] = 2.0  h[23] = 0.0  output = 42.955
```

The `True` here is the clinching evidence, not just a sanity check — neuron 22's weight row is literally `2·bits − 1` of the decoded string, meaning the model stores the trigger template directly inside its own parameters.

For behavioral confirmation, I ran 2,000 random 49-character dispatches (lowercase letters, digits, underscore, same bit encoding) as a baseline against both candidate strings:

```
forged order (neuron-22 string): output 42.955, h[22]=2.0, h[23]=0.0
decoy string  (neuron-23 string): output  4.440, h[22]=0.0, h[23]=0.0
random dispatches:               min -9.70, mean 8.371, max 36.747
```

The forged order wakes the dormant neuron exactly as designed and clears every random dispatch in the sample, while the decoy string scores *below* the random mean — it would never be accepted even if submitted. I did not independently determine the model's exact acceptance threshold (it isn't recoverable from the file), but that doesn't affect which string is "the" trigger: only one of the two can ever activate its detector at all, which settles the question without needing the threshold.

## Root Cause

1. **The backdoor is a single dormant ReLU unit** with an engineered bias/output-weight pair, invisible under any normal input and overwhelming under the one it was built for.
2. **Decodable structure in weights is not evidence of a working exploit** — a second, mathematically unreachable trigger was planted specifically to look plausible to a solver who stops at the decode step. This is a deliberate trap in the challenge design, not a flaw in the backdoor technique itself.
3. **The {0,1} input encoding is load-bearing** for the entire analysis: it's the only encoding under which the ±1 weight rows resolve to readable text, and verifying that explicitly (rather than assuming a natural-seeming bipolar encoding) was necessary to trust any of the rest.

## Validation

**What was confirmed in testing:**
- Biases `b1[22]=-205.0` and `b1[23]=-208.0`, output weights `W2[22]=16.0` and `W2[23]=26.0`, are extreme outliers against the rest of the model's parameters.
- Decoding `W1[22]` and `W1[23]` as 49-byte ASCII strings (MSB-first, `{0,1}` encoding) yields two distinct, flag-shaped strings agreeing on 67.9% of bits.
- Neuron 22's activation threshold (205) is achievable given its positive-weight count (207); neuron 23's threshold (208) exceeds its achievable maximum (203) and can never fire.
- `W1[22]` is exactly `2·bits(flag) − 1`, confirmed by direct array comparison.
- Forward-pass output for the neuron-22 string (42.955) exceeds the full range observed across 2,000 random dispatches (max 36.747); the neuron-23 string's output (4.440) falls below the random mean.

**What was not confirmed in my own session, and must not be claimed:**
- The model's exact decision threshold for "genuine" is not recoverable from the file and was not determined.
- No submission to a scoring platform was recorded in this session.

## Conclusion

The chain here was: find the statistically implausible neurons, decode their weight rows as text, then prove — mathematically, not just by eyeballing plausibility — that only one of the two decoded strings could ever activate its detector. That last step is what separates this from guesswork: a backdoor trigger that's merely decodable text isn't the same as one that's actually reachable, and the simple positive-weight-count bound settled which was which with certainty rather than a coin flip between two equally flag-shaped candidates.

## Flag

```
CSCTF{09_the_ash_countersign_is_emberfall_4a19de}
```
