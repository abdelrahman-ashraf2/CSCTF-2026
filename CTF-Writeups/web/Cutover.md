# Cutover

**Category:** Web

## Solution

1. I compared the batch register, manifests, and journal. Batch `MRN-9F6EA9` declared `35,300,000`, but its instructions summed to `38,300,000`. That drain explained the projected liquidity-floor breach.
2. I used a crafted `flatted` manifest whose `basis` reference resolved to the live `Array.prototype`. The engine merged the manifest's `RECALL: true` hint onto it. Since the permission check read `grants["RECALL"]` from arrays, the inherited value bypassed the supervisor restriction.
3. The recall exceeded the gateway's `23,900,000` cap. I sent the amount as the JSON number `3.83e7`: the gateway deferred screening, while the engine parsed the same value as `38300000`.
4. The held recall disclosed `unlock_input: "cutover|MRN-9F6EA9|38300000"`. I calculated the expected unlock value:

   ```python
   import hashlib

   unlock = hashlib.sha256(b'cutover|MRN-9F6EA9|38300000').hexdigest()
   print(unlock)
   ```

5. I resubmitted the recall with that hash and read the flag from the receipt's `authorization` field.

## Flag

```text
CSCTF{Man5JZVdDaE8XJAtT0XVlaPD}
```

> **Note:** This preserves my historical exploit notes; the service source and live instance are absent, so I could not replay the chain. The recorded flag is specific to that instance.
