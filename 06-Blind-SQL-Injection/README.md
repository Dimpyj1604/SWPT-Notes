# Blind SQL Injection

Extracting data and achieving RCE when the query result never appears in the response —
boolean and time-based oracles, MSSQL schema enumeration, stacked-query escalation to
`xp_cmdshell`, and NetNTLM capture via `xp_dirtree`.

## Techniques

- [Blind Oracle Types](./blind-oracle-types.md) — boolean vs time-based, bit-by-bit and
  binary-search extraction, reducing request count
- [MSSQL Techniques](./mssql-techniques.md) — `WAITFOR DELAY`, `OFFSET/FETCH` enumeration,
  stacked queries, enabling `xp_cmdshell`, file read/write, `xp_dirtree` NetNTLM capture

## Labs

- [Skills Assessment](./skills-assessment.md) — MSSQL time-based blind SQLi, captchaAnswer
  injection, xp_cmdshell RCE, webroot path discovery
