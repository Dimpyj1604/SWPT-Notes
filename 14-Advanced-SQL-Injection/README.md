# Advanced SQL Injection

PostgreSQL-specific injection techniques from a whitebox approach. Covers the database internals, advanced injection classes, and privilege escalation paths that are specific to PostgreSQL but conceptually transferable to other SQL variants.

## Labs

- [PostgreSQL Basics](./postgresql-basics.md) — psql/pgAdmin4 setup, schema enumeration, query patterns for common recon tasks
- [Decompiling Java JARs](./decompiling-java-jars.md) — Fernflower + JD-GUI, Spring Boot JAR structure, quick config extraction without full decompile
- [Searching for SQL Injection](./searching-for-strings.md) — grep RegEx patterns, parameterized vs concatenated queries, what blocks injection (hashing, encoding), second-order injection via stored email
- [Hunting for SQL Errors](./hunting-for-sql-errors.md) — enable SQL logging via postgresql.conf, tail log files, application_name identification
- [Common Character Bypasses](./common-character-bypasses.md) — space bypass (/**/), single-quote bypass ($$...$$), Matcher.matches() flaw, union extraction, comparative precomputation
- [Error-Based SQL Injection](./error-based-sql-injection.md) — CAST-to-INT technique, X-Forwarded-For IP spoof for verbose errors, regex bypass via --@domain, reset link reconstruction from md5(id:email:hash)
- [Second-Order SQL Injection](./second-order-sql-injection.md) — store payload via parameterized UPDATE, trigger via raw concat in separate endpoint, UNION column types, data flow tracing
