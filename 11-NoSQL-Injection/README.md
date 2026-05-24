# NoSQL Injection

Two flavors: MongoDB operator injection (`$ne`, `$gt`, `$regex`) and server-side JavaScript injection via `$where`. They're different enough that they need different payloads and different oracles, but the underlying cause is the same — user-controlled input reaches the query without sanitization.

## Labs

- [Server-Side JavaScript Injection (SSJI)](./ssji.md) — $where clause injection, boolean oracle via response text, char-by-char username brute-force
- [Skills Assessments](./skills-assessment.md) — MangoAPI: operator injection to extract admin token; MangoFile: $where boolean oracle + reset-token leak chain
