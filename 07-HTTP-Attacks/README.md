# HTTP Attacks

Two major families: CRLF injection and HTTP request smuggling. CRLF covers log poisoning to get RCE, response splitting for XSS, and SMTP injection for email redirect. Request smuggling covers every classic variant — CL.TE, TE.TE, TE.CL, H2.CL — plus two interesting edge cases involving a gunicorn WebSocket key bug and a cookie theft via partial-request hijack.

## Labs

- [CRLF Injection](./crlf-injection.md) — Log poisoning RCE, response splitting XSS, SMTP Bcc injection
- [Request Smuggling](./request-smuggling.md) — CL.TE, TE.TE (VTab trick), TE.CL (bare-CR WAF bypass), H2.CL (Armeria+Apache), cookie theft, gunicorn WebSocket bug, skills assessment chain
