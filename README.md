# SWPT-Notes

Personal study notes compiled while working through advanced web application security concepts. These cover attack techniques, underlying mechanics, and methodology — written to reinforce my own understanding and share knowledge with the security community.

All content reflects publicly documented attack classes. No flags, no direct answers. If you're learning these topics, use these as a supplement — not a shortcut. Do the labs yourself.

---

## Modules

| # | Module | Techniques |
|---|--------|------------|
| 01 | [Parameter Logic](./01-Parameter-Logic/) | Type coercion, null safety bypass, business logic flaws |
| 02 | [Advanced .NET Deserialization](./02-Advanced-Deserialization-DotNet/) | BinaryFormatter, XmlSerializer, JSON gadgets, RCE |
| 03 | [Advanced XSS + CSRF](./03-Advanced-XSS-CSRF/) | CSRF privilege escalation, XSS via file upload, HTTPS exfil, SQLi chaining |
| 04 | [TLS / HTTPS Attacks](./04-TLS-Attacks/) | CBC padding oracle, AES-128 + DES/3DES, cookie forgery |
| 05 | [HTTP Misconfigurations](./05-HTTP-Misconfigurations/) | Session fixation, session puzzling, web cache poisoning, parameter cloaking |
| 06 | [Blind SQL Injection](./06-Blind-SQL-Injection/) | MSSQL time-based blind SQLi, xp_cmdshell RCE, NetNTLM hash capture |
| 07 | [HTTP Attacks](./07-HTTP-Attacks/) | CRLF injection, request smuggling (CL.TE, TE.TE, TE.CL, H2.CL), cookie theft |
| 08 | [Modern Web Exploitation](./08-Modern-Web-Exploitation/) | SSRF filter bypasses, DNS rebinding, second-order IDOR, second-order LFI |
| 09 | [Whitebox Pentesting](./09-Whitebox-Pentesting/) | JWT secret forging, eval injection, code review methodology |
| 10 | [Attacking Authentication Mechanisms](./10-Attacking-Authentication-Mechanisms/) | JWT (alg:none, secret crack, algorithm confusion, JWK forgery), OAuth token theft, SAML signature exclusion + wrapping |
| 11 | [NoSQL Injection](./11-NoSQL-Injection/) | MongoDB operator injection, $where JS injection, boolean oracle, blind token exfil |
| 12 | [Advanced Injections](./12-Advanced-Injections/) | wkhtmltopdf server-side XSS, LFI via file://, iframe SSRF, XPath blind boolean injection |
| 13 | [LDAP Injection](./13-LDAP-Injection/) | Blind LDAP filter injection, OR-clause attribute exfiltration, boolean oracle |
| 14 | [Advanced SQL Injection](./14-Advanced-SQL-Injection/) | PostgreSQL internals, psql/pgAdmin4, schema enumeration, advanced injection techniques |
| 15 | [Intro to Deserialization Attacks](./15-Intro-Deserialization-Attacks/) | PHP serialize format, Python Pickle protocol 0 opcodes, unsafe deserialization primitives |

---

## Setup Notes

Most labs use VPN. I run everything from Kali with the HTB VPN on `tun0`.

For any lab that needs a listener (Responder, netcat, HTTP server), make sure your tun0 IP is reachable from the target — test with a ping from the SQLi/SSRF before setting up the full chain.

---

## Disclaimer

All of this is for authorized lab environments only. Don't do any of this outside of CTFs, authorized engagements, or HTB/similar platforms.
