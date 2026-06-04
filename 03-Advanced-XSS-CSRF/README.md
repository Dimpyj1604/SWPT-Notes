# Advanced XSS + CSRF

Chaining CSRF with XSS, defeating modern CSRF/CORS/SameSite defences, turning XSS into
account takeover and an internal-network pivot, and bypassing input filters.

## Techniques

- [CSRF Techniques](./csrf-techniques.md) — CORS-misconfig token theft, null-origin
  sandboxed-iframe bypass, SameSite Strict/Lax evasion, method/content-type tricks
- [XSS Exploitation Chains](./xss-exploitation-chains.md) — HTTPS exfil listener, HttpOnly
  bypass (read the page not the cookie), ATO via token scrape, XSS→internal API/SQLi/CMDi
  pivots, same-origin chunked exfil
- [XSS Filter Bypasses](./xss-filter-bypass.md) — tag/attribute mutations
  (`<SCRIPT/SRC>`, `<svg onload>`), exploit-server delivery, exfil under HttpOnly+firewall

## Labs

- [Skills Assessment](./skills-assessment.md) — CSRF escalation → file upload XSS →
  HTTPS exfil → SQLi API
