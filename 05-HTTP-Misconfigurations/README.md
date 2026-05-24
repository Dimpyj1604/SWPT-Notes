# HTTP Misconfigurations

Session-based attacks and web cache poisoning. The session labs build intuition for how PHP session state is populated and when that creates exploitable race conditions or logic gaps. The cache poisoning labs go much deeper — parameter cloaking (CVE-2020-28473), header injection, and chaining a poisoned cache hit to social-engineer an admin bot.

## Labs

- [Session Attacks](./session-attacks.md) — Weak session IDs, auth bypass via premature population, account takeover by skipping MFA phase, easy skills assessment
- [Cache Poisoning — Skills Assessment](./cache-poisoning-skills-assessment.md) — Python Bottle CVE-2020-28473 semicolon cloaking + Forwarded header injection to exfiltrate admin PIN
