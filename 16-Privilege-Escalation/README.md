# Privilege Escalation

Covers privilege escalation techniques in web applications including prototype pollution in Node.js.

## Sections

- [Prototype Pollution (Node.js)](./prototype-pollution-nodejs.md) — CVE-2018-16491 node.extend, pollute Object.prototype via __proto__ in login body, bypass isAdmin check → admin panel
- [Prototype Pollution → RCE](./prototype-pollution-rce.md) — lodash.merge 4.6.1, constructor.prototype bypass for __proto__ filter, pollute User.prototype.deviceIP → command injection via /ping
- [Client-Side Prototype Pollution → XSS → CSRF](./client-side-prototype-pollution.md) — jquery-deparam pollutes Object.prototype.onerror, jQuery 3.5.1 script-loader sets onerror attr, admin bot promotes htb-stdnt via fetch("/admin.php?promote=2"), flag in Admin Info
- [User Enumeration via Response Timing](./timing-user-enumeration.md) — /reset send_email() only fires for valid users (~1.5s), invalid skips it (~0.2s); xato wordlist + 0.8s threshold; valid username = frankie
- [Data Exfiltration via Response Timing](./timing-data-exfil.md) — /filecheck recursive os.walk before permission check; /home/USERNAME/ timing oracle; xato wordlist + 0.55s threshold; valid username = maggie
