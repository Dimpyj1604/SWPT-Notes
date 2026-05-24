# Blind SQL Injection

MSSQL-flavored blind SQLi with a captcha gate that also turns out to be injectable. The path goes from bypassing the captcha to stacked queries, enabling `xp_cmdshell`, writing files to the webroot, and reading arbitrary files on the box.

## Labs

- [Skills Assessment](./skills-assessment.md) — MSSQL time-based blind SQLi, captchaAnswer injection, xp_cmdshell RCE, webroot path discovery
