# LDAP Injection

LDAP injection is similar to SQL injection — user input lands in a filter expression that queries a directory service. The distinguishing feature is that blind LDAP injection relies on boolean side-channels (different response messages) rather than time delays, since LDAP doesn't have a sleep equivalent.

## Labs

- [Blind LDAP Exploitation](./blind-exploitation.md) — OR-clause injection to extract the admin description attribute char by char; charset selection, wildcard confirmation, and boolean oracle mechanics
