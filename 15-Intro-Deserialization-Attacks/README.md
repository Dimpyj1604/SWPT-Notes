# Introduction to Deserialization Attacks

Covers serialization fundamentals across PHP and Python (Pickle), leading into deserialization vulnerabilities and exploitation techniques.

## Sections

- [Introduction to Serialization](./serialization-intro.md) — PHP and Python Pickle serialization format internals, protocol 0 opcodes
- [Object Injection (PHP)](./object-injection-php.md) — HTBank: modify serialized UserSettings to bypass @htbank.com email restriction, trigger XSS via unescaped name field
- [RCE via Magic Methods](./rce-magic-methods.md) — `__wakeup()` shell_exec injection, finding flag paths, curl timeout behavior, Laravel session quirks
