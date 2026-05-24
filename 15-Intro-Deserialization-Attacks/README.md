# Introduction to Deserialization Attacks

Covers serialization fundamentals across PHP and Python (Pickle), leading into deserialization vulnerabilities and exploitation techniques.

## Sections

- [Introduction to Serialization](./serialization-intro.md) — PHP and Python Pickle serialization format internals, protocol 0 opcodes
- [Object Injection (PHP)](./object-injection-php.md) — HTBank: modify serialized UserSettings to bypass @htbank.com email restriction, trigger XSS via unescaped name field
- [RCE via Magic Methods](./rce-magic-methods.md) — `__wakeup()` shell_exec injection, finding flag paths, curl timeout behavior, Laravel session quirks
- [PHAR Deserialization](./phar-deserialization.md) — arbitrary upload + phar:// path to file_exists() → metadata deserialized → RCE, namespace escape for \Phar
- [PHPGGC](./phpggc.md) — pre-built gadget chains for Laravel/Symfony/etc., direct import vs PHAR variant, chain version selection
- [Python Pickle Object Injection](./python-object-injection.md) — forge admin role cookie, module path must match server (util.auth.Session not __main__.Session)
- [Python Pickle RCE](./python-pickle-rce.md) — __reduce__ returning os.system, badword bypass via empty single quotes (n''c, /s''h)
- [Skills Assessment I — HTBrain](./skills-assessment-1.md) — Fernet-encrypted pickle cookie, known key re-derive, regex bypass by appending words after STOP opcode
- [Skills Assessment II — HTBear](./skills-assessment-2.md) — HMAC key in HTML comment, forge admin cookie, PHPGGC CodeIgniter4/RCE2 via /import, __destruct fires after response
