# Attacking Authentication Mechanisms

JWT, OAuth, and SAML. Each has its own class of implementation mistakes, and this module runs through the main ones that actually show up in the wild.

For JWT: the attacks go from trivial (`alg:none`) to complex (algorithm confusion where the server accepts HS256 with the RSA public key as the HMAC secret). The signing-secret lab shows how weak secrets in HS256 tokens are just hashcat targets. The JWK lab shows what happens when a server trusts a key that comes embedded in the token itself.

For OAuth: redirect_uri validation is the critical gate. If the authorization server doesn't pin it to the registered callback, you can steal authorization codes by pointing them at an attacker-controlled server.

For SAML: the XML signature handling has two main failure modes — the SP doesn't require a signature at all (exclusion attack), or the verifier and the attribute parser look at different parts of the XML document (wrapping attack).

## Labs

- [JWT Attacks](./jwt-attacks.md) — alg:none, HS256 secret cracking, RS256→HS256 algorithm confusion, JWK header forgery, skills assessment
- [OAuth Attacks](./oauth-attacks.md) — redirect_uri token theft, CSRF via missing state parameter, reflected XSS on authorization endpoint
- [SAML Attacks](./saml-attacks.md) — lab flow walkthrough, signature exclusion, signature wrapping (XSW)
