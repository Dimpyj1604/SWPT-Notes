# CBC Padding Oracle — PadBuster Workflow

The skills assessment hand-rolls the oracle loop in Python. For a quick win against a
single short ciphertext (e.g. an encrypted session cookie) `padbuster` does the same
math with one command. Both rest on the same CBC identity:

```
Plaintext_i = AES_Decrypt(Ciphertext_i) XOR Ciphertext_{i-1}
```

If the server reveals *padding valid vs invalid* as two distinguishable responses, you
recover the intermediate (`AES_Decrypt`) of any block one byte at a time and from there
either **decrypt** unknown ciphertext or **encrypt** arbitrary plaintext.

## Identify the oracle

Two distinct response shapes for tampered ciphertext is the whole game:

- Tampered/garbage cookie → `500 Invalid Padding`
- Missing/empty cookie → `401 Unauthorized`
- Valid-padding cookie → normal app behaviour

Two *different* error pages for "bad padding" vs "not authorized" confirms the oracle.

## Decrypt an unknown cookie

```bash
padbuster http://TARGET/admin \
    "<URL-SAFE-CIPHERTEXT>" <BLOCKSIZE> -encoding 0 \
    -cookies "user=<CIPHERTEXT>" \
    -error 'Invalid Padding'
# → Decrypted value (ASCII): user=htb-stdnt
```

## Forge a chosen plaintext (privilege escalation)

Add `-plaintext`. PadBuster builds ciphertext that decrypts to whatever you specify:

```bash
padbuster http://TARGET/admin \
    "<CIPHERTEXT>" <BLOCKSIZE> -encoding 0 \
    -cookies "user=<CIPHERTEXT>" \
    -error 'Invalid Padding' -plaintext 'user=admin'
# → Encrypted value is: Ctq8zd%2Bc%2B...   (URL-encoded, drop straight into the cookie)
```

## Pitfalls

- **Block size is not always 16.** Decode the base64 cookie and divide its raw byte
  length by the number of blocks. 24 raw bytes = 3 × **8** (DES/3DES), not AES-16.
  PadBuster's default of 16 silently fails on an 8-byte cipher — every byte lookup misses.
- **Encoding flag matters.** `-encoding 0` = Base64, `1` = lower hex, `2` = upper hex.
- **Watch the real field name.** Login forms sometimes use `user`, not `username` — the
  cookie you attack is whatever the *app* sets, regardless of the login field.
- Manual/threaded Python (see `skills-assessment.md`) is the move when you must
  **encrypt** multi-block plaintext or parallelise 256 guesses/byte for speed.

## Mitigation

Authenticated encryption (AES-GCM / encrypt-then-MAC). Never expose padding validity
through status code, error text, or response timing.
