# Validation Disparity

The core idea of these labs: there's a gap between what the schema/frontend *says* is valid, and what the backend *actually does* with the value. Schema validation catches bad format. It doesn't catch bad math.

---

## Lab 1 — Negative Amount

### App Overview

A shop with items that cost in-game currency ("cubes"). The purchase form enforces `amount >= 1` via a Yup schema. Standard stuff.

### Finding the Injection Point

Open Burp, buy an item normally, catch the POST request. The body looks like:

```json
{"itemId": 1, "amount": 1}
```

The frontend Yup schema has `.min(1)` on the amount field. That validation runs in the browser. The backend probably validates it too — but validation rejecting the value and the math engine rejecting the value are two different things.

If the backend does:
```javascript
user.balance -= item.price * amount;
```

...and passes a negative `amount`, the subtraction flips to addition.

### The Exploit

Bypass the frontend and POST directly:

```bash
curl -s http://TARGET/api/purchase \
  -H "Content-Type: application/json" \
  -H "Cookie: session=YOUR_SESSION" \
  -d '{"itemId": 1, "amount": -1000}'
```

Balance goes from ~100 to 100 + (item_price * 1000). Buy everything.

### Why It Works

Yup's `.min(1)` only rejects input *before* it reaches the business logic. Once you bypass the check (by sending the request directly), the database operation runs on the raw value. The backend developer added validation but forgot to add a guard in the actual purchase handler.

---

## Lab 2 — Float Amount + parseInt Name Trick

### App Overview

Same shop, harder version. Two bugs need to combine.

### Bug 1: Float Bypasses the Integer Check

The schema uses `.min(1)` expecting integers. `0.1` is less than 1, so it should fail. But:

- Some validation libraries check `value >= min` where both are floats internally
- If the backend casts to int before the check runs, `parseInt(0.1) = 0` which fails a different way
- The real question is: what does the server do with `0.1` when computing cost?

If the backend does: `cost = Math.floor(item.price * amount)` and `item.price = 10`, then:
- `Math.floor(10 * 0.1) = Math.floor(1.0) = 1` — fine
- But with `item.price = 5`: `Math.floor(5 * 0.1) = Math.floor(0.5) = 0` — free item

Test with small float values like `0.001` to drive cost to zero.

### Bug 2: parseInt on the Name Field

The order endpoint also takes a `name` field (probably for the order label or something similar). Somewhere in the backend, this value goes through `parseInt()`.

In JavaScript:
```javascript
parseInt("-1k")   // returns -1
parseInt("0x10")  // returns 16
parseInt("abc")   // returns NaN
```

`parseInt` reads left-to-right, stops at the first character that can't be part of a number. So `"-1k"` → `-1`.

If this parsed value ends up in the cost calculation (multiplier, discount, quantity), a negative result reverses the transaction.

### Combined Payload

```bash
curl -s http://TARGET/api/purchase \
  -H "Content-Type: application/json" \
  -H "Cookie: session=YOUR_SESSION" \
  -d '{"itemId": 1, "amount": 0.1, "name": "-1k"}'
```

The float drives cost toward zero; the parsed name value applies a negative multiplier. Net effect: account gets credited instead of debited.

### Recon Tips for This Bug Class

When looking at a purchase/order endpoint, check every field in the request — not just `amount` and `price`. Fields like `name`, `note`, `ref`, `label` might feed into calculations in non-obvious ways. Always look at the JS source or decompiled app to trace how each field is used.

---

## General Script — Fuzz Numeric Fields

```python
#!/usr/bin/env python3
import requests

TARGET = "http://TARGET"
SESSION = "your_session_cookie"
HEADERS = {"Content-Type": "application/json", "Cookie": f"session={SESSION}"}

test_values = [0, -1, -1000, 0.1, 0.001, -0.1, 9999999, -9999999]

for val in test_values:
    r = requests.post(f"{TARGET}/api/purchase",
                      json={"itemId": 1, "amount": val},
                      headers=HEADERS)
    print(f"amount={val} → {r.status_code} {r.text[:100]}")
```
