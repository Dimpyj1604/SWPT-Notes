# POODLE, BEAST, Downgrade & SSL Stripping

Three related CBC/protocol weaknesses plus the downgrade tricks that force a client onto
them.

## SSL 3.0 padding (POODLE)

SSL 3.0's CBC padding is **not deterministic**: only the *last* padding byte (the length)
is defined; every other padding byte is arbitrary and unchecked on decrypt. That
unchecked padding is what POODLE (2014) abuses as a byte-by-byte decryption oracle when an
attacker can both inject plaintext and observe whether a tampered record is accepted.

**Constructing valid SSL 3.0 padding** — given block size `B` and plaintext length `L`:

- Padding length `n = B - (L mod B)` bytes total.
- Last byte = `n - 1` (length of padding *excluding* itself).
- All other padding bytes = arbitrary (use `00`).

Example: plaintext `AABBCCDDEEFF` (6 bytes), AES-128 (`B = 16`) → need 10 padding bytes,
last byte = `09`, nine `00` before it:

```
AABBCCDDEEFF 00 00 00 00 00 00 00 00 00 09
= AABBCCDDEEFF00000000000000000009
```

## BEAST

CBC IV-chaining flaw in TLS 1.0 — the IV of record *n+1* is the last ciphertext block of
record *n*, so it is predictable. A chosen-plaintext attacker in the browser (applet/JS)
recovers session data block by block. Mitigated by TLS 1.1+ (explicit per-record IV) and
by RC4 historically (itself later broken — so just use TLS 1.2+/AEAD).

## Downgrade detection

A downgrade attack strips the client's offered version down to a weak one. In a capture,
compare the version the client *offered* to what the handshake actually *used*:

```bash
tshark -r downgrade.pcap -Y "tls.handshake.type == 1 || tls.handshake.type == 2"
#  Client Hello → Version: TLS 1.2 (0x0303)
#  Server Hello → Version: SSL 3.0  (0x0300)   ← forced down to vulnerable SSL3
```

ClientHello announcing 1.2 while the rest of the handshake runs at SSL 3.0 is the classic
fingerprint. `TLS_FALLBACK_SCSV` is the defence — signals "this is a fallback" so a
MITM-induced downgrade is rejected.

## SSL stripping & HSTS

SSL stripping (Moxie, 2009) MITMs the initial **HTTP→HTTPS** redirect, keeping the victim
on plaintext HTTP while the attacker talks HTTPS to the server. The defence is **HSTS** —
`Strict-Transport-Security` forces the browser to use HTTPS for `max-age` seconds:

```bash
curl -sk -I https://TARGET/ | grep -i strict
# Strict-Transport-Security: max-age=63072000;   (63072000 s = 2 years)
```

A long `max-age` + `includeSubDomains` + HSTS preload closes the first-visit gap.

## Mitigations (all of the above)

- Disable SSL 3.0 and TLS 1.0/1.1; prefer TLS 1.3, AEAD suites only.
- `TLS_FALLBACK_SCSV` to block forced downgrades.
- HSTS with a long `max-age`, `includeSubDomains`, and preload registration.
