# TLS / HTTPS Attacks

Cryptographic and protocol attacks against TLS — CBC and RSA padding oracles, SSL 3.0 /
downgrade weaknesses, memory disclosure, and configuration auditing.

## Techniques

- [CBC Padding Oracle](./padding-oracle.md) — PadBuster decrypt + forge, oracle ID,
  block-size pitfalls (AES-16 vs DES-8)
- [Bleichenbacher / ROBOT / DROWN](./bleichenbacher-drown.md) — RSA PKCS#1 v1.5 oracle,
  TLS-Breaker, pcap session decryption via keylog, query economics
- [POODLE, BEAST, Downgrade & SSL Stripping](./poodle-beast-downgrade.md) — SSL 3.0
  padding construction, CBC IV chaining, downgrade detection, HSTS
- [Weak Ciphers, Heartbleed & Config Testing](./weak-config-heartbleed.md) — FREAK/EXPORT,
  Heartbleed key recovery, openssl RSA decrypt, testssl.sh audit

## Labs

- [Skills Assessment](./skills-assessment.md) — Dual padding oracle: AES-128 cookie forge
  + DES token decryption (hand-rolled threaded oracle)
