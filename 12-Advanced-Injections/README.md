# Advanced Injections

PDF generation vulnerabilities and XPath injection. The unifying theme is injection that goes through a non-obvious execution layer — a headless browser rendering HTML, or an XML query engine — rather than a traditional database.

## Labs

- [PDF Generation (wkhtmltopdf)](./pdf-wkhtmltopdf.md) — Server-side XSS via wkhtmltopdf, SSRF via iframe, file:// LFI, internal port discovery
- [XPath Blind Injection](./xpath-blind.md) — Injectra skills assessment: wkhtmltopdf + LFI reveals Apache vhost → iframe SSRF to internal app → XPath boolean-blind binary search for hidden order ID → flag
