# WeasyPrint target — SSRF via redirect bypass (CVE-2025-68616)

Fifth use case, third new vulnerability class (after deserialization RCE,
sandbox-escape RCE, and command injection): **SSRF**. Verified against NVD,
OSV.dev, and the GitHub Advisory Database before building.

## The bug

WeasyPrint renders attacker-influenced HTML to PDF — the common
"invoice/resume/report to PDF" pattern. An app protects its internal services
with its own guard, `secure_fetcher`, which blocks direct requests to a known
internal endpoint. The bug: `weasyprint.urls.default_url_fetcher` fetches via
`urllib.request.urlopen()`, which **follows HTTP redirects transparently** —
the app's guard only ever inspects the *initial* URL, never where a redirect
actually lands. Fixed in 68.0 (`allow_redirects=False`).

## The oracle — two fixed local services, no real external hosts needed

- **Canary** (`127.0.0.1:5000`) — "the internal service that must never be
  reached directly." Writes a marker file (`hit: <path>`) the instant it
  receives *any* request.
- **Redirector** (`127.0.0.1:8080`) — a generic open redirector (modeling the
  many that exist across the real web — URL shorteners, ad-tracking
  click-throughs): `GET /bounce?to=<url>` → `302` to `<url>`. Not
  attacker-configured ahead of time; the attacker's HTML supplies `to=`.

`secure_fetcher` blocks the canary's specific host:port — a realistic,
non-strawman guard (real SSRF filters commonly blocklist specific known
endpoints/ports rather than all of RFC1918, since the latter breaks
legitimate internal integrations) — but doesn't block the redirector's port.
Verified with three cases:

| Input | Guard's initial check | Canary reached? | Oracle fires? |
|---|---|---|---|
| `<img>` → redirector `?to=`canary | Passes (redirector isn't blocked) | **Yes**, via the 302 | **Yes** — `exit 134`, evidence `hit: /secret` |
| `<img>` → canary directly | **Blocked** | No | No — `exit 0` |
| Plain text, no external resources | N/A | No | No — `exit 0` |

## Files

- `Dockerfile`, `entry.py`, `config.yaml`, `harness_oracle.py` — the target.
- `artifacts/poc_redirect_bounce.html` — the verified exploit HTML.
- `artifacts/negative_control_*.html` — the two negative controls above.

## Plain-English verdict

If an app lets users submit HTML that gets converted to PDF (invoices,
resumes, reports) and tries to block WeasyPrint from reaching its own
internal services, an attacker can route around that block by pointing at
any open redirector (including ones on the public internet) that bounces to
the blocked target — no direct access to the internal service ever needed.
Fix: upgrade to WeasyPrint ≥ 68.0.
