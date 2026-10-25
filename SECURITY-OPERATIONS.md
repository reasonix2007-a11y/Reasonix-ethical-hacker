# Security and tool operations

## Tenant scope and scan authorization

Full scans require an authenticated application session, explicit consent for each scan, and a server-side tenant scope. The limited Quick scan is available before login, but remains restricted to the server-side target allowlist and rate limit. Its guest panel displays the bounded Nmap/SQLmap commands, results, and finding evidence. The scanner does not require a DNS TXT record or a `/.well-known/reasonix-verify.txt` proof.

Copy `config.example.json` to the server-side `config.json` and set its `allowedTargets` array to the exact IPs or DNS names authorized for scanning. String domain entries include their subdomains on label boundaries (for example, `app.example.com` matches `example.com`, but `notexample.com` does not); IP entries match only that exact IP. To authorize a DNS name without its subdomains, use an object such as `{ "hostname": "example.com", "includeSubdomains": false }`. Do not add URL paths, wildcards, CIDR ranges, or targets supplied by a browser. Invalid JSON or invalid entries stop scanner startup. The local `config.json` is ignored by Git. For compatibility, `REASONIX_ALLOWED_DOMAINS` is used only when `config.json` is absent. Production requests are denied when the tenant or allowlist is absent.

The Quick profile uses its existing bounded probe set. Full and Deep profiles display a separate confirmation before starting; the scanner server also rejects these profiles unless the confirmation is explicitly included and records it in the audit log. Active checks remain bounded and non-extractive: this gate does not enable exploitation, access-control bypass, credential guessing, or data extraction. Do not take tenant IDs or allowed targets from browser input.

The browser-facing server signs the authenticated user (or a rate-limited anonymous Quick-scan identity), configured tenant, timestamp, and client IP when forwarding to the loopback-only scanner. `REASONIX_TRUSTED_PROXY_IPS` is optional and should contain only the direct IPs of trusted reverse proxies; otherwise the direct TCP peer is logged. Never trust arbitrary `X-Forwarded-For` values.

The browser cannot reliably prevent a recipient from copying, saving, or taking a screenshot of content already displayed to them. Scanner evidence is therefore bounded and redacted at collection/reporting; do not put credentials, tokens, private user records, or raw database contents in a report. Prefer a minimal proof (affected route, response status, and a sanitized excerpt or boolean observation) and an authenticated, short-lived report view when sharing is restricted.

## Audit log limitations

`scan-audit.log` entries are AES-256-GCM encrypted and form an HMAC-linked sequence. Startup verifies the chain and refuses to append to a corrupted or mixed-format log. Scan start is denied if the consent or scan-start audit record cannot be written.

This is **tamper-evident**, not immutable/WORM storage: a host administrator can still delete or truncate the file, and a local file cannot independently prove that its tail was not removed. For compliance-grade retention, forward audit events to an independently administered append-only/WORM service and retain external sequence/hash checkpoints.

`REASONIX_DATA_KEY` must be a private, stable, random 32-byte hexadecimal key. Back it up securely: losing it makes encrypted audit and account data unreadable. Do not commit `.env` or the key.

## Tool discovery and installation

- `npm run tools:check` checks the scanner's live tool inventory and writes a diagnostic `tool-readiness.json` snapshot.
- `npm run tools:install` asks before changing the system and tries only supported, explicit package-manager recipes.
- Add `--yes` only when package installation has already been approved, for example `node setup-tools.mjs --install --yes`.
- Missing/unsupported tools remain reported as missing; the installer does not fabricate availability or download arbitrary binaries. SQLmap/ZAP API services and credentials require separate configuration.
- On Windows development with Ubuntu WSL, `serve.mjs` resolves the current private WSL address at startup and maps configured loopback API URLs to that exact address. The API client accepts only loopback or that discovered WSL host. Do not expose either service on a public interface.
- SQLmap API and ZAP are opt-in in the Deep profile. SQLmap runs bounded injection checks without database extraction; ZAP is limited to same-origin crawling/passive analysis. The readiness check probes their authenticated local version endpoints and reports unhealthy services as blocked.

The application UI checks actual executable/API availability at runtime; it does not trust the saved JSON snapshot as a readiness override. In-process crawler/fuzzer components are reported as available without pretending they are separately installed binaries.

## Scan pipeline and partial failures

`serve.mjs` is the browser-facing server and proxies authorized requests to the loopback-only `scan-server.mjs`, which owns the scan pipeline. The scanner runs its built-in probes, same-origin crawler, selected local tools, then the optional heuristic and SQLmap/ZAP stages. A failure in an individual crawler resource or optional tool is reported in coverage and does not discard results from completed stages; cancellation still stops the scan.

SQLmap and ZAP are separate local services and are not launched by the app. Configure their loopback/approved WSL API URLs and required credentials, then confirm availability in the tool inventory before opting them into a Deep scan. SQLmap tasks are stopped/deleted on failure or cancellation and deleted after successful runs. ZAP reports per-seed failures and continues with remaining same-origin seeds; its integration runs spidering and passive analysis only. A service health check cannot guarantee that every later task will succeed.

## Local source and secret analysis

Uploaded source artifacts are analyzed locally with bounded built-in patterns in addition to optional static-analysis tools. Secret indicators include common provider token formats, private-key headers, and long literal assignments to credential-like names. Placeholder/example values are filtered, and finding evidence redacts matching secret values. Pattern matches are indicators, not proof that a credential is active; verify locally and rotate any confirmed exposed credential. The analyzer does not execute uploaded source.

## Local vulnerable demo

`vulnerable-site.mjs` binds only to `127.0.0.1`. Its admin, environment, API, and backup training routes return 404 unless `REASONIX_ENABLE_VULNERABLE_DEMO=true` is explicitly set. Even when enabled, all displayed credentials and records are synthetic. Never enable this training mode on a shared or production host.

## Report interpretation

Live progress reports the scanner's actual HTTP/TLS/DNS probe family or external tool command. Black-box remediation samples are labeled illustrative and are not represented as source code from the target. Only a source/repository scan can provide an actual source snippet, and suggested changes still require review.

An HTTP 200 response from a common administration path is reported only as an informational interface-discovery signal when the page has a distinctive administrative heading or login form; it does not prove missing authentication. Sensitive-file checks require content signatures appropriate to the requested file (for example, secret-like assignments in `.env` or SQL statements in a database dump). Matched response contents are not copied into the finding evidence. These checks reduce common catch-all-page false positives but do not replace manual validation or a benchmark against the target's known ground truth.

The HTTP baseline also reviews CSP directives and avoids reporting HSTS as missing on plain HTTP. It checks `Set-Cookie` attributes without storing cookie values and flags CORS only when an untrusted test `Origin` (random `.invalid` origin or `null`) is reflected together with credentialed access. CORS probes omit configured Cookie and Authorization headers; the finding is a risky-policy signal, not proof that sensitive data is readable. These are bounded GET/header observations; they do not submit forms or bypass authentication.

Common route checks use a random same-origin canary URL as a differential baseline to suppress likely soft-404/catch-all responses. The comparison uses bounded normalized response text and matching status codes; dynamic or personalized pages can still require manual review. Missing `Permissions-Policy`, COOP, or COEP alone does not create a finding because applicability depends on the application. CSP weaknesses are evaluated with directive fallback and nonce/hash exceptions, and are reported only for HTML or when explicitly present.

API checks require endpoint-specific response signatures: generic `/api/` JSON is not classified as exposure, and response bodies are not copied into findings. Public API documentation is informational; a recognizable environment endpoint is a stronger signal, not a claim that the returned values were validated as secrets.

HTTP probes are queued per origin with a maximum of four in flight and at least 200 ms between request starts (up to five starts per second per origin). The gate is cancellation-aware. This controls HTTP probe pressure; it is not a guarantee against every server-side rate limit, and other probe types have their own behavior.
