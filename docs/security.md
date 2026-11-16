# Security notes

What the code does to protect users and the service, the assumptions it makes,
and what is still missing. This is not a substitute for an independent review.

## Trust boundaries

1. **Browser to Caddy.** Everything a user submits is untrusted: URLs, message text, files and file names.
2. **Caddy to web to API.** Only Caddy is published. It replaces `X-Forwarded-For` with the real client address. The web gateway forwards only that value, and the API trusts it (`SENTINEL_TRUST_FORWARDED_FOR=true`) because it is not reachable any other way. If you deploy differently, keep this property or turn the flag off; otherwise clients can choose the address their rate limits are counted against.
   - *Not yet verified:* Caddy's replacement of the header was not exercised in a running container during development. The Next.js gateway behaviour was tested.
3. **Worker to the internet.** The worker contacts attacker-chosen hosts while tracing redirects. This is the main SSRF surface (see below).
4. **Threat feeds.** Feed content is parsed as data and validated (URLs re-parsed, hashes checked for format). It is never executed or rendered as HTML.

## Authentication and sessions

- **Passwords.** Hashed with Argon2id (`argon2-cffi` defaults), re-hashed when parameters change, minimum 10 characters.
- **Constant-time login.** Unknown emails are verified against a decoy hash, so response time does not reveal which accounts exist. The error message is the same in both cases.
- **Session tokens.** 256-bit random tokens in an `HttpOnly`, `SameSite=Lax` cookie (`Secure` in production). Only their SHA-256 digest is stored, and sessions expire after 7 days.
- **CSRF.** Every state-changing request from a session must carry the per-session CSRF token in a header, compared in constant time.
- **Password changes.** Changing the password revokes every other session.
- **Rate limits.** Registration is limited per IP. Login is limited per IP and per account, password checks per account, and scans per user or IP, with a lower limit for files. Limits are counted in Redis. If Redis is down, the API fails closed with a 503 rather than dropping protection.
- **Production secret.** `SENTINEL_ENVIRONMENT=production` refuses to start with the default secret.

## SSRF defences (`app/analyzers/safe_fetch.py`)

- **Schemes and ports.** Only `http` and `https`, and only ports 80, 443, 8080 and 8443.
- **Address checks.** The host is resolved and every returned address must be public. That rejects:
  - loopback, private, link-local (including `169.254.169.254`), CGNAT, multicast, reserved and unspecified addresses;
  - IPv6 addresses that embed IPv4 (mapped, 6to4 and Teredo), which are unwrapped and checked.
- **DNS rebinding.** The connection goes to the exact address that was validated, so a second DNS answer cannot redirect it. TLS still verifies the original hostname.
- **Redirects.** Followed manually, at most 6, with loop detection and a 20-second overall budget. Every hop is validated again.
- **No body reads.** Only the status line and headers are read; page bodies are never downloaded.

## File handling

- **Upload limits.** Uploads are streamed to disk with the 25 MB limit enforced while streaming. Empty and oversized files are refused, and partial files are removed.
- **Storage.** Samples are stored under random names in a `0700` directory with `0600` permissions, outside anything web-served. The client's file name is kept for display only.
- **No execution.** Nothing is extracted from archives. Entries are listed from the ZIP directory to detect bombs, traversal, executables and encryption.
- **Deletion.** Samples are deleted when the scan finishes, fails or is deleted. A retention sweep also fails any scan stuck for 15 minutes and removes its sample.
- **Worker containment.** The worker runs as an unprivileged user on a read-only filesystem, with all capabilities dropped, `no-new-privileges`, and memory and CPU caps. Tasks have hard time limits.
- **No third parties.** Files are never sent to a third party. VirusTotal is not integrated; if it is added, it must ask for consent first.

## Output handling

- **The API.** It only returns JSON, with `nosniff`, `X-Frame-Options: DENY`, `Cache-Control: no-store` and a `default-src 'none'` CSP.
- **The web app.** It sets a nonce-based CSP for scripts (`strict-dynamic`, no `unsafe-inline` for scripts), `frame-ancestors 'none'`, HSTS, `Referrer-Policy` and a restrictive `Permissions-Policy`. Styles allow `unsafe-inline` because React style attributes and charts need it.
- **Evidence.** Scan evidence (matched text, URLs) is rendered as plain text and never as links, so a malicious URL in a report is not clickable.
- **Redirect safety.** The post-login redirect only accepts same-site paths.

## Data minimisation

The API keeps only what each feature needs. Message text and file contents are
not retained. Users can switch history off, export everything and delete their
account (cascading to scans and the audit log). [The privacy page](../apps/web/src/app/(site)/privacy/page.tsx)
documents exactly what is stored and shared, and must be kept in step with the
code.

## API keys and metrics

- **API keys.** Personal keys are 256-bit random values prefixed `snt_`, shown once and stored only as SHA-256 digests. They are revocable and limited to ten per account. Keys authenticate scanning, history and lookups only. Account changes, key management, extension linking and all staff functions require a website session with its CSRF token, so a leaked key cannot take over or escalate an account. Disabling an account stops its keys working immediately.
- **Metrics.** The metrics endpoint is disabled unless `SENTINEL_METRICS_TOKEN` is set. Requests without the right bearer token get the same 404 as an unknown route.

## Mobile web app

- **Service worker.** It caches only the offline notice. Pages, scan results and API responses are never stored on the device.
- **Shared content.** Content shared into SENTINEL is placed in the form, not submitted. It travels in the address of a page on this site, so it is visible to this server's access logs if those are enabled.

## Known gaps

- Email verification, password reset and two-factor authentication are not implemented.
- There is no admin area, and the `role` column is not used for authorization yet.
- There is no encryption at rest beyond what the database volume provides.
- The scan worker shares the API's database credentials. A separate role with access only to `scan_jobs`, `findings` and the indicator tables would reduce the impact of a worker compromise.
- There has been no independent penetration test.
