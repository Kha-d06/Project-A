# Security self-review

A structured review of the SENTINEL codebase by the team that wrote it, done
before the second round of features. **It is not an independent review.** It
catches what the authors can see; an outside reviewer should still test the
areas marked "recommended for external testing" before production use.

Scope: the API (`services/api`), web app (`apps/web`), browser extension
(`apps/extension`) and the deployment files.

## Findings fixed during this review

| # | Area | Finding | Fix |
| --- | --- | --- | --- |
| 1 | Scan workers | Workers parse untrusted files with third-party libraries (oletools, pefile, pyaxmlparser, Pillow, zxing-cpp) while holding the API's full database credentials. A parser exploit could read accounts, sessions and keys. | Workers now connect as `sentinel_worker`, which can only read and update scan jobs, write findings and read threat indicators (`infrastructure/database/worker-role.sql`). Verified on PostgreSQL: a scan completes, and reading `users` is refused. |
| 2 | Password reset | For an existing account the server sent the email before answering, so response time could reveal whether an address had an account. | The email is now sent after the response, so every request takes the same time. |
| 3 | Privacy | Audit events stored IP addresses indefinitely. | Purged after 180 days by the retention job. |
| 4 | Accounts | No way to recover a forgotten password and no second factor, so a reused password meant a lost account. | Email verification, single-use one-hour reset links that end every session, and authenticator-app two-step sign-in with ten single-use backup codes. The TOTP secret is encrypted at rest with a key derived from the application secret. |
| 6 | Scan workers (found in round 2) | Fix 1 limited the worker's *database session*, but the worker container still had the full database URL and the application secret in its environment, and ran feed syncs and cleanup itself. A parser exploit could have read them from the process environment. | Two workers now. The scan worker consumes only the `scans` queue, and its environment holds only the restricted database URL, its own secret (`WORKER_SECRET_KEY`) and no SMTP, bot or metrics credentials. A separate `tasks` worker, which never opens uploaded samples, handles feeds, retention, webhooks and bot and email replies. |
| 5 | API keys | Before this round, an API key could have reached any endpoint that accepted a signed-in user. | Keys are limited to scanning, history and lookups. Account changes, key management, extension linking and all staff functions require a website session plus its CSRF token. |

## Areas reviewed with no change needed

- **SSRF.** Every address is resolved and must be public. IPv6 addresses with an embedded IPv4 address (mapped, 6to4, Teredo) are unwrapped and checked. Connections are pinned to the validated address to block DNS rebinding, and every redirect is checked again. Ports are restricted and timeouts bounded. Page bodies are read in capped, time-limited chunks. Tests cover private and metadata addresses, rebinding answers, redirect loops, redirect limits and redirects to internal hosts.
- **Uploads.** Size limits are enforced while streaming. Samples get random storage names in owner-only directories, file types are detected from content, and file names are display-only. Archives are listed, never extracted. Images have a pixel limit against decompression bombs. Samples are deleted on every outcome, and stuck scans are cleaned up.
- **Sessions and CSRF.** Session tokens are random, stored as digests, and sent as HttpOnly, SameSite=Lax cookies. Every state change made with a session requires a per-session CSRF header, compared in constant time.
- **Passwords.** Hashed with Argon2id. Unknown emails are checked against a decoy hash so login time does not reveal account existence. Rate limits apply per IP and per account.
- **Two-step sign-in.** The challenge is HMAC-signed, expires after five minutes and carries no session by itself. Code attempts are rate-limited per user, and backup codes work once.
- **Output encoding.** React escapes all text. Scan evidence (matched text, URLs) is never rendered as a link. The extension builds all of its pages with `textContent`.
- **Content Security Policy.** Nonce-based script policy with `strict-dynamic`, `frame-ancestors 'none'`, and `worker-src 'self'` only. The API sends `default-src 'none'`.
- **Authorization.** Moderator and admin checks run on every request, on the server. Scans tied to an account are visible only to their owner, and anonymous scans only to whoever holds their random ID. Admin job monitoring never shows scan targets.
- **Extension.** It accepts messages only from its own pages (`sender.id` check) and declares no `externally_connectable`. Access to all pages is optional and requested at runtime. Credentials stay in extension-private storage, and access tokens are short-lived and revocable.
- **AI.** Only sanitised finding summaries are sent. The prompt is written with prompt injection in mind, links are stripped from the output, and the output is labelled and never changes the verdict.
- **Dependencies.** `pip-audit` and `npm audit` report no known vulnerabilities, and both run in CI.

## New surfaces in round 2, reviewed

- **Isolated page rendering.** Every browser request goes through the SSRF-checked fetcher; only GET and HEAD are allowed. Chromium's own sandbox is off inside the container (see security.md), so the container is the boundary.
- **Webhooks.** HTTPS domain names only. Delivery uses the same address checks as the fetcher, does not follow redirects, signs each body with HMAC-SHA256 plus a timestamp, and switches off after ten failures. Secrets are encrypted at rest and shown once.
- **Share links.** 256-bit tokens stored as digests, expiring (30 days by default) and revocable. Without the sharer's explicit choice, the address, evidence and details are left out.
- **Groups.** Invites only work for the invited address (and only once it is verified when email is on). A member's warning counts are visible to owners and admins only when that member opts in, and only as numbers.
- **Bots and scan-by-email.** Telegram is checked with its secret header, WhatsApp with the app-secret HMAC, and inbound email with a bearer token. Replies go only to the `From` address, never `Reply-To`, and mail marked `dmarc=fail` or `Auto-Submitted` is dropped, so SENTINEL cannot be used to mail bystanders. Chat IDs and addresses are deleted once the reply is sent.
- **Breach check.** Only the signed-in user's own address can be checked, so it cannot be used to look up other people. Password checks run in the browser against the Pwned Passwords range API (k-anonymity); passwords never reach SENTINEL.
- **Extension assistant.** Reads cookie names, never values, and sends only a summary to the server. It is drawn in a closed shadow root using text nodes only.

## Round 3 additions, reviewed

| # | Area | Finding | Resolution |
| --- | --- | --- | --- |
| 7 | QR decoder | The decoder set Pillow's process-wide pixel limit. A lower value set by one caller (a test) leaked into other image code. | Images are checked from their header against the limit before decoding; the global setting is left alone. |
| 8 | Web gateway | The gateway did not forward `PUT`, so saving a group block list failed. It was harmless, but it showed the gateway's method list was not covered by tests. | `PUT` is forwarded and the group block-list flow is covered end to end. |
| 9 | Check cache | The cache generation was first bumped before the database commit, so a concurrent request could cache old data for up to two minutes. | The bump now happens in an `after_commit` hook. The cache key is a digest of the address, never the address. |
| 10 | Desktop app | A slower, older screen render could replace a newer one. The ransomware alert could be hidden this way. | Renders carry a token, and only the newest is applied. The alert is held separately from status refreshes. |

**Also reviewed, with no change needed:**

- **Screenshot scans.** AI reading happens only with consent. The image is re-encoded with EXIF and other metadata removed and resized. The vision model's output is treated as text for SENTINEL's own rules, and its opinion is capped at low severity. QR codes are always checked locally.
- **Visual phishing references.** Only 64-bit hashes are stored, never screenshots. A brand's own domains never match their own reference.
- **Phone lookups and trends.** Phone lookups show verified reports and pending counts, not the reports themselves. Trends publish aggregates only, with counts below three hidden.
- **Web Push.** Payloads contain a title, a sentence and a site-relative link, never scanned content. The service worker opens only same-origin URLs on notification click. Dead subscriptions are deleted.
- **Weekly summaries and breach monitoring.** Both are opt-in. Breach monitoring only checks the user's own confirmed address and announces only new breaches.
- **Family block lists.** Admins can only suggest a list. Each member applies it in their own browser by their own choice. A family block has no "continue anyway", and it says which group set it.
- **Extension search labels and tracker blocking.** Both are opt-in. Search pages are read only for result links and only on the six listed search origins. Tracker blocking uses declarativeNetRequest and needs no host access.
- **Desktop system checks.** Wi-Fi, updates and 7-Zip listing all run through `execFile` with fixed arguments and timeouts, and never through a shell. Ransomware watch is detection only and never deletes or moves files.
- **Rate-limit multiplier.** It exists for load tests only, and production refuses to start with it set.
- **Android app.** It is a Trusted Web Activity with only the Internet permission. Asset links are served only when configured, and malformed fingerprints are dropped.
- **Accessibility.** Not a security item, but audited the same way: axe-core finds no serious or critical WCAG 2.1 AA violations on 72 page views (English and Arabic, light and dark).

## Round 4 additions, reviewed

- **Linked devices.**
  - Device tokens (`sdv_…`) are stored as digests.
  - A device token can only send heartbeats, fetch its own commands and report results.
  - Commands are refused unless the device itself allows remote scans and is online.
  - A folder scan can only name a folder the device offered, by id. Paths never reach the server.
  - Quarantine by hash checks the file's hash again before moving it.
  - The command history is capped at 50 per device. Removing a device deletes it and its commands.
- **Desktop security centre.**
  - Everything runs locally through `execFile` (no shell) or by reading `/proc`.
  - The "scan this program" action accepts only an id from the startup list just shown, never a path from the page.
  - Backup and restore folders come only from system dialogs.
- **Encrypted backups.**
  - Format: AES-256-GCM per 1 MiB record, scrypt key (N=2¹⁵, r=8).
  - Each record's sequence number is authenticated, and the closing record carries totals, so reordering, dropping, swapping or truncation is detected.
  - Restore writes only into a new or empty folder, rejects `..`, absolute, drive-letter and control-character paths, and never creates links.
  - Backups skip symbolic links.
  - The password is kept in the OS keychain through `safeStorage`, or only in memory.
- **Password vault.**
  - The master password never leaves the browser. PBKDF2-SHA256 (600,000 iterations) wraps a random AES-256-GCM vault key, which then exists only as a non-extractable `CryptoKey`.
  - Both encryptions bind the account id and their purpose as associated data.
  - Plaintext is padded to 1 KiB.
  - The API stores only base64 ciphertext, after checking sizes and a minimum of 310,000 iterations.
  - Saves are versioned with a row lock, so a stale tab cannot overwrite newer data.
  - Deleting needs the account password.
  - Auto-lock happens after 10 minutes idle, and copied secrets are cleared from the clipboard after 30 seconds.
  - Breach checks use the k-anonymity range API from the browser.
  - CSV export is exact (no spreadsheet-formula mangling), behind a warning.
  - Known limit: PBKDF2 is the strongest function WebCrypto offers. A memory-hard function (Argon2) would need a WebAssembly dependency.

- **WireGuard VPN.**
  - Device private keys are made in the browser and never sent. The API validates public keys as 32-byte base64.
  - The sync endpoint needs a token of at least 32 characters (compared in constant time) and is left out of the OpenAPI schema.
  - `sync.sh` writes only peers whose key and IPv4 address match strict patterns, so a compromised API response cannot add other directives. A test feeds it injection attempts.
  - The token is read from a 0600 header file, not passed on the command line.
  - Firewall rules isolate peers from each other, from the container, and from RFC 1918, CGNAT, link-local, loopback and multicast ranges. That keeps PostgreSQL and Redis out of reach.
  - IPv6 is routed into the tunnel and dropped to prevent leaks.
  - CI starts the real container and completes a handshake from the runner.

## Open items

| Risk | Item | Recommendation |
| --- | --- | --- |
| Medium | **Account-level login limit can lock a user out.** An attacker who knows an email can trigger the per-account limit (8 attempts in 15 minutes). | Accept for now, since it is temporary. Consider CAPTCHA or proof-of-work after repeated failures instead of a hard lock. |
| Medium | **`style-src 'unsafe-inline'`.** It is needed for React style attributes and charts. | Low impact while scripts stay nonce-locked; revisit if styles move to classes only. |
| Medium | **Proxy trust.** The API's per-client rate limits depend on Caddy replacing `X-Forwarded-For`. | Keep the API and web containers unexposed. Confirm the header replacement in the deployed environment. |
| Low | **2FA challenge reuse.** A challenge can be retried until it expires (5 minutes). Each attempt still needs a valid code and is rate-limited. | Optionally make challenges single-use with a server-side nonce list. |
| Low | **Report tracking tokens travel in URLs.** The referrer policy prevents leaking them to other sites. | Acceptable. |

**Recommended for external testing:**
- the SSRF fetcher, against cloud metadata and DNS-rebinding services;
- the file parsers, by fuzzing with malformed Office, PDF, PE and APK files;
- authentication flows, including session fixation and race conditions on single-use tokens;
- the browser extension's message handling.
