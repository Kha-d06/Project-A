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
