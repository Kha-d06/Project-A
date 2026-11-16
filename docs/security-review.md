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
