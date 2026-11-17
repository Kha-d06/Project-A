# Website security assessment

An account that an administrator has enabled can run read-only security checks
against **websites it has proven it owns**. It is a self-audit tool for site
owners, not a scanner for other people's sites.

## The rule that governs this feature

SENTINEL only ever probes a domain the account has verified it controls, and
**ownership is checked again at the start of every scan**. A domain that changes
hands, or whose verification record is removed, can no longer be scanned — the
assessment stops before making a single request to the site. Unverified domains
are refused outright.

Running active security tests against a site you do not own is unauthorised
access and illegal in most countries. This feature is built so it cannot be used
that way.

## Turning it on (the "subscription")

The feature is off for every account until an administrator turns it on, under
**Admin → Accounts → Site assessment**. The admin also sets two limits per
account: how many domains it can add (default 3) and how many assessments it can
run each month (default 20). There is no payment processor; access is granted by
an administrator.

## Verifying a domain

On **Dashboard → Site assessment**, the owner adds a domain and proves control
with either method (the same ones Google Search Console and certificate
authorities use):

- **DNS** — add a `TXT` record containing the token shown.
- **File** — serve the token at `https://<domain>/.well-known/sentinel-verification.txt`.

## What the assessment checks

All checks are **read-only**: plain GET requests to the owner's own site, spaced
out, reading only what any visitor can already see. Nothing is changed, no
crafted input is sent, and no attempt is made to break in.

- **TLS / HTTPS** — certificate expiry, and whether `http://` redirects to `https://`.
- **Security headers** — HSTS, Content-Security-Policy, X-Content-Type-Options, clickjacking protection, Referrer-Policy, and software-version disclosure.
- **Cookies** — Secure, HttpOnly and SameSite flags.
- **Exposed files and pages** — a short list of well-known sensitive locations (`/.git/config`, `/.env`, `/server-status`, `phpinfo`, directory listing). No brute forcing.
- **DNS and email** — SPF, DMARC (and its policy), and whether DNSSEC is on.

Each finding is listed with a plain explanation and how to fix it. The report
**never calls a site "secure"**: the best result is "no issues found by the
checks that ran", which it states is not a guarantee.

## Where it runs

Assessments run in the isolated scan worker, which has a restricted database role
(it cannot read users, sessions, API keys or audit logs). Outbound requests go
through the same SSRF-protected fetcher as the URL scanner: private and reserved
addresses are refused, so the feature cannot be pointed at internal services.

## Limits

- Only common configuration mistakes are checked, not application logic, not every vulnerability class.
- A clean result does not prove a site is secure.
- The feature does not perform active exploitation (no injection, no fuzzing, no credential testing).
