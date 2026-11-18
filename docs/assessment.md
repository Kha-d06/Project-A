# Website security assessment

An account that an administrator has enabled can run read-only security checks
against **websites it has proven it owns**. It is a self-audit tool for site
owners, not a scanner for other people's sites.

## The rule that governs this feature

Qalaa only ever probes a domain the account has verified it controls, and
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
- **File** — serve the token at `https://<domain>/.well-known/qalaa-verification.txt`.

## What the assessment checks

The standard checks are **read-only**: plain GET requests to the owner's own site, spaced
out, reading only what any visitor can already see. Nothing is changed, no
crafted input is sent, and no attempt is made to break in.

- **TLS / HTTPS** — certificate expiry, and whether `http://` redirects to `https://`.
- **Security headers** — HSTS, Content-Security-Policy, X-Content-Type-Options, clickjacking protection, Referrer-Policy, and software-version disclosure.
- **Cookies** — Secure, HttpOnly and SameSite flags.
- **Exposed files and pages** — a short list of well-known sensitive locations (`/.git/config`, `/.env`, `/server-status`, `phpinfo`, directory listing). No brute forcing.
- **DNS and email** — SPF, DMARC (and its policy), and whether DNSSEC is on.

### Optional light active tests

Off by default. The owner can tick **Include light active tests** for one scan,
and must also tick a second box confirming *"I own this site and I authorise
Qalaa to send these test requests to it now"*. The API refuses
(`422 confirmation_required`) unless both are sent, and the choice is recorded in
the audit log (`assessment_started_active`). Scheduled scans never include them.

They add three GET requests to the homepage:

| Test | What is sent | Finding when |
| --- | --- | --- |
| Reflected XSS | a random marker containing `"'<x>` in `q`, `s` and `search` | the marker appears in the page **unescaped** (high) |
| Open redirect | `https://sentinel-redirect-test.invalid/` in `next`, `url`, `redirect`, `return`, `returnUrl`, `continue` | the response redirects there (medium) |
| Database errors | a single `'` in `id` and `q` | the page shows a known SQL error message (high) |

The markers are harmless text (no script, no SQL payloads, no `UNION`, nothing
submitted, no logins tried), and nothing on the site is changed. The redirect
target uses the reserved `.invalid` domain, so it can never resolve.

## Scheduled re-assessments and regression emails

Each verified domain can repeat automatically **every week** or **every month**
(`PATCH /assess/domains/{id}` with `{"schedule": "weekly"}`). An hourly job
starts the ones that are due. Scheduled runs follow the same rules as manual
ones: ownership is re-verified first, they count towards the monthly limit, and
they are skipped (not queued) when the account is over its limit or the feature
has been turned off.

When an assessment finishes it is compared with the previous completed one for
that domain. If **new issues** appeared or the **overall result got worse**, the
owner gets a plain-text email listing what changed, with a link to the report.
If a scheduled run could not confirm ownership, the owner is told that too.

## Report and PDF

Every completed assessment has a printable report at
`/dashboard/assessment/report/<id>`. **Print or save as PDF** uses the browser's
print dialog (navigation and buttons are hidden when printing), so no file is
generated or stored on the server.

Each finding is listed with a plain explanation and how to fix it. The report
**never calls a site "secure"**: the best result is "no issues found by the
checks that ran", which it states is not a guarantee.

## Where it runs

Assessments run in the isolated scan worker (Celery queue `scans`), which has a restricted database role
(it cannot read users, sessions, API keys or audit logs). Outbound requests go
through the same SSRF-protected fetcher as the URL scanner: private and reserved
addresses are refused, so the feature cannot be pointed at internal services.

## Limits

- Only common configuration mistakes are checked, not application logic, not every vulnerability class.
- A clean result does not prove a site is secure.
- The feature does not perform exploitation: no injection payloads, no fuzzing, no credential testing. The optional active tests only look for signs of three common weaknesses, using harmless markers.
