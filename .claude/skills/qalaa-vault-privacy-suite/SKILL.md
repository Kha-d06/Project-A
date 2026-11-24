---
name: qalaa-vault-privacy-suite
description: Rules for Qalaa's password vault (passkeys, TOTP, sharing, emergency access), family controls, email scanning and privacy tools (SafePay, credential-read guardrails, fingerprint noise, aliases, clipboard TTL, data-broker checklist). Load when touching vault, sharing, family or privacy code in services/api, apps/web, apps/extension, apps/thunderbird or apps/desktop.
---

# Qalaa vault and privacy suite

## Existing pieces
- Vault crypto: `apps/web/src/lib/vault.ts` (shared by the extension), TOTP in
  `apps/web/src/lib/totp.ts`, sharing and emergency access in
  `services/api/app/api/vault_share.py`. The server only ever holds ciphertext.
- Family: groups in `services/api/app/api/groups.py`, policies in
  `app/groups_policy.py`; screen time in `apps/extension/src/lib/screentime.ts`.
- Email: on-device analysis in `apps/thunderbird/src/lib/analysis.js`, used by
  the add-on and `apps/desktop/src/engine/mail.ts` (IMAP, read-only inbox).

## Rules
- Vault keys never leave the client unencrypted; shares use the recipient's
  public key; emergency access waits out the owner's delay and can be denied.
- Family rules apply only to members who chose to follow them; parents see
  activity only from members who chose to share it; state these limits.
- Email: bodies, headers, addresses and attachments never leave the device.
  Only bare links (scheme, host, path) go to `POST /email/links`.
- Inbox account inventory (to build): parse sign-up and welcome emails locally;
  store the list on the device; deletion help is links and steps, not
  automation through a broker.
- SafePay (to build): launch the system browser with a fresh hardened profile
  (extensions off, DoH on) outside Qalaa; anti-screenshot flags on Qalaa's own
  sensitive views (`SetWindowDisplayAffinity`, `NSWindowSharingNone`,
  `FLAG_SECURE`). Never embed a browser engine.
- Credential guardrails (to build): watch reads of `~/.ssh`, `.env`, browser
  cookie stores by unexpected processes (fanotify on Linux; best effort
  elsewhere); alert first, block only with consent.
- Fingerprint noise, aliases, clipboard TTL and the data-broker checklist are
  opt-in and explained; no paid broker services.

## Tests
Crypto round-trips and wrong-key failures; policy combination tests; "only
these bytes leave the device" assertions for every network call.
