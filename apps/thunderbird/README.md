# Qalaa for Thunderbird

A Thunderbird add-on (Thunderbird 128 or later) that checks each email you open,
on your computer, for scam and phishing signs: forged senders (the provider's SPF, DKIM and DMARC
results), a sender name that claims a brand, replies going to another domain,
link text that names a different site from the one the link opens, and pressure
wording. A badge appears on the message toolbar button; click it for details.

## Privacy

Every check runs inside Thunderbird. Nothing is checked until you enter your
Qalaa server in the add-on's options and allow access to it. The add-on then:

- downloads the public rule pack (`GET /api/v1/email/rules`, scam-wording
  patterns and brand domains) once a day; this sends nothing about your mail;
- checks the sender, reply address, authentication results, link text and
  wording on this computer (`src/lib/analysis.js`);
- sends only the message's links, cut down to scheme, host and path (no query
  string, fragment or user name), to `POST /api/v1/email/links` for a
  threat-list lookup. The server keeps nothing and leaves these requests out of
  its access log.

Message bodies, headers, subjects, addresses and attachments never leave the
device. The add-on asks only for `messagesRead` and `storage`, plus access to
the one server you choose.

## Develop

    npm test        # node:test, no dependencies
    npm run pack    # dist/qalaa-thunderbird-<version>.xpi (needs zip)

To try it: Thunderbird → Add-ons and Themes → gear menu → Debug Add-ons →
Load Temporary Add-on → choose `manifest.json`.
