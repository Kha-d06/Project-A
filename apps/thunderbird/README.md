# Qalaa for Thunderbird

A Thunderbird add-on (Thunderbird 128 or later) that checks each email you open
for scam and phishing signs: forged senders (the provider's SPF, DKIM and DMARC
results), a sender name that claims a brand, replies going to another domain,
link text that names a different site from the one the link opens, and pressure
wording. A badge appears on the message toolbar button; click it for details.

## Privacy

Nothing is checked until you enter your Qalaa server in the add-on's options
and allow access to it. For each email it sends the sender, reply address,
subject, text, links and authentication results to that server's
`POST /api/v1/email/check`, which answers at once and stores nothing.
Attachments are never sent. The add-on asks only for `messagesRead` and
`storage`, plus access to the one server you choose.

## Develop

    npm test        # node:test, no dependencies
    npm run pack    # dist/qalaa-thunderbird-<version>.xpi (needs zip)

To try it: Thunderbird → Add-ons and Themes → gear menu → Debug Add-ons →
Load Temporary Add-on → choose `manifest.json`.
