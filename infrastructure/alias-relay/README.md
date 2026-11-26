# Email alias relay (self-hosted, no paid service)

Qalaa's disposable aliases are forwarded by **your own Postfix**. The Qalaa
API only answers "where does this alias go?"; it never receives message bodies
or headers. Postfix itself does handle each message in transit, so what you can
truthfully tell people is that content isn't stored or read, not that the relay
never sees mail (see "Privacy settings" below).

## 1. Qalaa API

```sh
SENTINEL_ALIAS_DOMAINS='["relay.example.org"]'
SENTINEL_ALIAS_RELAY_TOKEN=<32+ random characters>
```

People can also use domains they verified for site assessments
(Dashboard, Domains), once their MX points at this relay.

## 2. The lookup adapter, next to Postfix

```sh
SENTINEL_API_URL=https://qalaa.example.org SENTINEL_ALIAS_RELAY_TOKEN=<same token> \
  python -m app.relay.socketmap --listen 127.0.0.1:8945
```

## 3. Postfix `main.cf`

```
virtual_alias_domains = relay.example.org
virtual_alias_maps = socketmap:inet:127.0.0.1:8945:qalaa
# Forwarded mail must pass SPF at the destination: rewrite the envelope sender (SRS).
sender_canonical_maps = tcp:127.0.0.1:10001
sender_canonical_classes = envelope_sender
recipient_canonical_maps = tcp:127.0.0.1:10002
recipient_canonical_classes = envelope_recipient,header_recipient
```

Run [postsrsd](https://github.com/roehling/postsrsd) for the two SRS
lookups, and sign outgoing mail with DKIM (for example OpenDKIM) for the relay
domain. Add an MX record for `relay.example.org` pointing at this server.

Paused, deleted and unknown aliases return NOTFOUND, so Postfix refuses them
at SMTP time ("User unknown"); nothing is stored. If the API can't be reached,
the adapter answers TEMP and the sender's server retries later.

## Privacy settings

Postfix queues a message only until the next server accepts it, but by default
it logs the envelope sender and recipient of every message, and keeps a message
it can't deliver for days. Keep both short:

```
# main.cf: give up on undeliverable mail after a day, and don't keep bounces long.
maximal_queue_lifetime = 1d
bounce_queue_lifetime = 1d
```

Rotate the mail log daily and keep it for no more than 7 days (logrotate:
`daily`, `rotate 7`), or send Postfix's log to journald with
`MaxRetentionSec=7day`. Don't add `header_checks` or `always_bcc` rules that
copy or log message content.
