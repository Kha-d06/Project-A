# Email alias relay (self-hosted, no paid service)

Qalaa's disposable aliases are forwarded by **your own Postfix**. Qalaa only
answers "where does this alias go?"; it never receives message bodies or
headers.

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
