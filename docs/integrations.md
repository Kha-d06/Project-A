# Integrations: bots, scan by email, webhooks and the bulk API

All of these are optional and off until configured. The integrations list on the
home page (`GET /api/v1/system/providers`) shows which are active.

## Telegram bot

1. Create a bot with @BotFather and copy its token.
2. Pick a random secret: `python -c "import secrets; print(secrets.token_urlsafe(32))"`.
3. Set `SENTINEL_TELEGRAM_BOT_TOKEN` and `SENTINEL_TELEGRAM_WEBHOOK_SECRET`, then restart.
4. Register the webhook once:
   ```bash
   curl -sS "https://api.telegram.org/bot$TOKEN/setWebhook" \
     -d url="https://your-sentinel.example/api/v1/bots/telegram" \
     -d secret_token="$SECRET"
   ```

People then send the bot a link or paste a message. A lone link gets a link scan; anything else gets a message scan (English and Arabic). The task worker replies with the verdict, up to three main findings and a link to the full report. Each chat is limited to 30 scans an hour.

## WhatsApp (Cloud API)

1. In Meta for Developers, create an app with the WhatsApp product, and note the phone number ID, a permanent access token and the app secret.
2. Set `SENTINEL_WHATSAPP_ACCESS_TOKEN`, `SENTINEL_WHATSAPP_PHONE_NUMBER_ID`, `SENTINEL_WHATSAPP_APP_SECRET` and a random `SENTINEL_WHATSAPP_VERIFY_TOKEN`.
3. Configure the webhook URL `https://your-sentinel.example/api/v1/bots/whatsapp` with that verify token, and subscribe to `messages`.

Every delivery is checked against the `X-Hub-Signature-256` HMAC. Meta's rules on business-initiated messages apply: SENTINEL only ever replies to messages people send it.

## Scan by email (for example check@your-domain)

Configure your mail provider's inbound routing to POST the raw message (`message/rfc822`) to `https://your-sentinel.example/api/v1/inbound/email` with `Authorization: Bearer $SENTINEL_INBOUND_EMAIL_TOKEN`. This works with Mailgun Routes ("store and notify" with the raw MIME), Postmark inbound (raw), AWS SES via SNS, or a Cloudflare Email Worker that forwards `message.raw`.

- The text and subject get a message scan, and up to three attachments get file scans.
- The reply goes to the `From` address only.
- Messages that fail DMARC (as reported in `Authentication-Results`), automatic replies, and mail from SENTINEL's own address are ignored.
- Each sender is limited to 20 messages an hour.
- Set `SENTINEL_INBOUND_EMAIL_ADDRESS` to show the address to users.

## Webhooks

Signed-in users add up to five HTTPS endpoints under Settings → Webhooks, choosing `scan.dangerous` (known malicious or suspicious results) and/or `scan.completed`. Each delivery is a JSON POST:

```
X-Sentinel-Event: scan.dangerous
X-Sentinel-Timestamp: 1763300000
X-Sentinel-Signature: sha256=<hex HMAC-SHA256(secret, timestamp + "." + body)>
```

Verify the signature, reject timestamps older than five minutes, and answer 2xx. Endpoints that fail ten times in a row are switched off. Delivery refuses private and internal addresses.

## Bulk link scans

`POST /api/v1/scans/bulk` with `{"urls": [...]}` (up to 50, duplicates removed) and an API key (`Authorization: Bearer snt_…`). The response lists the queued scans; fetch each one with `GET /api/v1/scans/{id}`, or use a webhook. Ten bulk calls an hour per account.
