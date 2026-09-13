# Nokia 215 CloudPhone

## Local
1. Create a Neon PostgreSQL database and copy `.env.example` to `.env`.
2. Set all four required secrets: `DATABASE_URL`, a private four-digit `PHONE_PIN`, `TELEGRAM_BOT_TOKEN`, and a random `TELEGRAM_WEBHOOK_SECRET`.
3. Run `npm ci && npm start`.
4. Configure Telegram with `scripts/setup-webhook.sh https://your-domain.example` (it sends `secret_token` and limits updates to messages).

The phone asks for the PIN on every page launch. Tokens remain in memory and are discarded on page hide. Each private Telegram user is a separate database chat; incoming text and photos are stored for 30 days. Photos are only proxied from Telegram to the phone, with a 5 MB limit. Outgoing delivery uses a database client-id reservation: failed sends are marked failed and are never automatically replayed because a network timeout cannot prove Telegram did not accept a message.

## Render + Neon
Create a Render Web Service from this repository. `render.yaml` uses Node 22, `npm ci`, and the free web service. Add the variables in `.env.example` in Render's environment settings, using the Neon pooled TLS URL. Render's free instance sleeps; Neon is the durable store. Set the webhook only after Render has a stable HTTPS URL.

## Health checks
`GET /health` is a real health request. If desired, run `scripts/keepalive.sh https://your-domain.example/health` from a personal machine or external cron. This does not simulate user activity, guarantee uptime, or bypass Render limits; free cron services and Render may impose their own quotas.

## Security and retention
Never commit `.env` or bot tokens. Rotate the webhook secret if exposed. Database cleanup runs hourly and removes messages and processed-update records older than 30 days; cascading foreign keys remove empty chats only when their messages are deleted. No live Telegram deployment is tested by the local test command.
