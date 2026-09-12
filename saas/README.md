# pwmanager SaaS API

Zero-knowledge companion to the CLI. The server stores **account metadata**
and **opaque vault ciphertext**. It never receives the master password, the
vault key, TOTP secrets, or card numbers.

## Run

```bash
python saas/server.py
# or
python -m saas
```

Open http://127.0.0.1:8787 — the process serves `web/` as well as `/api/*`.

## Environment

| Variable | Purpose |
|----------|---------|
| `PWMANAGER_DB` | SQLite path (default `pwmanager-saas.sqlite`) |
| `PWMANAGER_HOST` | Bind address (default `127.0.0.1`) |
| `PWMANAGER_PORT` | Bind port (default `8787`) |
| `PWMANAGER_PUBLIC_URL` | Public origin, used for CORS and Stripe redirects |
| `PWMANAGER_SECURE_COOKIES` | Set `1` to add `Secure` on the session cookie |
| `PWMANAGER_TRUST_PROXY` | Set `1` to honour `X-Forwarded-For` behind a reverse proxy |
| `PWMANAGER_CORS_ORIGINS` | Extra allowed origins, comma-separated |
| `PWMANAGER_STRIPE_SECRET` | Stripe secret key (`sk_test_…` locally) |
| `PWMANAGER_STRIPE_WEBHOOK_SECRET` | Webhook signing secret (`whsec_…`) |
| `PWMANAGER_STRIPE_PRICE_MONTHLY` | Price id for A$4 / month |
| `PWMANAGER_STRIPE_PRICE_YEARLY` | Price id for A$40 / year |

If the Stripe variables are missing, `POST /api/checkout` and
`POST /api/stripe/webhook` return **503** JSON explaining how to set them.
The server never pretends a customer is Pro.

Local webhook forwarding:

```bash
stripe listen --forward-to localhost:8787/api/stripe/webhook
```

Production must sit behind TLS. Session cookies are `HttpOnly; SameSite=Strict`.
IPs in the audit log are stored as HMAC hashes, not raw addresses.
