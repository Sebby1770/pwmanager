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
| `PWMANAGER_WEBAUTHN_RP_ID` | Passkey relying-party id (default: host of `PWMANAGER_PUBLIC_URL`; `localhost` for IPs) |
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

## Passkeys (second factor)

Install the extra: `pip install "pwmanager[saas]"` (pulls in `webauthn`).

Once an account registers a passkey, `POST /api/login` with a correct
`auth_key` returns `{"mfa_required": true, "ceremony", "publicKey"}` and **no
session**. The client completes one of:

| Route | Body | Notes |
|-------|------|-------|
| `POST /api/login/webauthn` | `{ceremony, credential}` | WebAuthn assertion (JSON, base64url fields) |
| `POST /api/login/recovery` | `{ceremony, code}` | One of 10 one-time recovery codes |

Management (signed in; factor changes re-verify `auth_key`):

| Route | Body |
|-------|------|
| `POST /api/webauthn/register/options` | `{}` → `{ceremony, publicKey}` |
| `POST /api/webauthn/register/verify` | `{ceremony, credential, name, auth_key}` → recovery codes on the first passkey |
| `GET /api/webauthn/credentials` | — |
| `POST /api/webauthn/credentials/delete` | `{id, auth_key}` |
| `POST /api/webauthn/recovery-codes` | `{auth_key}` → a fresh set; old codes stop working |

Ceremonies are single-use and expire after 5 minutes. Browsers refuse IP
addresses as RP ids, so for local testing open **http://localhost:8787**
rather than 127.0.0.1. If `webauthn` is not installed, accounts with passkeys
cannot sign in to the cloud (fail closed); local vaults are unaffected.
