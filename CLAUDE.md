# pwmanager — notes for Claude

A password manager in three parts that share a threat model but not code:

| Path | What it is |
|------|------------|
| `pwmanager/` | Python CLI vault. `cli.py` (commands), `vault.py` (file format, entry ops), `crypto.py` (KDF, AEAD, file HMAC), `importers.py` (Bitwarden / 1Password / Chrome CSV), `totp.py`, `hibp.py`, `audit.py`. Works fully offline with no account. |
| `saas/` | stdlib-only HTTP API + static server for the web vault. `server.py` (routes), `auth.py` (auth-key hashing, sessions, rate limits), `envelope.py` (validates ciphertext envelopes), `db.py` (SQLite), `stripeutil.py` (Checkout + webhooks), `schema.sql`. |
| `web/` | Static site. `web/saas/*.js` is the zero-knowledge browser vault (ES modules, no bundler); `web/generator.js` + `web/app.js` are the standalone generator page. |
| `tests/` | pytest suite (`tests/test_*.py`) and zero-dependency Node tests (`tests/js/*.mjs`). |

## Running things

```bash
pip install -r requirements-dev.txt        # the SessionStart hook does this in cloud sessions
python -m pwmanager                         # interactive CLI; vault.json in the cwd
python -m pwmanager --vault /tmp/x.vault.json add github --gen
python -m saas                              # API + web on http://127.0.0.1:8787 (Stripe optional)
python -m pytest -q                         # Python tests
node tests/js/run.mjs && node tests/js/saas_crypto.mjs   # JS tests
```

Stripe is disabled unless all four `PWMANAGER_STRIPE_*` env vars are set; the
API then returns 503 for checkout/webhook. Mark an account Pro in tests with
`UPDATE accounts SET plan='pro', plan_status='active'`.

## Crypto design (10 lines)

1. CLI: Argon2id (t=3, 64 MiB, p=4; PBKDF2-SHA256 600k fallback) over the master password + 16-byte salt → 32-byte key.
2. CLI: the whole entry set is one AES-256-GCM blob (random 96-bit nonce per save); legacy Fernet vaults still open and are upgraded on save.
3. CLI: an HMAC-SHA256 over version|kdf|cipher|salt|ciphertext (length-prefixed) binds the unencrypted header; a mismatch after a successful decrypt means tampering.
4. KDF parameters in the CLI are constants, never read from the file; only the KDF *name* is, and a wrong name just fails to decrypt.
5. Web: PBKDF2-SHA256, 600k iterations, salt = SHA-256(random 32-byte salt ‖ email) → 64 bytes.
6. Web: bytes 0–31 are `vaultKey` (AES-GCM, never leaves the browser); bytes 32–63 are `authKey`.
7. Web: the server stores only Argon2id(authKey) and the random salt; iterations are fixed client-side, so a server cannot downgrade them.
8. Web: vault = AES-256-GCM(vaultKey, JSON) with AAD `pwmanager-vault-v1`, uploaded as `{v, nonce, ct, kdf}`; `envelope.py` rejects anything plaintext-shaped.
9. Prelogin returns a deterministic HMAC-derived dummy salt for unknown emails so salts do not reveal which emails exist.
10. Nothing derived from the master password other than `authKey` may reach the server, its logs, or error messages — keep it that way.

## Conventions

- Never weaken a security check to make a test pass; add a test that proves the check instead.
- GitHub push protection rejects secret-shaped literals (`sk_test_…`, `whsec_…` of realistic length). Build fake secrets at runtime in tests.
- Keep the CLI usable without the SaaS or any network access.
- User-facing changes go in `CHANGELOG.md`; threat-model changes go in `SECURITY.md`.
