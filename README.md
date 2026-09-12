# pwmanager 3.1

Local encrypted password manager with TOTP watch, HIBP breach checks, rotation reminders, secure notes, vault profiles, favorites, fuzzy search, CSV/JSON import/export, `get --copy` scripting, `doctor` self-test, a colorized CLI, and an optional **zero-knowledge web vault**. The CLI still never requires an account. The website encrypts secrets in the browser; the operator cannot read them.

**Tagline:** a vault that never sees your secrets.

**New in 3.1:** hosted SaaS UI + `saas/` API for encrypted cloud sync (Pro), vault shortcuts, and a recovery kit. The CLI in 2.5 gained AES-256-GCM, rename, and undelete. The static [generator](web/generator.html) stays local. See [SECURITY.md](SECURITY.md) for the cloud threat model.

## SaaS (zero-knowledge web vault)

The browser derives **two** keys from your email + master password with
WebCrypto **PBKDF2-HMAC-SHA256** (600,000 iterations, SHA-256, 32-byte salt):

1. **vaultKey** — AES-GCM-256, encrypts vault JSON in the tab, never uploaded
2. **authKey** — sent to the API and hashed again (Argon2id). Used only to sign in

IndexedDB stores ciphertext. Pro sync uploads `{v, nonce, ct, kdf}` only.

```bash
python saas/server.py
# http://127.0.0.1:8787
```

| Variable | Purpose |
|----------|---------|
| `PWMANAGER_DB` | SQLite path (default `pwmanager-saas.sqlite`) |
| `PWMANAGER_HOST` / `PWMANAGER_PORT` | Bind address (default `127.0.0.1:8787`) |
| `PWMANAGER_PUBLIC_URL` | Public origin for CORS and Stripe redirects |
| `PWMANAGER_STRIPE_SECRET` | Stripe secret key (`sk_test_…` locally) |
| `PWMANAGER_STRIPE_WEBHOOK_SECRET` | Webhook signing secret (`whsec_…`) |
| `PWMANAGER_STRIPE_PRICE_MONTHLY` | Price id for A$4 / month |
| `PWMANAGER_STRIPE_PRICE_YEARLY` | Price id for A$40 / year |
| `PWMANAGER_SECURE_COOKIES` | `1` to add `Secure` on the session cookie |
| `PWMANAGER_TRUST_PROXY` | `1` to honour `X-Forwarded-For` |

If the Stripe variables are missing, `POST /api/checkout` returns **503 JSON**
and nobody is marked Pro. Local webhook forwarding:

```bash
stripe listen --forward-to localhost:8787/api/stripe/webhook
```

Put TLS in front of the process in production. Details: [saas/README.md](saas/README.md),
[web/README.md](web/README.md), legal pages under `web/*.html`.

**Plans:** Free = local vault + generator. Pro = encrypted multi-device sync,
versioned blobs (cap 20), 8&nbsp;MiB envelope. Forget the master password and
the vault is gone — that is stated at signup, in Terms, Privacy, and Security.

## Highlights

- **Zero-knowledge vault** — AES-GCM in the browser; server stores opaque blobs
- **Web generator** — [static page](web/generator.html) sharing the CLI's presets, wordlist and entropy maths; nothing leaves the browser except an optional HIBP prefix
- **Enforced integrity** — a vault edited outside pwmanager now refuses to unlock instead of silently opening
- **Owner-only vault files** — written `0600` atomically with `fsync`, never through the process umask
- **Honest passphrase strength** — scored by words, not characters (a 5-word phrase is ~55 bits, not ~150)
- **Strong KDF** — Argon2id by default (PBKDF2-HMAC-SHA256 fallback)
- **Authenticated encryption** — AES-256-GCM for new vaults; Fernet still unlocks older files. File-level HMAC covers version, KDF, cipher, salt, and ciphertext.
- **Rotation reminders** — per-entry `rotate_after_days` (default 90); `touch NAME` after you rotate
- **get / clipboard one-shot** — `get NAME --copy password|username|totp|url` for scripts
- **Integrity verify** — `verify` recomputes HMAC without listing secrets
- **doctor** — self-test (Argon2, clipboard, path, crypto + vault roundtrip)
- **Generator presets** — `gen --preset pin|wifi|apple|max`
- **Recent access** — `recent` shows last 10 viewed/copied entries
- **TOTP / 2FA** — store base32 secrets, live RFC 6238 codes, `totp NAME --watch`
- **HIBP k-anonymity** — optional `audit --hibp` (SHA-1 prefix only)
- **Secure notes** — `add-note` / `add --note` (`kind: note`)
- **Password history** — `history NAME` list / restore previous passwords
- **Vault profiles** — `pwmanager --profile work` or `PWMANAGER_PROFILE=work`
- **Fuzzy search** — exact matches plus ranked suggestions
- **Favorites / pin** — pin important entries
- **Security audit** — reused / weak / due-for-rotation passwords, duplicate usernames across domains, missing TOTP, empty usernames, optional HIBP
- **Plain CSV / JSON export** — gated with YES / `--i-understand` (plaintext warning)
- **Encrypted export / import** — backups and machine moves
- **Clipboard auto-clear** — optional copy with wipe; `--clipboard-timeout`
- **Auto-lock** — idle lock clears screen; `--lock-timeout` (default 5 minutes)
- **Shell completions** — `pwmanager completions bash|zsh`

## Install

```bash
# Recommended (Argon2 + clipboard)
pip install -e ".[full]"

# Core only (cryptography)
pip install -e .

# Dev / tests
pip install -e ".[full,test]"
```

Or with requirements:

```bash
pip install -r requirements.txt
```

`cryptography` is required. `argon2-cffi` and `pyperclip` are optional but recommended.

## Usage

### Interactive

```bash
python -m pwmanager
# or
python pwmanager.py
# or (after install)
pwmanager
```

First run creates a master password (min 10 characters, strength check). Later runs unlock the vault. Menu includes add/view/search/edit, audit, TOTP, notes, recent, touch, verify, doctor, and export options. Idle auto-lock **clears the screen** before re-prompting.

### One-shot commands

```bash
python -m pwmanager add github
python -m pwmanager add github --gen --length 20 --username me@ex.com
python -m pwmanager add wifi --gen --preset wifi
python -m pwmanager add-note wifi --notes "SSID guest / pass …"
python -m pwmanager view github
python -m pwmanager get github --copy password
python -m pwmanager get github --copy username
python -m pwmanager touch github          # mark rotated (updates updated_at only)
python -m pwmanager recent
python -m pwmanager verify
python -m pwmanager doctor
python -m pwmanager search api --tag work
python -m pwmanager history github
python -m pwmanager totp github --watch
python -m pwmanager audit
python -m pwmanager audit --hibp
python -m pwmanager stats
python -m pwmanager import-csv export.csv --format auto --on-conflict skip
python -m pwmanager export-csv backup.csv --i-understand
python -m pwmanager export-json backup.json --i-understand
python -m pwmanager gen --length 32
python -m pwmanager gen --preset wifi
python -m pwmanager gen --preset pin
python -m pwmanager gen --length 24 --no-symbols --avoid-ambiguous
python -m pwmanager gen --passphrase --words 6 --separator . --capitalize
python -m pwmanager gen --length 20 --count 10        # bulk rotation
python -m pwmanager --vault /path/to/other.json view
python -m pwmanager --profile work stats
PWMANAGER_PROFILE=work python -m pwmanager
PWMANAGER_VAULT=~/secrets/vault.json python -m pwmanager
python -m pwmanager completions bash
python -m pwmanager --version
```

### get — scripting / clipboard one-shot

```bash
# Copy password to clipboard and exit (stderr status; password not printed)
python -m pwmanager get github --copy password

# Print password to stdout (pipeline-friendly; be careful with shell history)
python -m pwmanager get github
```

Fields: `password`, `username`, `totp`, `url`. Viewing or copying updates `last_accessed` for `recent`.

### Automation unlock (`--password-env`) — insecure opt-in

By default the master password is **always prompted**. For CI/tests or tightly controlled automation only:

```bash
# Explicit flag required — do NOT set this habitually
export PWMANAGER_PASSWORD='…'   # process env is visible to other users/tools
python -m pwmanager --password-env --vault /tmp/test.vault.json verify
unset PWMANAGER_PASSWORD
```

**Never** document or store production master passwords in shell profiles, Docker Compose files, or CI secrets that end up in logs. Prefer interactive prompt or OS keychain wrappers outside this tool. See [SECURITY.md](SECURITY.md).

### Rotation reminders

- Default rotation window: **90 days** (`ROTATE_DEFAULT_DAYS`).
- Override per entry via `rotate_after_days` (stored on the entry; `None` = use default).
- Audit flags entries whose `updated_at` is older than their window.
- After you change a password elsewhere (or confirm it is still good), run:

```bash
python -m pwmanager touch github
```

### Generator presets

| Preset | Length | Notes |
|--------|--------|--------|
| `pin` | 6 | Digits only |
| `wifi` | 16 | Upper+lower+digits, no symbols, no ambiguous chars |
| `apple` | 20 | Strong mixed, no ambiguous |
| `max` | 64 | Full character classes |

```bash
python -m pwmanager gen --preset wifi
```

### Integrity verify

```bash
python -m pwmanager verify
```

Unlocks, recomputes the file HMAC, confirms ciphertext decrypts, prints **OK** or **FAIL** — does not list entries.

### doctor

```bash
python -m pwmanager doctor
```

Checks Argon2 availability (warn), clipboard (warn), vault parent directory writable, crypto roundtrip, and a temporary vault create/unlock/HMAC path. Exit `0` if critical checks pass.

### HIBP breach check (optional network)

```bash
python -m pwmanager audit --hibp
```

Uses the [Have I Been Pwned](https://haveibeenpwned.com/API/v3#PwnedPasswords) **k-anonymity** range API (only first 5 hex chars of SHA-1). Full password never leaves the machine. Offline → skipped, not a hard failure. See [SECURITY.md](SECURITY.md).

### Plaintext CSV / JSON export (dangerous)

```bash
python -m pwmanager export-csv vault_export.csv --i-understand
python -m pwmanager export-json vault_export.json --i-understand
```

Both write **passwords and TOTP secrets in cleartext**. Prefer encrypted `export` for backups. Delete plaintext files when finished. JSON shape:

```json
{
  "exported_at": 0.0,
  "version": 2,
  "entries": {
    "name": { "username": "…", "password": "…", "…": "…" }
  }
}
```

## Security audit

```bash
python -m pwmanager audit
python -m pwmanager audit --hibp
```

| Check | Description |
|-------|-------------|
| Reused passwords | Same password on multiple entries |
| Weak passwords | Estimated entropy &lt; 50 bits |
| Rotation due | Not updated within `rotate_after_days` (default 90) |
| Missing TOTP | Has a URL but no TOTP secret (hint) |
| Empty usernames | No username/email on login entries |
| Duplicate usernames | Same username across different domains/sites |
| HIBP breached | Optional: password seen in known breaches |

## Vault format

Default path: `vault.json` in the current working directory (or profile path).

```json
{
  "version": 3,
  "kdf": "argon2id",
  "cipher": "aes256gcm",
  "salt": "<base64 salt>",
  "vault": "<base64 nonce || ciphertext || tag>",
  "hmac": "<sha256 hmac over version+kdf+cipher+salt+vault>"
}
```

Since 2.4 the HMAC covers the `version` and `kdf` fields as well; 2.5 also
covers `cipher`. Editing those is detected rather than surfacing as a confusing
"wrong password". Older HMAC forms still open and are upgraded on the next
save. The file itself is written `0600`; run `pwmanager doctor` to check an
existing vault's permissions.

**Backward compatible** with earlier vaults. New entry fields default when missing:

- `rotate_after_days` — `null` → use global 90-day default
- `last_accessed` — `0` → never accessed via view/get/copy

Other fields: `username`, `password`, `url`, `notes`, `tags`, `totp_secret`, `history`, `created_at`, `updated_at`, `favorite`, `kind` (`login` \| `note`).

## Package layout

```
pwmanager/
  __init__.py      # version 3.2.0
  __main__.py
  crypto.py
  generators.py    # presets: pin|wifi|apple|max
  data/eff_short.txt
  totp.py
  models.py        # Entry + rotate_after_days, last_accessed
  vault.py         # touch, recent, verify, export_json
  audit.py         # rotation + domain-aware username reuse
  hibp.py
  profiles.py
  importers.py
  cli.py
  colors.py
  constants.py
scripts/
  build_web_wordlist.py   # regenerates web/wordlist.js from package data
web/                      # SaaS UI + generator (GitHub Pages / local server)
  index.html vault.html pricing.html generator.html
  saas.css saas/*.js
  privacy.html terms.html cookies.html security.html dpa.html acceptable-use.html
saas/                     # stdlib HTTP API (ciphertext only)
  server.py schema.sql
```

## Development

```bash
pip install -e ".[full,test]"
python -m pytest tests/ -q      # CLI + library + web parity
node tests/js/run.mjs           # browser generator core
```

Serve the full site (API + static files):

```bash
python saas/server.py          # http://127.0.0.1:8787
```

Static-only (generator and marketing, no cloud API):

```bash
python3 -m http.server 8137 --directory web
```

CI runs pytest on Ubuntu with Python 3.11 and 3.12, plus the Node generator
tests, and fails if `web/wordlist.js` has drifted from the packaged wordlist.
`web/` deploys to GitHub Pages on every push to `main` that touches it.

## Security notes

- The master password is **never** stored. Forget it and the vault is unrecoverable.
- **Do not** use `--password-env` / `PWMANAGER_PASSWORD` for production secrets.
- **Do not** commit `vault.json`, plaintext CSV/JSON exports, or real credentials.
- HIBP is optional and uses k-anonymity (hash prefix only). See SECURITY.md.
- Argon2id: time=3, memory=64 MiB, parallelism=4. PBKDF2 fallback: 600,000 iterations.
- The vault file is owner-only (`0600`) and written atomically with `fsync`.
- A vault that decrypts but fails its HMAC raises `VaultIntegrityError` rather than opening.
- The web generator never transmits or stores a password; see [web/README.md](web/README.md).
- The SaaS API never receives master passwords, vault keys, TOTP secrets, or card numbers.
- See [SECURITY.md](SECURITY.md) for the CLI and cloud threat models.
- This is a learning/hobby tool. For high-stakes use, prefer Bitwarden / 1Password / KeePassXC.

## License

[MIT](LICENSE)
