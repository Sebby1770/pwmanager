# pwmanager 2.3

Local encrypted password manager with TOTP watch, HIBP breach checks, rotation reminders, secure notes, vault profiles, favorites, fuzzy search, CSV/JSON import/export, `get --copy` scripting, `doctor` self-test, and a colorized CLI. No cloud, no accounts — your vault stays on your machine.

## Highlights

- **Strong KDF** — Argon2id by default (PBKDF2-HMAC-SHA256 fallback)
- **Authenticated encryption** — Fernet (AES-128-CBC + HMAC-SHA256) plus file-level HMAC
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
  "version": 2,
  "kdf": "argon2id",
  "salt": "<base64 salt>",
  "vault": "<Fernet token>",
  "hmac": "<sha256 hmac of salt+vault>"
}
```

**Backward compatible** with earlier vaults. New entry fields default when missing:

- `rotate_after_days` — `null` → use global 90-day default
- `last_accessed` — `0` → never accessed via view/get/copy

Other fields: `username`, `password`, `url`, `notes`, `tags`, `totp_secret`, `history`, `created_at`, `updated_at`, `favorite`, `kind` (`login` \| `note`).

## Package layout

```
pwmanager/
  __init__.py      # version 2.3.0
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
```

## Development

```bash
pip install -e ".[full,test]"
python -m pytest tests/ -q
```

CI runs pytest on Ubuntu with Python 3.11 and 3.12.

## Security notes

- The master password is **never** stored. Forget it and the vault is unrecoverable.
- **Do not** use `--password-env` / `PWMANAGER_PASSWORD` for production secrets.
- **Do not** commit `vault.json`, plaintext CSV/JSON exports, or real credentials.
- HIBP is optional and uses k-anonymity (hash prefix only). See SECURITY.md.
- Argon2id: time=3, memory=64 MiB, parallelism=4. PBKDF2 fallback: 600,000 iterations.
- See [SECURITY.md](SECURITY.md) for the full threat model.
- This is a learning/hobby tool. For high-stakes use, prefer Bitwarden / 1Password / KeePassXC.

## License

[MIT](LICENSE)
