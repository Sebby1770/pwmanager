# pwmanager 2.2

Local encrypted password manager with TOTP watch, HIBP breach checks, secure notes, vault profiles, favorites, fuzzy search, CSV import/export, and a colorized CLI. No cloud, no accounts — your vault stays on your machine.

## Highlights

- **Strong KDF** — Argon2id by default (PBKDF2-HMAC-SHA256 fallback)
- **Authenticated encryption** — Fernet (AES-128-CBC + HMAC-SHA256) plus file-level HMAC
- **TOTP / 2FA** — store base32 secrets, live RFC 6238 codes, `totp NAME --watch`, otpauth URI box (+ optional `qrcode` / `qrencode`)
- **HIBP k-anonymity** — optional `audit --hibp` checks passwords without sending them (only SHA-1 prefix)
- **Secure notes** — `add-note` / `add --note` for note-first entries (`kind: note`)
- **Password history** — `history NAME` lists previous passwords; restore with confirmation
- **Vault profiles** — `pwmanager --profile work` or `PWMANAGER_PROFILE=work`
- **Generate-on-add** — `add NAME --gen --length 20` non-interactive password generation
- **Fuzzy search** — exact substring matches plus ranked fuzzy suggestions
- **Favorites / pin** — pin important entries; listed first in view and search
- **Security audit** — reused / weak / old passwords, missing TOTP hints, empty usernames, optional HIBP
- **Vault stats** — entry counts, logins vs notes, tags, TOTP coverage, health score
- **CSV import** — Bitwarden, Chrome, and generic layouts with added/skipped/updated summary
- **Plain CSV export** — gated with YES / `--i-understand` (plaintext warning)
- **Password generator** — random passwords and diceware-style passphrases (1000+ word list)
- **Clipboard auto-clear** — optional copy with wipe; `--clipboard-timeout`
- **Auto-lock** — idle lock; `--lock-timeout` / default 5 minutes
- **Shell completions** — `pwmanager completions bash|zsh`
- **Encrypted export / import** — backups and machine moves

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

First run creates a master password (min 10 characters, strength check). Later runs unlock the vault. Menu:

```
1  add         add entry
2  view        view / list entries (favorites first, notes tagged)
3  search      search (exact + fuzzy)
4  edit        edit entry
5  delete      delete entry
6  generate    password or passphrase
7  export      encrypted backup
8  import      restore from backup
9  master      change master password
a  audit       security audit & health score
h  hibp        audit + HIBP breach check (network)
n  add-note    add secure note
y  history     password history browser
t  totp        show / watch TOTP code
c  import-csv  import from Bitwarden/Chrome CSV
e  export-csv  plaintext CSV export (dangerous)
p  pin         pin as favorite
u  unpin       remove favorite
s  stats       vault statistics
l  lock        lock vault
q  quit
```

The interactive menu shows your **password health score** (0–100) derived from audit findings.

### One-shot commands

```bash
python -m pwmanager add github
python -m pwmanager add github --gen --length 20 --username me@ex.com
python -m pwmanager add-note wifi --notes "SSID guest / pass …"
python -m pwmanager add memo --note --notes "secret text"
python -m pwmanager view github
python -m pwmanager search api --tag work
python -m pwmanager history github
python -m pwmanager totp github
python -m pwmanager totp github --watch
python -m pwmanager audit
python -m pwmanager audit --hibp
python -m pwmanager stats
python -m pwmanager import-csv export.csv --format auto --on-conflict skip
python -m pwmanager export-csv backup.csv --i-understand
python -m pwmanager gen --length 32
python -m pwmanager --vault /path/to/other.json view
python -m pwmanager --profile work stats
PWMANAGER_PROFILE=work python -m pwmanager
PWMANAGER_VAULT=~/secrets/vault.json python -m pwmanager
python -m pwmanager completions bash
python -m pwmanager --version
```

### HIBP breach check (optional network)

```bash
python -m pwmanager audit --hibp
```

Uses the [Have I Been Pwned](https://haveibeenpwned.com/API/v3#PwnedPasswords) **k-anonymity** range API:

1. Password is hashed with **SHA-1** locally.
2. Only the **first 5 hex characters** of the hash are sent to `api.pwnedpasswords.com`.
3. The full password and full hash **never** leave your machine.
4. Matching is done locally against the returned suffix list.
5. If offline, the report says **skipped (network unavailable)** — audit continues without failing hard.

Reports breached **entry names only** (never prints passwords). See [SECURITY.md](SECURITY.md).

### Secure notes

```bash
python -m pwmanager add-note passport
python -m pwmanager add ideas --note
```

Notes use `kind: "note"`. Username/password are optional; the **notes** field is primary. Listed with a `[note]` tag in view/search.

### Password history

```bash
python -m pwmanager history github
```

Shows previous passwords (from `entry.history`) with timestamps. Optionally restore one with confirmation (current password is pushed into history first).

### Live TOTP

```bash
python -m pwmanager totp github          # code + seconds left + progress bar + otpauth URI
python -m pwmanager totp github --watch  # refreshes every second until Ctrl+C
```

The otpauth URI can be turned into a QR with `qrencode` or the optional Python `qrcode` package if installed.

### Vault profiles

```bash
# Loads ~/.config/pwmanager/work.vault.json
python -m pwmanager --profile work

# Or via environment
export PWMANAGER_PROFILE=work
python -m pwmanager

# Optional path map: ~/.config/pwmanager/profiles.json
# { "work": "/secure/work.vault.json", "personal": "~/vaults/personal.json" }
```

Resolution order:

1. `--vault PATH`
2. `--profile NAME` or `PWMANAGER_PROFILE`
3. `PWMANAGER_VAULT`
4. `./vault.json` (cwd default)

### Security audit

```bash
python -m pwmanager audit
python -m pwmanager audit --hibp
```

Reports (never prints actual passwords):

| Check | Description |
|-------|-------------|
| Reused passwords | Same password on multiple entries |
| Weak passwords | Estimated entropy &lt; 50 bits |
| Old passwords | Not updated in &gt; 365 days (or never) |
| Missing TOTP | Has a URL but no TOTP secret (hint) |
| Empty usernames | No username/email on login entries |
| HIBP breached | Optional: password seen in known breaches |

### CSV import

```bash
python -m pwmanager import-csv file.csv --format auto|bitwarden|chrome|generic
python -m pwmanager import-csv file.csv --on-conflict skip|overwrite
```

After import, prints a summary: **N added, M overwritten, K skipped**.

### Plaintext CSV export (dangerous)

```bash
python -m pwmanager export-csv vault_export.csv --i-understand
```

Columns: `name`, `username`, `password`, `url`, `notes`, `tags`, `totp_secret`, `favorite`, `kind`.

**This file is unencrypted.** Prefer encrypted export for backups. Delete the CSV when finished.

## Vault format

Default path: `vault.json` in the current working directory (or profile path above).

```json
{
  "version": 2,
  "kdf": "argon2id",
  "salt": "<base64 salt>",
  "vault": "<Fernet token>",
  "hmac": "<sha256 hmac of salt+vault>"
}
```

Fully compatible with earlier vaults. Entry fields: `username`, `password`, `url`, `notes`, `tags`, `totp_secret`, `history`, `created_at`, `updated_at`, `favorite`, `kind` (`login` | `note`, default `login`).

## Package layout

```
pwmanager/
  __init__.py      # version 2.2.0
  __main__.py
  crypto.py
  generators.py
  data/eff_short.txt
  totp.py          # RFC 6238, watch mode, otpauth box
  models.py        # Entry (login | note)
  vault.py
  audit.py
  hibp.py          # HIBP k-anonymity client
  profiles.py      # multi-vault profiles
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
- HIBP is **optional** and uses k-anonymity (hash prefix only). See SECURITY.md.
- Argon2id: time=3, memory=64 MiB, parallelism=4. PBKDF2 fallback: 600,000 iterations.
- **Never** commit vault files or plaintext CSV exports to git.
- See [SECURITY.md](SECURITY.md) for the full threat model.
- This is a learning/hobby tool. For high-stakes use, prefer Bitwarden / 1Password / KeePassXC.

## License

[MIT](LICENSE)
