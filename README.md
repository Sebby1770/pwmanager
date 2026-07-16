# pwmanager 2.0

Local encrypted password manager with TOTP, security audit, CSV import, and a colorized CLI. No cloud, no accounts — your vault stays on your machine.

## Highlights

- **Strong KDF** — Argon2id by default (PBKDF2-HMAC-SHA256 fallback)
- **Authenticated encryption** — Fernet (AES-128-CBC + HMAC-SHA256) plus file-level HMAC
- **TOTP / 2FA** — store base32 secrets and generate live RFC 6238 codes
- **Security audit** — reused / weak / old passwords, missing TOTP hints, empty usernames
- **Password health score** — 0–100 score shown in the interactive menu
- **CSV import** — Bitwarden, Chrome, and generic column layouts
- **Password generator** — random passwords and diceware-style passphrases
- **Tags, search, history** — organize, find, and keep previous passwords on edit
- **Clipboard auto-clear** — optional copy with wipe after 20 seconds
- **Auto-lock** — locks after 5 minutes of inactivity
- **Encrypted export / import** — backups and machine moves
- **Modular package** — installable via pip; root `pwmanager.py` shim kept for old usage

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
2  view        view / list entries (grouped by tag)
3  search      search across all fields
4  edit        edit entry
5  delete      delete entry
6  generate    password or passphrase
7  export      encrypted backup
8  import      restore from backup
9  master      change master password
a  audit       security audit & health score
c  import-csv  import from Bitwarden/Chrome CSV
l  lock        lock vault
q  quit
```

The interactive menu shows your **password health score** (0–100) derived from audit findings.

### One-shot commands

```bash
python -m pwmanager add github
python -m pwmanager view github
python -m pwmanager search api --tag work
python -m pwmanager audit
python -m pwmanager import-csv export.csv --format auto --on-conflict skip
python -m pwmanager gen --length 32
python -m pwmanager gen --passphrase --words 6
python -m pwmanager --vault /path/to/other.json view
python -m pwmanager --version
```

### Security audit

```bash
python -m pwmanager audit
```

Reports (never prints actual passwords):

| Check | Description |
|-------|-------------|
| Reused passwords | Same password on multiple entries |
| Weak passwords | Estimated entropy &lt; 50 bits |
| Old passwords | Not updated in &gt; 365 days (or never) |
| Missing TOTP | Has a URL but no TOTP secret (hint) |
| Empty usernames | No username/email stored |

### CSV import

```bash
python -m pwmanager import-csv file.csv --format auto|bitwarden|chrome|generic
python -m pwmanager import-csv file.csv --on-conflict skip|overwrite
```

Supported columns:

| Format | Columns |
|--------|---------|
| **Bitwarden** | `name`, `login_username`, `login_password`, `login_uri`, `notes`, `login_totp` |
| **Chrome** | `name`, `url`, `username`, `password` |
| **Generic** | `name`/`title`, `username`, `password`, `url`, `notes`, `totp` |

Imported entries are tagged `imported` and with the detected format name.

## Vault format

Default path: `vault.json` in the current working directory (override with `--vault`).

```json
{
  "version": 2,
  "kdf": "argon2id",
  "salt": "<base64 salt>",
  "vault": "<Fernet token>",
  "hmac": "<sha256 hmac of salt+vault>"
}
```

Fully compatible with vaults created by the previous single-file `pwmanager.py`.

Each entry stores: `username`, `password`, `url`, `notes`, `tags`, `totp_secret`, `history`, `created_at`, `updated_at`.

## Package layout

```
pwmanager/
  __init__.py      # version
  __main__.py      # python -m pwmanager
  crypto.py        # salt, KDF, encrypt/decrypt, hmac
  generators.py    # password, passphrase, entropy
  totp.py          # RFC 6238
  models.py        # Entry dataclass
  vault.py         # storage + lock/unlock/save
  audit.py         # security audit + health score
  importers.py     # CSV import
  cli.py           # interactive menu + argparse
  colors.py        # ANSI helpers
  constants.py
pwmanager.py       # thin shim for python pwmanager.py
```

## Development

```bash
pip install -e ".[full,test]"
python -m pytest tests/ -q
```

CI runs pytest on Ubuntu with Python 3.11 and 3.12.

## Security notes

- The master password is **never** stored. Forget it and the vault is unrecoverable.
- Argon2id: time=3, memory=64 MiB, parallelism=4. PBKDF2 fallback: 600,000 iterations.
- Decrypted entries live in process memory while unlocked. Best-effort `secure_wipe` only zeroes mutable `bytearray` buffers.
- Auto-lock and clipboard auto-clear reduce exposure but are not a substitute for a clean machine.
- See [SECURITY.md](SECURITY.md) for the full threat model and recommendations.
- This is a learning/hobby tool. For high-stakes use, prefer Bitwarden / 1Password / KeePassXC.

## License

[MIT](LICENSE)
