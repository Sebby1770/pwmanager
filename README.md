# Advanced Local Password Manager

A single-file, **local-first, zero-knowledge** Python password manager: strong
crypto, TOTP, an embedded-database backend, an audit log, encrypted backups, and
a colorized CLI. Everything stays on your machine; the master password is never
stored.

[![CI](https://github.com/Sebby1770/pwmanager/actions/workflows/ci.yml/badge.svg)](https://github.com/Sebby1770/pwmanager/actions/workflows/ci.yml)
![python](https://img.shields.io/badge/python-3.9%E2%80%933.13-blue)
![license](https://img.shields.io/badge/license-MIT-blue)

## What's new in 2.0

- 🔒 **Enforced integrity** — the file HMAC is now actually checked; a tampered
  vault is **refused** (`IntegrityError`), not silently opened. *(This was a
  real no-op bug before — see [CHANGELOG](CHANGELOG.md).)*
- 🗄️ **Embedded SQLite backend** — `--backend sqlite` keeps the encrypted blob
  in a one-row database instead of a JSON file. Same crypto, new container.
- 📝 **Audit log** — `--log-file audit.log` records *events* (unlock, add,
  delete, tamper, lockout). Never secrets. Written `0600`.
- 🔐 **Hardened permissions** — vaults, backups and logs are owner-only; a
  world-readable vault triggers a warning.
- 📦 **Packaging + tests + CI** — `pip install .`, a `pwmanager` command, a
  19-test suite, and CI across Python 3.9–3.13.

See [ARCHITECTURE.md](ARCHITECTURE.md) for how every backend concept maps to
the code, and [CLOUD_SYNC.md](CLOUD_SYNC.md) for the zero-knowledge sync roadmap.

## Highlights

- **Strong KDF** — Argon2id by default (PBKDF2-HMAC-SHA256, 600k iters, fallback)
- **Authenticated encryption** — Fernet (AES-128-CBC + HMAC-SHA256) per vault,
  plus an enforced HMAC over the file wrapper
- **Pluggable storage** — JSON file *or* embedded SQLite (`--backend`)
- **TOTP / 2FA** — store base32 secrets, generate live RFC 6238 codes
- **Generators** — random passwords (class controls, ambiguous-char filtering)
  and diceware-style passphrases, with a Shannon-entropy strength meter
- **Password history**, **tags**, **fuzzy search**, **clipboard auto-clear**,
  **auto-lock**, **failed-attempt lockout**
- **Encrypted export / import** and **change master password**

## Install

```bash
pip install .                 # core (cryptography only)
pip install ".[argon2]"       # + Argon2id (recommended)
pip install ".[argon2,clipboard]"   # + clipboard support
```

This installs a `pwmanager` command. You can also just run `python pwmanager.py`.

## Usage

```bash
pwmanager                          # interactive menu (JSON vault)
pwmanager --backend sqlite         # use the embedded SQLite backend
pwmanager --log-file audit.log     # keep an audit trail
pwmanager add github               # one-shot add
pwmanager gen --length 32          # generate a password (no vault needed)
pwmanager gen --passphrase --words 6
pwmanager --vault /path/other.db --backend sqlite view
pwmanager --help
```

## File format

The vault stores an encrypted payload — as JSON, or in a one-row SQLite table:

```json
{
  "version": 2,
  "kdf": "argon2id",
  "salt": "<base64 salt>",
  "vault": "<Fernet token — all entries>",
  "hmac": "<sha256 HMAC of salt+vault, derived-key keyed>"
}
```

The salt is in the clear (standard practice). `vault` is the Fernet-encrypted
JSON of all entries. `hmac` authenticates the wrapper and is **verified on
unlock** — a mismatch aborts with `IntegrityError`.

## Security notes

- The master password is **never** stored. Forget it and the vault is
  unrecoverable — by design.
- Argon2id parameters: time=3, memory=64 MiB, parallelism=4 (tune in source).
- The audit log records events only — never passwords or vault contents.
- Decrypted entries live in process memory while running; `secure_wipe` zeroes
  the key on lock, but Python strings are immutable so plaintext can't be
  guaranteed wiped.
- This is a learning/hobby tool. For high-stakes use, prefer Bitwarden /
  1Password / KeePassXC, which carry years of audit history.

## Development

```bash
pip install ".[argon2,dev]"
ruff check .
pytest        # 19 tests: crypto, both backends, integrity, TOTP, generators
```

See [CONTRIBUTING.md](CONTRIBUTING.md).

## License

MIT — see [LICENSE](LICENSE).
