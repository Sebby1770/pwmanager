# Advanced Local Password Manager

A single-file Python password manager with strong crypto, TOTP, auto-lock, encrypted backups, and a colorized CLI. No external services, everything stays on your machine.

## Highlights

- **Strong KDF** — Argon2id by default (PBKDF2-HMAC-SHA256 fallback)
- **Authenticated encryption** — Fernet (AES-128-CBC + HMAC-SHA256) for entries, plus a separate HMAC over the file for tamper detection
- **TOTP / 2FA** — store base32 secrets and generate live RFC 6238 codes
- **Password generator** — random passwords (with character class controls and ambiguous-char filtering) and diceware-style passphrases
- **Strength meter** — Shannon entropy estimate with rating
- **Password history** — previous passwords kept per entry on edit (capped at 10)
- **Tags** — group entries by category in the list view
- **Search** — fuzzy match across name, username, URL, notes, and tags
- **Clipboard with auto-clear** — copies wipe themselves after 20 seconds
- **Auto-lock** — vault locks after 5 minutes of inactivity
- **Failed-attempt lockout** — exponential backoff, 5 tries max
- **Encrypted export / import** — for backups or moving between machines
- **Change master password** — re-encrypts the whole vault
- **Two modes** — interactive menu, or one-shot subcommands for scripting

## Install

```bash
pip install cryptography argon2-cffi pyperclip
```

`cryptography` is required. `argon2-cffi` and `pyperclip` are optional but recommended — the program degrades gracefully without them.

## Usage

### Interactive

```bash
python pwmanager.py
```

First run prompts you to create a master password (min 10 chars, with a strength check). Subsequent runs prompt to unlock. Then a menu:

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
l  lock        lock vault
q  quit
```

### One-shot

```bash
python pwmanager.py add github
python pwmanager.py view github
python pwmanager.py search
python pwmanager.py gen --length 32
python pwmanager.py gen --passphrase --words 6
python pwmanager.py --vault /path/to/other.json view
```

## File format

Vault is a JSON file with these fields:

```json
{
  "version": 2,
  "kdf": "argon2id",
  "salt": "<base64 salt>",
  "vault": "<Fernet token>",
  "hmac": "<sha256 hmac of salt+vault>"
}
```

The salt is in the clear (standard practice). The `vault` field contains the Fernet-encrypted JSON of all entries. The `hmac` is computed with the derived key, providing an extra integrity check on the file wrapper itself.

Each entry stores: `username`, `password`, `url`, `notes`, `tags`, `totp_secret`, `history`, `created_at`, `updated_at`.

## Security notes

- The master password is **never** stored. Forget it and the vault is unrecoverable — this is by design.
- Argon2id parameters are time=3, memory=64 MiB, parallelism=4. Bump them in the source if you want it slower/stronger.
- PBKDF2 fallback uses 600,000 iterations of HMAC-SHA256.
- Decrypted entries live in process memory while the program runs. Best-effort
  `secure_wipe` only zeroes mutable `bytearray` buffers; Python strings and
  bytes cannot be safely wiped from user-space code.
- Auto-lock and clipboard auto-clear reduce the window of exposure but are not a substitute for a clean machine.
- This is a learning/hobby tool. For high-stakes use, prefer Bitwarden / 1Password / KeePassXC, which have years of audit history and hardened memory handling.

## License

Do whatever you like.
