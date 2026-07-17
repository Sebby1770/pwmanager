# Security Policy

## Threat model

**pwmanager** is a **local, offline-first** password manager. It is designed to protect
stored credentials against:

- Casual inspection of the vault file on disk
- Offline brute-force of a **strong** master password (via Argon2id / high-iteration PBKDF2)
- Simple tampering of the vault wrapper (HMAC over salt + ciphertext; Fernet authenticated encryption of the payload)

It is **not** designed to resist:

- An attacker with unrestricted access to your unlocked session (decrypted entries live in process memory)
- Malware, keyloggers, or a compromised OS
- Physical memory forensics / cold-boot attacks
- Side-channel attacks against the Python runtime
- Cloud sync, multi-device compromise, or phishing of the master password
- Advanced adversaries who can modify the program while you use it

**Bottom line:** treat this as a solid personal/hobby tool. For high-stakes
credentials (primary email, banking, work SSO), prefer mature audited products
such as Bitwarden, 1Password, or KeePassXC.

## What it is / isn't for

| Good fit | Poor fit |
|----------|----------|
| Learning crypto / local vaults | Enterprise secret management |
| Small personal credential sets | Shared team vaults |
| Air-gapped or single-machine use | Sync across untrusted devices |
| Generating strong passwords & TOTP | Storing files/attachments |
| Optional HIBP check when online | Relying on breach checks offline |

## Cryptography

### Key derivation

| KDF | Parameters | Notes |
|-----|------------|--------|
| **Argon2id** (default when `argon2-cffi` is installed) | time=3, memory=64 MiB, parallelism=4, hash_len=32 | Preferred |
| **PBKDF2-HMAC-SHA256** | 600,000 iterations, hash_len=32 | Fallback if Argon2 unavailable |

Salt: 16 random bytes, stored in the vault file (not secret).

Derived key is urlsafe-base64-encoded for Fernet.

### Encryption & integrity

- **Fernet** (AES-128-CBC + HMAC-SHA256) encrypts the JSON map of entries.
- A separate **HMAC-SHA256** over `salt|vault` (using the derived key) detects
  tampering of the on-disk wrapper. Wrong master password and tampering both
  surface as decryption failure (`InvalidToken`).
- **`pwmanager verify`** re-reads the vault file, recomputes the HMAC, and
  confirms the ciphertext still decrypts — without listing entry contents.

### Vault file format (v2)

```json
{
  "version": 2,
  "kdf": "argon2id",
  "salt": "<base64>",
  "vault": "<Fernet token>",
  "hmac": "<hex sha256>"
}
```

Entry fields (inside the encrypted payload): `username`, `password`, `url`,
`notes`, `tags`, `totp_secret`, `history`, `created_at`, `updated_at`,
`favorite` (optional, default false), `kind` (`login` | `note`, default `login`),
`rotate_after_days` (optional, default null → global 90-day rotation window),
`last_accessed` (optional, default 0).

Older vaults load with safe defaults for new fields (`Entry.from_dict`).

## Have I Been Pwned (HIBP) — optional network feature

`pwmanager audit --hibp` (or interactive **h**) can check whether stored
passwords appear in known breach corpora using the HIBP **Pwned Passwords**
range API ([k-anonymity model](https://haveibeenpwned.com/API/v3#PwnedPasswords)).

### What is sent

| Sent | Not sent |
|------|----------|
| First **5 hex characters** of `SHA-1(password)` | The password itself |
| | The remaining hash suffix |
| | Entry names, usernames, or vault paths |
| | Master password |

### How it works

1. Locally compute `SHA-1` of the password (UTF-8).
2. HTTP GET `https://api.pwnedpasswords.com/range/{prefix}` with only the 5-char prefix.
3. Compare the local hash **suffix** against the returned list of `SUFFIX:COUNT` lines.
4. Report **entry names** that match (never print the password or full hash).

### Offline / failure behavior

If the network is unavailable, DNS fails, or the request times out, the audit
reports **skipped (network unavailable)** and continues. HIBP is never required
for normal vault use.

### Privacy considerations

- This is the only **optional outbound network** call in pwmanager.
- Do not use `--hibp` on a hostile network if you are concerned about traffic
  analysis of hash prefixes (theoretical risk; prefixes alone do not reveal passwords).
- Prefer running HIBP checks on a trusted connection.

## `--password-env` / `PWMANAGER_PASSWORD` (INSECURE)

By default, the master password is **always read via an interactive prompt**
(`getpass`). For automated tests or tightly controlled pipelines only, you may
pass **`--password-env`**, which reads the master password from the
`PWMANAGER_PASSWORD` environment variable.

| Do | Don't |
|----|--------|
| Use only with disposable test vaults | Put production master passwords in env files, Compose, or shell rc |
| Unset the variable immediately after use | Log or echo `PWMANAGER_PASSWORD` |
| Prefer OS keychain / secret stores outside this tool | Commit env files that contain real passwords |
| Keep the flag off for daily interactive use | Assume process environment is private on multi-user hosts |

Environment variables are visible to other processes with sufficient privilege,
appear in some crash dumps, and are easy to leak via CI logs. **This flag is an
explicit insecure opt-in** — not a recommended production unlock method.

## Plaintext export (`export-csv` / `export-json`)

Both commands write **passwords, notes, and TOTP secrets in cleartext**.

- Interactive use requires typing `YES` (all caps).
- Scripts must pass **`--i-understand`**.
- Prefer **encrypted** `export` for backups and machine moves.
- Delete plaintext files when migration is finished.
- **Never commit** `vault.json`, `*.vault.json`, CSV, or JSON exports to git
  (see `.gitignore`).

## Operational recommendations

1. **Master password** — long passphrase (≥ 5 random words) or ≥ 16 chars with high entropy. There is **no recovery**.
2. **Install Argon2** — `pip install "pwmanager[full]"` so Argon2id is used. Run `pwmanager doctor` to confirm.
3. **Permissions** — keep vault files on an encrypted volume; restrict file mode (`chmod 600`).
4. **Backups** — use **encrypted** export; never commit vault files to git.
5. **Plaintext CSV/JSON export** — treat as highly sensitive; delete when finished.
6. **Clipboard** — `get --copy` and interactive copy use auto-clear (`--clipboard-timeout`); still avoid shared machines.
7. **Auto-lock** — idle lock (default 5 minutes) clears the terminal screen in interactive mode; lock manually when stepping away.
8. **Rotation** — audit flags passwords older than 90 days (or per-entry `rotate_after_days`); use `touch` after rotating.
9. **Updates** — keep `cryptography` and Python patched.
10. **Audit / stats / HIBP / verify** — run `audit` regularly; `verify` after copies or sync; use `--hibp` when online.
11. **Profiles** — keep separate vaults for work/personal under `~/.config/pwmanager/`; do not sync vaults via unencrypted cloud folders.
12. **Memory** — Python strings cannot be securely wiped; assume secrets may linger until process exit.
13. **History / TOTP watch** — history browser shows previous passwords only while unlocked; live TOTP is terminal-only.
14. **Automation** — avoid `--password-env` except for ephemeral test vaults.

## Reporting issues

Open a private security advisory or issue on the
[GitHub repository](https://github.com/Sebby1770/pwmanager). Please do not
include real passwords or vault files in public reports.

## Scope of support

This project is provided under the MIT license **as-is**, without warranty.
Security fixes are welcome via pull request.
