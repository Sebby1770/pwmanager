# Security Policy

## Threat model

**pwmanager** is a **local, offline** password manager. It is designed to protect
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
`favorite` (optional, default false).

## Operational recommendations

1. **Master password** — long passphrase (≥ 5 random words) or ≥ 16 chars with high entropy. There is **no recovery**.
2. **Install Argon2** — `pip install "pwmanager[full]"` so Argon2id is used.
3. **Permissions** — keep `vault.json` on an encrypted volume; restrict file mode (`chmod 600 vault.json`).
4. **Backups** — use **encrypted** export; never commit vault files to git (see `.gitignore`).
5. **Plaintext CSV export** — `export-csv` writes passwords and TOTP secrets in cleartext. Require typing `YES` or `--i-understand`. Treat the file as highly sensitive and delete it when finished.
6. **Clipboard** — auto-clear (`--clipboard-timeout`) reduces exposure; still avoid copying secrets on shared machines.
7. **Auto-lock** — idle lock (default 5 minutes, `--lock-timeout`) helps; lock manually when stepping away.
8. **Updates** — keep `cryptography` and Python patched.
9. **Audit / stats** — run `pwmanager audit` and `pwmanager stats` regularly; fix reused and weak passwords first.
10. **Memory** — Python strings cannot be securely wiped; assume secrets may linger until process exit.

## Reporting issues

Open a private security advisory or issue on the
[GitHub repository](https://github.com/Sebby1770/pwmanager). Please do not
include real passwords or vault files in public reports.

## Scope of support

This project is provided under the MIT license **as-is**, without warranty.
Security fixes are welcome via pull request.
