# Changelog

Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/);
this project adheres to [Semantic Versioning](https://semver.org/).

## [2.2.0] — 2026-07-04

### Added
- **`pwmanager import-csv <file> --format {chrome,bitwarden,generic}`** — the
  migration path in. Parses browser/password-manager CSV exports (BOM-safe,
  case-insensitive headers): Chrome's `name,url,username,password`,
  Bitwarden's `login_*` columns (including **`login_totp` → TOTP secret**),
  or a generic layout. Unnamed rows are named after their URL's domain, rows
  with no credentials are skipped, name clashes get a `" (2)"` suffix (never
  overwriting existing entries), and imports are tagged (`--tag`, default
  `imported`) for easy review. Reminds you the source CSV is plaintext.
- Five new tests (30 total): Chrome + Bitwarden mappings, domain naming,
  dedupe/skip rules, unknown-format rejection, and end-to-end merge +
  persistence into a real vault.

## [2.1.0] — 2026-07-03

### Security
- **Persistent unlock lockout.** Failed attempts are now recorded in an
  owner-only sidecar file (`<vault>.throttle`), so the exponential cooldown
  (30s after the 5th failure, doubling per failure, capped at 1h) **survives
  process restarts** — previously an attacker could reset the counter by
  simply re-running the program. A successful unlock clears it.

### Added
- **`pwmanager audit`** — a password health report (also menu option `a`):
  - **reused passwords** (groups of entries sharing one password),
  - **weak passwords** (< 50 bits of estimated entropy),
  - **stale passwords** (not rotated in over a year),
  - opt-in **HaveIBeenPwned breach check** (`--hibp`) via the k-anonymity
    range API: only the first 5 hex chars of each password's SHA-1 ever leave
    the machine; matching happens locally. Injectable fetcher, fully tested
    offline.
- Six new tests (25 total): throttle persistence across instances, exponential
  backoff and reset, sidecar file permissions, audit analysis of reuse/weak/
  stale, and HIBP prefix privacy + response parsing.

## [2.0.0] — 2026-07-02

Hardening + packaging release. The tool is still a single, dependency-light
Python file, but it now enforces integrity, supports an embedded database, and
ships with tests, CI, and packaging.

### Security
- **Enforced vault integrity.** Previous versions computed a file HMAC but the
  verification path was a no-op (`pass`) — a tampered envelope could slip
  through. Unlock now **raises `IntegrityError`** when the authentication tag
  does not match the decrypted contents. Covered by two regression tests.
- **Owner-only file permissions.** Vaults, backups and audit logs are written
  `0600`; a warning is logged if a vault is group/world-readable.

### Added
- **Embedded SQLite storage backend** (`--backend sqlite`) alongside the JSON
  backend, behind a small `StorageBackend` abstraction. Same ciphertext, new
  container.
- **Audit logging** (`--log-file`, `--verbose`): records events (create,
  unlock, add, delete, export, failed attempts, tamper, lockout) — **never**
  passwords or vault contents.
- **Packaging** (`pyproject.toml`): `pip install .` installs a `pwmanager`
  console script; optional extras `[argon2]`, `[clipboard]`, `[dev]`.
- **Test suite** (`tests/`, 19 tests): crypto round-trip, both backends,
  wrong-password rejection, integrity/tamper detection, generators, entropy,
  TOTP (RFC 6238 vector), export/import, search, file permissions.
- **CI** (`.github/workflows/ci.yml`): ruff + pytest across Python 3.9–3.13.
- **Docker** image (non-root) and `.dockerignore`.
- **Docs**: `ARCHITECTURE.md` (concept map), `CLOUD_SYNC.md` (zero-knowledge
  cloud-sync roadmap), `CONTRIBUTING.md`, `LICENSE` (MIT), and a `.gitignore`
  that keeps real vaults and logs out of git.

### Changed
- `Vault` now persists through a storage backend rather than touching the file
  path directly; `change_master` and `save` go through the same abstraction.
- README rewritten around backends, the audit log, packaging and integrity.

## [1.0.0] — 2026-05-06

### Added
- Initial single-file password manager: Argon2id/PBKDF2 KDF, Fernet-encrypted
  JSON vault, TOTP, password/passphrase generators, strength meter, tags,
  history, clipboard auto-clear, auto-lock, failed-attempt lockout, encrypted
  export/import, and an interactive + one-shot CLI.
