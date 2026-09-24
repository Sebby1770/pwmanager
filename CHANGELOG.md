# Changelog

## Unreleased (3.3.0)

### Security
- Security audit fixes F1–F12; see the table in `SECURITY.md`.
- Stripe: Pro is granted only once payment has actually succeeded, and stale or out-of-order webhook events can no longer change the plan.
- API: rate limiting uses the proxy-appended `X-Forwarded-For` hop, logins are also throttled per account, JSON routes cap bodies at 16 KiB, state-changing routes reject cross-origin and non-JSON requests, and sockets time out after 30 s.
- Account deletion now requires the auth key (re-entering the master password), not just a session cookie.
- `kdf_params` are validated and stored in canonical form.
- CLI: a vault or encrypted export with its HMAC removed is refused.
- Web vault: locking clears the clipboard and wipes decrypted values from the DOM; cloud sync compares a timestamp sealed inside the ciphertext, which fixes a data-loss bug where a second device overwrote newer cloud data.

- API: a request whose body was not read now closes the connection, which blocks HTTP request smuggling on keep-alive connections (F13).
- CLI: a tampered, non-ASCII vault MAC reports an integrity failure instead of crashing (F14).

### Added
- `import-csv` also accepts unencrypted Bitwarden JSON exports (`--format bitwarden-json`, or auto-detected), plus 1Password CSV columns.

### Fixed
- The passphrase generator's extra symbol is never the separator.
- CSV import keeps passwords and notes verbatim, reads back the `totp_secret` column from pwmanager's own export, keeps `favorite`/`kind`/`tags`, and never produces two entries with the same name (F15).

### Tests
- Regression tests for every audit finding, including Playwright tests against the real server and a zero-knowledge wire test.
- Property-based tests (hypothesis): AEAD round-trips, tampering with any byte or field of the vault file and the SaaS envelope (including real JS-produced envelopes decrypted in Python), envelope parser fuzzing, and CSV/Bitwarden-JSON importer fuzzing with an export→import round trip.
- Playwright end-to-end flow: sign up, add, lock, unlock, sync, second device, offline, CSP.
- CI enforces at least 90% coverage on `crypto.py`, `vault.py`, `importers.py` and `saas/` (currently 98%).

## 3.2.0

### Added
- Visible idle-lock countdown in the vault sidebar.
- Five-word passphrase generator (EFF wordlist, rejection-sampled) beside the existing password generator.
- Landing honesty strip: never on the wire, never in a URL, never recoverable.

## 3.1.0

### Added
- Vault keyboard shortcuts: `/` search, `n` new entry, `l` lock, `?` help.
- Encrypted **recovery kit** download (ciphertext + warning; master password is not in the file). Import accepts kits or raw envelopes.
- Submit buttons disable while PBKDF2 is deriving keys.
- `Strict-Transport-Security` when `PWMANAGER_SECURE_COOKIES=1`.

## 3.0.0

### Added

- **Zero-knowledge web vault (`web/` + `saas/`)** — browser encryption with
  WebCrypto PBKDF2-HMAC-SHA256 (600,000 iterations) deriving two keys:
  `vaultKey` (AES-GCM-256, never sent) and `authKey` (hashed again on the
  server). IndexedDB stores ciphertext only. Pro cloud sync uploads an opaque
  `{v, nonce, ct, kdf}` envelope.
- Hosted API (`python saas/server.py`) with SQLite, HttpOnly session cookies,
  rate-limited register/login, Stripe Checkout (no PAN on this server), HMAC
  webhook verification, account export of ciphertext, and account deletion that
  wipes blobs.
- Marketing, vault, pricing, generator, and legal pages (Privacy, Terms,
  Cookies, Security, DPA, Acceptable use) for an independent Victoria,
  Australia project. Australian Consumer Law guarantees are not excluded.
- Free (local vault + generator) and Pro (A$4/month or A$40/year encrypted
  sync, versioned blobs, 8&nbsp;MiB cap). Missing Stripe keys return 503; the
  server never fakes a paid plan.

### Changed

- The static generator moved to `web/generator.html`. `web/index.html` is the
  product landing page. Generator logic in `generator.js` / `wordlist.js` is
  unchanged.

## 2.5.0

### Added

- AES-256-GCM for new vaults. Fernet files still unlock and migrate on the next
  save. The wrapper HMAC is now v3 and also covers the `cipher` field.
- Atomic master-password change: new salt and key are written via rename, so a
  crash cannot leave the vault deleted.
- One-slot trash inside the encrypted payload (`undelete` / `z`) so a delete
  survives a process restart until the next delete.
- `rename` / `m` to rename an entry.

### Changed

- Encrypted export/import use the same v3 wrapper (cipher + HMAC) as the vault.
- CI runs Python 3.13 as well as 3.11 and 3.12.

## 2.4.0

### Added

- **Web generator (`web/`)** — a static, dependency-free password and passphrase
  generator that runs entirely in the browser and deploys to GitHub Pages.
  Presets, symbol set, lookalike set, wordlist and entropy thresholds are shared
  with the CLI, and `tests/test_web_parity.py` fails if the two drift apart.
  Randomness comes from `crypto.getRandomValues` with rejection sampling (no
  modulo bias, no `Math.random` fallback). A Content-Security-Policy permits one
  outbound destination — the HIBP range API, contacted only on an explicit click.
- `pwmanager gen` gained `--no-lower`, `--no-upper`, `--no-digits`, `--separator`,
  `--capitalize` and `--count N`, so every policy the web UI offers is expressible
  from the terminal.
- `pwmanager doctor` now reports the vault file's permission bits.
- `Vault.file_mode()` and `Vault.tighten_permissions()` for auditing and fixing
  vaults created by earlier versions.
- `tests/js/run.mjs` — 35 dependency-free tests for the browser generator,
  including a distribution check that would fail on a modulo-biased RNG.

### Fixed

- **The vault integrity check was a no-op.** `unlock()` computed the file HMAC
  and then discarded the result, so a vault modified outside pwmanager opened
  without complaint. It now raises `VaultIntegrityError` — but only after the
  ciphertext has decrypted, so an ordinary wrong password is still reported as a
  wrong password rather than as tampering.
- **The file HMAC did not cover `version` or `kdf`.** Both are unencrypted, so
  edits to them went undetected. The MAC is now domain-separated and
  length-prefixed over all four plain fields. Vaults carrying the older
  salt+ciphertext MAC still open and are upgraded on the next save.
- **Vault files were written through the process umask**, typically leaving them
  group- and world-readable. They are now created `0600` from the start — the
  temp file included, so there is no window where the mode is loose — and
  `fsync`ed before and after the atomic rename.
- **`save()` could destroy a vault.** It re-read the file for its salt without
  checking the read succeeded; a truncated or missing file produced a confusing
  crash. It now refuses to overwrite a vault it cannot parse, and says why.
- **Passphrase strength was overstated by roughly 3x.** `password_entropy_bits`
  applied a per-character model to dictionary passphrases, reporting ~150 bits
  for a five-word phrase actually worth ~55. Recognisable wordlist phrases are
  now scored as `words * log2(listSize)`; random passwords are unaffected.

### Changed

- CI additionally runs the Node generator tests and fails if `web/wordlist.js`
  has drifted from `pwmanager/data/eff_short.txt`.

## 2.3.0

- Rotation reminders, `get --copy`, `verify`, `recent`, `doctor`, generator presets.

## 2.2.0 and earlier

- TOTP, HIBP audit, secure notes, profiles, favorites, fuzzy search, import/export.
