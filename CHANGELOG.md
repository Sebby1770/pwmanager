# Changelog

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
