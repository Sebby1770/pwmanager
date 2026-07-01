# Contributing to pwmanager

It's a single-file tool with a small test suite. Keep it dependency-light —
`cryptography` is the only hard dependency; anything else must degrade
gracefully when absent (see how `argon2` and `pyperclip` are handled).

## Setup & checks (what CI runs)

```sh
pip install ".[argon2,dev]"
ruff check .
pytest
```

## Security ground rules

- **Never log or print secrets.** The audit log records event *names* and entry
  *labels* only — add tests if you touch that path.
- Anything that persists the vault must go through a `StorageBackend`, never
  raw file IO, so both backends stay in sync.
- New crypto or storage code needs a test in `tests/` — prefer a known-answer
  vector where one exists (see the RFC 6238 TOTP test).

## Branch & PR workflow

1. `git switch -c feat/thing` off `main`.
2. Update `CHANGELOG.md` (Unreleased) and, if relevant, `ARCHITECTURE.md`.
3. Push, open a PR, get CI green.

### Cherry-picking a security fix to a release branch

```sh
git switch release/2.0
git cherry-pick -x <commit-sha>   # -x records the original SHA for traceability
git push
```
