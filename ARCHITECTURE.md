# Architecture & concept map

pwmanager is a **local-first, zero-knowledge** password manager. Everything is
one dependency-light Python module; the vault is encrypted at rest and the
master password is never stored. This document is an honest map of every
backend concept from the project brief onto the code.

- ✅ **implemented** — real, tested code here
- 🧩 **configured** — real config/manifest in the repo
- 🗺️ **roadmap** — designed & documented (see `CLOUD_SYNC.md`), not yet wired in

## How it fits together

```
CLI (argparse)  ──►  Vault  ──►  StorageBackend  ──►  JSONStorage | SQLiteStorage
                       │                                    (encrypted payload)
     derive_key (Argon2id/PBKDF2)  ─┐
     Fernet encrypt/decrypt         ├─ crypto core (same for every backend)
     file_hmac integrity tag       ─┘
                       │
                  audit LOG (events only, never secrets)
```

The crypto is identical regardless of backend — only *where the encrypted blob
lives* changes. That single seam (`StorageBackend`) is what makes both the
embedded database and the cloud-sync roadmap clean.

## Concept map

| Concept | Status | Where / how |
|---|---|---|
| **Encryption** | ✅ | Argon2id (PBKDF2 fallback) → Fernet (AES-128-CBC + HMAC). `derive_key`, `encrypt_bytes`. |
| **Embedded database** | ✅ | `SQLiteStorage` — the encrypted blob in a one-row SQLite table (`--backend sqlite`). |
| **Database** | ✅ | The vault *is* the database; `StorageBackend` abstracts JSON vs SQLite. |
| **Optimisation** | ✅ | Tunable Argon2id cost (time=3, 64 MiB, p=4); atomic writes; single-pass search. |
| **Error logging** | ✅ | Structured audit log (`--log-file`) of events; secrets are never logged. |
| **Rate limiting** | ✅ | Failed-unlock lockout with exponential backoff, max 5 attempts. |
| **Firewall** (access control) | ✅ | Vault/backup/log files written `0600`; warns if a vault is world-readable. |
| **Encryption integrity** | ✅ | Enforced HMAC — unlock refuses a tampered envelope (`IntegrityError`). |
| **CI/CD** | 🧩 | `.github/workflows/ci.yml` — ruff + pytest on Python 3.9–3.13. |
| **Containerisation / Docker** | 🧩 | Non-root `Dockerfile` + `.dockerignore`. |
| **deployments** | 🧩 | `pip install .` → `pwmanager` console script; versioned `pyproject.toml`. |
| **git / github / cherry pick** | 🧩 | This repo + CI; backport recipe in `CONTRIBUTING.md`. |
| **CLOUD / S3** | 🗺️ | Encrypted-blob sync to S3 (zero-knowledge) — `CLOUD_SYNC.md`. |
| **DynamoDB** | 🗺️ | Optimistic version/lock metadata for multi-device sync — `CLOUD_SYNC.md`. |
| **Serverless / Lambda** | 🗺️ | Scheduled encrypted backup + breach-check function — `CLOUD_SYNC.md`. |
| **SQS / Kafka / RabbitMQ** | 🗺️ | Async breach-scan / notification queue for a hosted edition — `CLOUD_SYNC.md`. |
| **Web sockets / RPC / long-short polling** | 🗺️ | Local autofill daemon over a Unix socket for a browser extension. |
| **Load balancer / QPS / throughput / availability** | 🗺️ | Only relevant to a hosted multi-user edition (see roadmap). |
| **Sharding / partitioning** | 🗺️ | Hosted edition: shard vault blobs by user id. |
| **FTP** | 🗺️ | Off-box encrypted backups over SFTP (the blob is already ciphertext). |
| **TensorFlow** | 🗺️ | On-device password-strength / breach-pattern classifier (offline model). |
| **PyCharm** | — | The tool is IDE-agnostic; developed with pytest + ruff from any editor. |

## Why "zero-knowledge" matters for the roadmap

Because the vault is already a single encrypted blob (`payload["vault"]`), every
cloud item above syncs *ciphertext only*. The server, S3 object, and DynamoDB
row never see the master password or plaintext — the same property that makes
the local tool safe is what makes the hosted roadmap safe. See `CLOUD_SYNC.md`.
