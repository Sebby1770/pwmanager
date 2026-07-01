# Cloud sync roadmap (zero-knowledge)

pwmanager is local-first by design. This document is the **honest roadmap** for
optional, opt-in cloud sync — real AWS services and a real data flow, not yet
wired into the CLI. The guiding rule: **the cloud only ever sees ciphertext.**

## Why this is safe

The vault is already a single encrypted blob (`payload["vault"]`, a Fernet
token). Sync uploads *that blob*. The master password and every plaintext entry
never leave the device, so a breach of the bucket, the table, or the network
reveals nothing but opaque ciphertext.

## Data flow

```
device A                         AWS                          device B
────────                    ─────────────                    ────────
encrypt vault ──put──►  S3 (versioned bucket)  ◄──get──  decrypt vault
     │                        ▲     │
     │ conditional write      │     │ object-created event
     ▼                        │     ▼
DynamoDB (version, etag) ◄────┘   Lambda (breach check) ──► SQS ──► notifier
  optimistic lock                   (HaveIBeenPwned k-anon)
```

| Service | Role | Concept |
|---------|------|---------|
| **S3** | Store the versioned encrypted vault blob | S3, CLOUD |
| **DynamoDB** | `{user_id → {version, etag, updated_at}}` for optimistic-lock conflict detection across devices | DynamoDB, sharding, partitioning |
| **Lambda** | On upload: k-anonymised breach check of password *hash prefixes* (never plaintext) | Serverless, Lambda |
| **SQS** | Queue breach/notification jobs, decoupled from the sync path | SQS |
| **SFTP** | Alternative off-box encrypted backup target | FTP |
| **TLS** | All transport encrypted in flight; blob encrypted at rest | Encryption |

## Sketch: the sync command (not yet in the CLI)

```python
# pwsync.py — optional module; boto3 imported lazily so the core stays dep-free.
def push(vault_path: str, bucket: str, key: str) -> None:
    import boto3  # optional dependency
    s3 = boto3.client("s3")
    with open(vault_path, "rb") as f:
        blob = f.read()            # already ciphertext — safe to upload as-is
    s3.put_object(Bucket=bucket, Key=key, Body=blob,
                  ServerSideEncryption="aws:kms")

def pull(vault_path: str, bucket: str, key: str) -> None:
    import boto3
    s3 = boto3.client("s3")
    blob = s3.get_object(Bucket=bucket, Key=key)["Body"].read()
    with open(vault_path, "wb") as f:
        f.write(blob)              # decrypt happens locally, with the master pw
```

## Conflict handling

Multi-device edits use DynamoDB as an optimistic lock: each push carries the
`version` it was based on and only wins the conditional write if the version is
unchanged. A losing push pulls, replays its local diff onto the newer blob, and
retries — the classic read-modify-write loop, keeping every device consistent
without a central lock server.

## Status

None of this is enabled today. The single `StorageBackend` seam
(`ARCHITECTURE.md`) is where a `S3Storage` backend would slot in with no change
to the crypto core.
