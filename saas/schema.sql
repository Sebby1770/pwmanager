-- pwmanager SaaS schema. SQLite by default; types chosen to also run on Postgres.
-- Ciphertext only: never store master passwords, vault contents in the clear, TOTP secrets, or card data.

CREATE TABLE IF NOT EXISTS meta (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS accounts (
    id TEXT PRIMARY KEY,
    email TEXT NOT NULL UNIQUE,
    auth_verifier TEXT NOT NULL,
    kdf_salt TEXT NOT NULL,
    kdf_params TEXT NOT NULL,
    created_at TEXT NOT NULL,
    last_login_at TEXT,
    email_verified_at TEXT,
    stripe_customer_id TEXT,
    plan TEXT NOT NULL DEFAULT 'free',
    plan_status TEXT,
    plan_period_end TEXT,
    deleted_at TEXT,
    CHECK (plan IN ('free', 'pro'))
);

CREATE TABLE IF NOT EXISTS sessions (
    id TEXT PRIMARY KEY,
    account_id TEXT NOT NULL REFERENCES accounts(id),
    token_hash TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    created_at TEXT NOT NULL,
    user_agent_hash TEXT
);

CREATE INDEX IF NOT EXISTS idx_sessions_account ON sessions(account_id);
CREATE INDEX IF NOT EXISTS idx_sessions_token ON sessions(token_hash);

CREATE TABLE IF NOT EXISTS vault_blobs (
    id TEXT PRIMARY KEY,
    account_id TEXT NOT NULL UNIQUE REFERENCES accounts(id),
    ciphertext TEXT NOT NULL,
    nonce TEXT NOT NULL,
    aad_version INTEGER NOT NULL,
    byte_size INTEGER NOT NULL,
    updated_at TEXT NOT NULL,
    CHECK (byte_size > 0 AND byte_size <= 8388608)
);

CREATE TABLE IF NOT EXISTS vault_revisions (
    id TEXT PRIMARY KEY,
    account_id TEXT NOT NULL REFERENCES accounts(id),
    ciphertext TEXT NOT NULL,
    nonce TEXT NOT NULL,
    aad_version INTEGER NOT NULL,
    byte_size INTEGER NOT NULL,
    updated_at TEXT NOT NULL,
    CHECK (byte_size > 0 AND byte_size <= 8388608)
);

CREATE INDEX IF NOT EXISTS idx_revisions_account ON vault_revisions(account_id, updated_at);

CREATE TABLE IF NOT EXISTS payment_events (
    id TEXT PRIMARY KEY,
    stripe_event_id TEXT NOT NULL UNIQUE,
    type TEXT NOT NULL,
    account_id TEXT,
    payload_type TEXT,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS audit_events (
    id TEXT PRIMARY KEY,
    account_id TEXT,
    event TEXT NOT NULL,
    at TEXT NOT NULL,
    ip_hash TEXT
);

CREATE INDEX IF NOT EXISTS idx_audit_account ON audit_events(account_id, at);

CREATE TABLE IF NOT EXISTS rate_limits (
    key TEXT PRIMARY KEY,
    window_start INTEGER NOT NULL,
    count INTEGER NOT NULL
);
