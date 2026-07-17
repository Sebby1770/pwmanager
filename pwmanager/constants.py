"""Shared constants for pwmanager."""

from __future__ import annotations

import os

VAULT_VERSION = 2
DEFAULT_VAULT_PATH = os.path.join(os.getcwd(), "vault.json")

# Argon2id parameters (sensible defaults — adjust higher for slower/stronger)
ARGON2_TIME_COST = 3
ARGON2_MEMORY_COST = 64 * 1024  # 64 MiB
ARGON2_PARALLELISM = 4

# PBKDF2 fallback
PBKDF2_ITERATIONS = 600_000

SALT_SIZE = 16
KEY_SIZE = 32

AUTOLOCK_SECONDS = 300  # 5 minutes idle
CLIPBOARD_CLEAR_SECONDS = 20
MAX_UNLOCK_ATTEMPTS = 5

# Password generator symbols
SYMBOLS = "!@#$%^&*()-_=+[]{};:,.?/"

# Audit thresholds
WEAK_ENTROPY_BITS = 50.0
# Default rotation window when Entry.rotate_after_days is None (v2.3+)
ROTATE_DEFAULT_DAYS = 90
# Alias kept for older imports / docs
OLD_PASSWORD_DAYS = ROTATE_DEFAULT_DAYS
