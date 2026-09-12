"""Vault envelope validation and schema hygiene for the zero-knowledge API."""

from __future__ import annotations

import base64
import json
import os
from pathlib import Path

import pytest

from saas.envelope import EnvelopeError, envelope_byte_size, parse_envelope

ROOT = Path(__file__).resolve().parent.parent
SCHEMA = (ROOT / "saas" / "schema.sql").read_text(encoding="utf-8")


def _b64(n: int) -> str:
    return base64.b64encode(os.urandom(n)).decode("ascii")


def valid_envelope(**overrides):
    body = {
        "v": 1,
        "nonce": _b64(12),
        "ct": _b64(64),
        "kdf": {
            "alg": "PBKDF2-HMAC-SHA256",
            "hash": "SHA-256",
            "iterations": 600000,
            "salt": _b64(32),
        },
    }
    body.update(overrides)
    return body


def test_valid_envelope_round_trips():
    env = parse_envelope(valid_envelope(updated_at=1_700_000_000))
    assert env["v"] == 1
    assert env["kdf"]["iterations"] == 600000
    assert env["updated_at"] == 1_700_000_000
    assert envelope_byte_size(env) > 80


def test_envelope_rejects_missing_fields():
    env = valid_envelope()
    del env["nonce"]
    with pytest.raises(EnvelopeError, match="missing"):
        parse_envelope(env)


def test_envelope_rejects_plaintext_password_field():
    env = valid_envelope()
    env["password"] = "hunter2"
    with pytest.raises(EnvelopeError, match="plaintext"):
        parse_envelope(env)


def test_envelope_rejects_entries_array():
    env = valid_envelope()
    env["entries"] = [{"password": "nope"}]
    with pytest.raises(EnvelopeError, match="plaintext"):
        parse_envelope(env)


def test_envelope_rejects_short_nonce():
    env = valid_envelope(nonce=_b64(8))
    with pytest.raises(EnvelopeError, match="nonce"):
        parse_envelope(env)


def test_envelope_rejects_weak_kdf():
    env = valid_envelope()
    env["kdf"]["iterations"] = 1000
    with pytest.raises(EnvelopeError, match="600000"):
        parse_envelope(env)


def test_envelope_rejects_non_json():
    with pytest.raises(EnvelopeError):
        parse_envelope(b"not-json")


def test_schema_has_no_plaintext_secret_columns():
    forbidden = (
        "password_plain",
        "master_password",
        "totp_secret",
        "card_number",
        "pan",
        "cvv",
        "cvc",
    )
    # Ignore SQL comments; only column / constraint text can hide a secret field.
    stripped = "\n".join(
        line.split("--", 1)[0] for line in SCHEMA.splitlines()
    ).lower()
    for name in forbidden:
        assert name not in stripped, f"schema must not contain column/token {name}"
    vault_start = stripped.index("create table if not exists vault_blobs")
    vault_end = stripped.index(";", vault_start)
    vault_sql = stripped[vault_start:vault_end]
    assert "password" not in vault_sql
    assert "ciphertext" in vault_sql
    assert "nonce" in vault_sql


def test_schema_caps_blob_size_at_8mb():
    assert "8388608" in SCHEMA
    assert "plan IN ('free', 'pro')" in SCHEMA or "plan in ('free', 'pro')" in SCHEMA.lower()


def test_parse_envelope_accepts_json_bytes():
    env = valid_envelope()
    parsed = parse_envelope(json.dumps(env).encode("utf-8"))
    assert parsed["v"] == 1


def test_js_aes_roundtrip():
    import shutil
    import subprocess

    node = shutil.which("node")
    if node is None:
        pytest.skip("node is not installed")
    script = ROOT / "tests" / "js" / "saas_crypto.mjs"
    result = subprocess.run([node, str(script)], capture_output=True, text=True, timeout=60)
    assert result.returncode == 0, result.stdout + result.stderr
    assert "roundtrip ok" in result.stdout
