"""Tests for pwmanager 2.3 features (rotation, get/copy, verify, recent, doctor, presets)."""

from __future__ import annotations

import json
import time
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from pwmanager.audit import audit_vault, extract_domain
from pwmanager.cli import cmd_doctor, cmd_get, cmd_touch, cmd_verify
from pwmanager.generators import GENERATOR_PRESETS, generate_from_preset
from pwmanager.models import Entry
from pwmanager.vault import Vault

MASTER = "test-master-pw-not-real!!"


def _vault(tmp_path, entries=None) -> Vault:
    path = tmp_path / "vault.json"
    v = Vault(str(path))
    v.create(MASTER, kdf="pbkdf2")
    for name, e in (entries or {}).items():
        v.entries[name] = e
    if entries:
        v.save()
    return v


# ---- touch / rotation -------------------------------------------------------


def test_touch_updates_updated_at(tmp_path):
    old_ts = time.time() - (200 * 24 * 3600)
    v = _vault(
        tmp_path,
        {
            "github": Entry(
                username="me",
                password="Str0ng!Passw0rd#Aa",
                updated_at=old_ts,
                created_at=old_ts,
            ),
        },
    )
    before = v.entries["github"].updated_at
    assert before == old_ts

    rc = cmd_touch(v, "github")
    assert rc == 0
    after = v.entries["github"].updated_at
    assert after > before
    # password unchanged
    assert v.entries["github"].password == "Str0ng!Passw0rd#Aa"

    # persist
    v.lock()
    v2 = Vault(str(tmp_path / "vault.json"))
    v2.unlock(MASTER)
    assert v2.entries["github"].updated_at == after


def test_rotation_audit_flags_old_entries(tmp_path):
    old_ts = time.time() - (120 * 24 * 3600)  # > default 90 days
    fresh_ts = time.time()
    custom_old = time.time() - (20 * 24 * 3600)  # > custom 10 days
    v = _vault(
        tmp_path,
        {
            "stale": Entry(
                username="a",
                password="Str0ng!Passw0rd#Aa",
                updated_at=old_ts,
                created_at=old_ts,
            ),
            "fresh": Entry(
                username="b",
                password="Str0ng!Passw0rd#Bb",
                updated_at=fresh_ts,
            ),
            "custom-due": Entry(
                username="c",
                password="Str0ng!Passw0rd#Cc",
                updated_at=custom_old,
                rotate_after_days=10,
            ),
            "custom-ok": Entry(
                username="d",
                password="Str0ng!Passw0rd#Dd",
                updated_at=custom_old,
                rotate_after_days=60,
            ),
        },
    )
    report = audit_vault(v)
    assert "stale" in report.old
    assert "fresh" not in report.old
    assert "custom-due" in report.old
    assert "custom-ok" not in report.old


def test_touch_clears_rotation_flag(tmp_path):
    old_ts = time.time() - (200 * 24 * 3600)
    v = _vault(
        tmp_path,
        {
            "site": Entry(
                username="u",
                password="Str0ng!Passw0rd#Ee",
                updated_at=old_ts,
                created_at=old_ts,
            ),
        },
    )
    assert "site" in audit_vault(v).old
    v.touch_entry("site")
    assert "site" not in audit_vault(v).old


def test_entry_from_dict_defaults_for_new_fields():
    e = Entry.from_dict({"username": "u", "password": "p"})
    assert e.rotate_after_days is None
    assert e.last_accessed == 0.0
    assert e.kind == "login"


# ---- get --copy -------------------------------------------------------------


def test_get_copy_password_mocked(tmp_path):
    v = _vault(
        tmp_path,
        {
            "svc": Entry(
                username="alice",
                password="secret-Pw1!",
                url="https://example.com",
            ),
        },
    )
    mock_clip = MagicMock()
    with patch("pwmanager.cli.CLIPBOARD_AVAILABLE", True), patch(
        "pwmanager.cli.pyperclip", mock_clip, create=True
    ), patch("pwmanager.cli.copy_with_autoclear", return_value=True) as copy_mock:
        rc = cmd_get(v, "svc", copy_field="password")
    assert rc == 0
    copy_mock.assert_called_once()
    assert copy_mock.call_args[0][0] == "secret-Pw1!"
    # last_accessed updated
    assert v.entries["svc"].last_accessed > 0


def test_get_prints_password_without_copy(tmp_path, capsys):
    v = _vault(
        tmp_path,
        {"svc": Entry(username="alice", password="secret-Pw1!")},
    )
    rc = cmd_get(v, "svc", copy_field=None)
    assert rc == 0
    out = capsys.readouterr().out
    assert "secret-Pw1!" in out


# ---- verify -----------------------------------------------------------------


def test_verify_ok(tmp_path):
    v = _vault(tmp_path, {"a": Entry(username="u", password="Str0ng!Passw0rd#Ff")})
    ok, msg = v.verify_integrity()
    assert ok is True
    assert "OK" in msg
    assert cmd_verify(v) == 0


def test_verify_fail_tampered_hmac(tmp_path):
    v = _vault(tmp_path, {"a": Entry(username="u", password="Str0ng!Passw0rd#Gg")})
    path = Path(v.path)
    payload = json.loads(path.read_text(encoding="utf-8"))
    payload["hmac"] = "0" * 64
    path.write_text(json.dumps(payload), encoding="utf-8")
    # re-unlock not needed — key still in memory; verify reads disk
    ok, msg = v.verify_integrity()
    assert ok is False
    assert "HMAC" in msg or "mismatch" in msg.lower()


# ---- export-json ------------------------------------------------------------


def test_export_json_structure(tmp_path):
    v = _vault(
        tmp_path,
        {
            "site1": Entry(
                username="alice",
                password="secret-Aa1!",
                url="https://example.com",
                tags=["work"],
                favorite=True,
            ),
            "site2": Entry(username="bob", password="other-Bb2!"),
        },
    )
    out = tmp_path / "export.json"
    n = v.export_json(str(out))
    assert n == 2
    data = json.loads(out.read_text(encoding="utf-8"))
    assert "entries" in data
    assert "exported_at" in data
    assert set(data["entries"].keys()) == {"site1", "site2"}
    assert data["entries"]["site1"]["password"] == "secret-Aa1!"
    assert data["entries"]["site1"]["username"] == "alice"
    assert data["entries"]["site1"]["favorite"] is True
    # new fields present with defaults
    assert "last_accessed" in data["entries"]["site2"]
    assert data["entries"]["site2"].get("rotate_after_days") is None


# ---- gen presets ------------------------------------------------------------


def test_gen_presets_expected_length():
    assert len(generate_from_preset("pin")) == GENERATOR_PRESETS["pin"]["length"]
    assert len(generate_from_preset("wifi")) == 16
    assert len(generate_from_preset("apple")) == 20
    assert len(generate_from_preset("max")) == 64

    pin = generate_from_preset("pin")
    assert pin.isdigit()

    wifi = generate_from_preset("wifi")
    ambiguous = set("Il1O0o`'\"|")
    assert not any(c in ambiguous for c in wifi)
    # wifi: no symbols
    from pwmanager.constants import SYMBOLS

    assert not any(c in SYMBOLS for c in wifi)


def test_gen_preset_unknown():
    with pytest.raises(ValueError):
        generate_from_preset("nope")


# ---- recent -----------------------------------------------------------------


def test_recent_orders_by_last_accessed(tmp_path):
    v = _vault(
        tmp_path,
        {
            "a": Entry(username="u", password="Str0ng!Passw0rd#Aa"),
            "b": Entry(username="u", password="Str0ng!Passw0rd#Bb"),
            "c": Entry(username="u", password="Str0ng!Passw0rd#Cc"),
            "never": Entry(username="u", password="Str0ng!Passw0rd#Dd"),
        },
    )
    # Access in order a, c, b (b most recent)
    v.entries["a"].last_accessed = 100.0
    v.entries["c"].last_accessed = 200.0
    v.entries["b"].last_accessed = 300.0
    v.save()

    order = v.recent(limit=10)
    assert order == ["b", "c", "a"]
    assert "never" not in order
    assert v.recent(limit=2) == ["b", "c"]


# ---- doctor -----------------------------------------------------------------


def test_doctor_returns_0():
    rc = cmd_doctor()
    assert rc == 0


# ---- duplicate username / domain --------------------------------------------


def test_extract_domain():
    assert extract_domain("https://www.Example.com/path") == "example.com"
    assert extract_domain("github.com") == "github.com"
    assert extract_domain("") == ""


def test_duplicate_username_across_domains(tmp_path):
    v = _vault(
        tmp_path,
        {
            "gh": Entry(
                username="same@mail.com",
                password="Str0ng!Passw0rd#Aa",
                url="https://github.com",
                updated_at=time.time(),
            ),
            "gl": Entry(
                username="same@mail.com",
                password="Str0ng!Passw0rd#Bb",
                url="https://gitlab.com",
                updated_at=time.time(),
            ),
            "unique": Entry(
                username="other@mail.com",
                password="Str0ng!Passw0rd#Cc",
                url="https://other.example",
                updated_at=time.time(),
            ),
        },
    )
    report = audit_vault(v)
    flat = {n for g in report.duplicate_username_groups for n in g}
    assert "gh" in flat and "gl" in flat
    assert "unique" not in flat
