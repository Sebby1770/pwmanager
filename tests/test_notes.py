"""Tests for secure note entries."""

from __future__ import annotations

from pwmanager.models import KIND_NOTE, Entry
from pwmanager.vault import Vault


def test_note_roundtrip(tmp_path):
    path = tmp_path / "vault.json"
    v = Vault(str(path))
    v.create("test-master-pw-not-real!!", kdf="pbkdf2")

    note = Entry(
        kind=KIND_NOTE,
        notes="Wifi password is in the drawer.\nLine two.",
        username="",
        password="",
        tags=["personal"],
    )
    v.add("home-wifi", note)
    v.lock()

    v2 = Vault(str(path))
    v2.unlock("test-master-pw-not-real!!")
    e = v2.entries["home-wifi"]
    assert e.kind == KIND_NOTE
    assert e.is_note()
    assert "drawer" in e.notes
    assert e.password == ""
    assert "personal" in e.tags


def test_login_default_kind(tmp_path):
    path = tmp_path / "vault.json"
    v = Vault(str(path))
    v.create("test-master-pw-not-real!!", kdf="pbkdf2")
    v.add("gh", Entry(username="u", password="p"))
    v.lock()

    v2 = Vault(str(path))
    v2.unlock("test-master-pw-not-real!!")
    assert v2.entries["gh"].kind == "login"
    assert not v2.entries["gh"].is_note()


def test_from_dict_legacy_without_kind():
    e = Entry.from_dict({"username": "a", "password": "b"})
    assert e.kind == "login"


def test_from_dict_invalid_kind_falls_back():
    e = Entry.from_dict({"kind": "weird", "notes": "x"})
    assert e.kind == "login"


def test_note_with_optional_password(tmp_path):
    path = tmp_path / "vault.json"
    v = Vault(str(path))
    v.create("test-master-pw-not-real!!", kdf="pbkdf2")
    v.add(
        "safe",
        Entry(kind="note", notes="body", password="optional-secret"),
    )
    v.lock()
    v2 = Vault(str(path))
    v2.unlock("test-master-pw-not-real!!")
    assert v2.entries["safe"].is_note()
    assert v2.entries["safe"].password == "optional-secret"
