"""Vault create / unlock / add / delete roundtrip (tmp_path, fake data)."""

from __future__ import annotations

import pytest
from cryptography.fernet import InvalidToken

from pwmanager.models import Entry
from pwmanager.vault import Vault

MASTER = "test-master-pw-not-real!!"
WRONG = "wrong-master-password!!!"


def test_create_unlock_add_delete_roundtrip(tmp_path):
    path = tmp_path / "vault.json"
    v = Vault(str(path))
    assert not v.exists()

    v.create(MASTER, kdf="pbkdf2")
    assert v.exists()
    assert v.key is not None
    assert v.entries == {}

    entry = Entry(
        username="alice@example.com",
        password="fake-password-Aa1!",
        url="https://example.com",
        notes="test note",
        tags=["test", "demo"],
    )
    v.add("example", entry)
    assert "example" in v.entries
    assert v.entries["example"].username == "alice@example.com"

    v.lock()
    assert v.key is None
    assert v.entries == {}

    v2 = Vault(str(path))
    v2.unlock(MASTER)
    assert "example" in v2.entries
    assert v2.entries["example"].password == "fake-password-Aa1!"
    assert v2.entries["example"].tags == ["test", "demo"]

    v2.delete("example")
    assert "example" not in v2.entries

    v2.lock()
    v3 = Vault(str(path))
    v3.unlock(MASTER)
    assert v3.entries == {}


def test_wrong_password_raises(tmp_path):
    path = tmp_path / "vault.json"
    v = Vault(str(path))
    v.create(MASTER, kdf="pbkdf2")
    v.lock()

    v2 = Vault(str(path))
    with pytest.raises(InvalidToken):
        v2.unlock(WRONG)


def test_search_case_insensitive_and_tag(tmp_path):
    path = tmp_path / "vault.json"
    v = Vault(str(path))
    v.create(MASTER, kdf="pbkdf2")
    v.add(
        "GitHub",
        Entry(username="dev", password="x" * 20, tags=["work", "code"], url="https://github.com"),
    )
    v.add(
        "Bank",
        Entry(username="me", password="y" * 20, tags=["finance"], notes="savings"),
    )

    assert v.search("github") == ["GitHub"]
    assert v.search("SAVINGS") == ["Bank"]
    assert v.search("", tag="work") == ["GitHub"]
    assert v.search("git", tag="work") == ["GitHub"]
    assert v.search("git", tag="finance") == []
    assert set(v.search("")) == {"Bank", "GitHub"}


def test_export_import_encrypted(tmp_path):
    path = tmp_path / "vault.json"
    export_path = tmp_path / "export.json"
    v = Vault(str(path))
    v.create(MASTER, kdf="pbkdf2")
    v.add("a", Entry(username="u", password="p1-fake-Aa!"))
    v.export_encrypted(str(export_path), "export-pass-not-real")

    v2 = Vault(str(tmp_path / "vault2.json"))
    v2.create(MASTER, kdf="pbkdf2")
    n = v2.import_encrypted(str(export_path), "export-pass-not-real", merge=True)
    assert n == 1
    assert "a" in v2.entries
