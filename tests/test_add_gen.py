"""Integration: add --gen creates entry with generated password."""

from __future__ import annotations

from pwmanager.cli import cmd_add
from pwmanager.models import Entry
from pwmanager.vault import Vault


def test_add_gen_creates_entry(tmp_path):
    path = tmp_path / "vault.json"
    v = Vault(str(path))
    v.create("test-master-pw-not-real!!", kdf="pbkdf2")

    cmd_add(
        v,
        "github",
        gen=True,
        length=24,
        username="me@example.com",
        non_interactive=True,
    )

    assert "github" in v.entries
    e = v.entries["github"]
    assert e.username == "me@example.com"
    assert len(e.password) == 24
    assert e.kind == "login"

    # Persist and reload
    v.lock()
    v2 = Vault(str(path))
    v2.unlock("test-master-pw-not-real!!")
    assert len(v2.entries["github"].password) == 24


def test_add_note_noninteractive(tmp_path):
    path = tmp_path / "vault.json"
    v = Vault(str(path))
    v.create("test-master-pw-not-real!!", kdf="pbkdf2")

    cmd_add(
        v,
        "passport",
        as_note=True,
        notes="P1234567 expires 2030",
        non_interactive=True,
    )
    assert v.entries["passport"].is_note()
    assert "P1234567" in v.entries["passport"].notes


def test_add_gen_no_symbols(tmp_path):
    path = tmp_path / "vault.json"
    v = Vault(str(path))
    v.create("test-master-pw-not-real!!", kdf="pbkdf2")
    cmd_add(v, "plain", gen=True, length=16, no_symbols=True, non_interactive=True)
    pw = v.entries["plain"].password
    assert len(pw) == 16
    # Should be alphanumeric only when no_symbols
    assert pw.isalnum()
