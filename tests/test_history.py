"""Tests for password history list / model."""

from __future__ import annotations

import time

from pwmanager.models import Entry
from pwmanager.vault import Vault


def test_history_list_on_entry(tmp_path):
    path = tmp_path / "vault.json"
    v = Vault(str(path))
    v.create("test-master-pw-not-real!!", kdf="pbkdf2")

    e = Entry(username="u", password="current-pw")
    e.history = [
        {"password": "old-one", "changed_at": 1_000_000.0},
        {"password": "old-two", "changed_at": 2_000_000.0},
    ]
    v.add("site", e)
    v.lock()

    v2 = Vault(str(path))
    v2.unlock("test-master-pw-not-real!!")
    hist = v2.entries["site"].history
    assert len(hist) == 2
    assert hist[0]["password"] == "old-one"
    assert hist[1]["password"] == "old-two"
    assert hist[0]["changed_at"] == 1_000_000.0


def test_history_restore_logic(tmp_path):
    """Simulate restore: push current to history, set previous password."""
    path = tmp_path / "vault.json"
    v = Vault(str(path))
    v.create("test-master-pw-not-real!!", kdf="pbkdf2")
    e = Entry(
        username="u",
        password="now",
        history=[{"password": "prev", "changed_at": time.time() - 100}],
    )
    v.add("acct", e)

    entry = v.entries["acct"]
    old = entry.history[0]
    entry.history.append({"password": entry.password, "changed_at": time.time()})
    entry.history = entry.history[-10:]
    entry.password = old["password"]
    entry.updated_at = time.time()
    v.save()

    v.lock()
    v2 = Vault(str(path))
    v2.unlock("test-master-pw-not-real!!")
    assert v2.entries["acct"].password == "prev"
    assert any(h["password"] == "now" for h in v2.entries["acct"].history)


def test_empty_history():
    e = Entry(username="u", password="p")
    assert e.history == []
