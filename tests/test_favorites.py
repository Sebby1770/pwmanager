"""Tests for pin / favorite entries."""

from __future__ import annotations

from pwmanager.models import Entry
from pwmanager.vault import Vault

MASTER = "test-master-pw-not-real!!"


def test_favorite_default_false_and_from_dict_compat(tmp_path):
    # Old entries without favorite key
    e = Entry.from_dict({"username": "u", "password": "p"})
    assert e.favorite is False
    e2 = Entry.from_dict({"username": "u", "password": "p", "favorite": True})
    assert e2.favorite is True


def test_pin_unpin_roundtrip(tmp_path):
    path = tmp_path / "vault.json"
    v = Vault(str(path))
    v.create(MASTER, kdf="pbkdf2")
    v.add("alpha", Entry(username="a", password="fake-Aa1!xxxx"))
    v.add("beta", Entry(username="b", password="fake-Bb2!yyyy"))

    assert v.favorites() == []
    v.pin("beta")
    assert v.entries["beta"].favorite is True
    assert v.favorites() == ["beta"]

    v.lock()
    v2 = Vault(str(path))
    v2.unlock(MASTER)
    assert v2.entries["beta"].favorite is True
    assert v2.entries["alpha"].favorite is False

    v2.unpin("beta")
    assert v2.entries["beta"].favorite is False
    assert v2.favorites() == []

    v2.lock()
    v3 = Vault(str(path))
    v3.unlock(MASTER)
    assert v3.entries["beta"].favorite is False


def test_sorted_entry_names_favorites_first(tmp_path):
    path = tmp_path / "vault.json"
    v = Vault(str(path))
    v.create(MASTER, kdf="pbkdf2")
    v.add("zebra", Entry(username="z", password="p1-fake-Aa!"))
    v.add("apple", Entry(username="a", password="p2-fake-Bb!"))
    v.add("mango", Entry(username="m", password="p3-fake-Cc!", favorite=True))
    names = v.sorted_entry_names()
    assert names[0] == "mango"
    assert set(names[1:]) == {"apple", "zebra"}


def test_search_ranks_favorites_first(tmp_path):
    path = tmp_path / "vault.json"
    v = Vault(str(path))
    v.create(MASTER, kdf="pbkdf2")
    v.add("work-a", Entry(username="a", password="p1", tags=["work"]))
    v.add("work-b", Entry(username="b", password="p2", tags=["work"], favorite=True))
    results = v.search("work")
    assert results[0] == "work-b"
