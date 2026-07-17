"""Tests for vault stats()."""

from __future__ import annotations

import time

from pwmanager.models import Entry
from pwmanager.vault import Vault

MASTER = "test-master-pw-not-real!!"


def test_stats_structure(tmp_path):
    path = tmp_path / "vault.json"
    v = Vault(str(path))
    v.create(MASTER, kdf="pbkdf2")

    old = time.time() - 1000
    new = time.time()
    v.add(
        "old-entry",
        Entry(
            username="a",
            password="Str0ng!Passw0rd#Aa",
            tags=["work"],
            updated_at=old,
            created_at=old,
        ),
    )
    v.add(
        "new-entry",
        Entry(
            username="b",
            password="Str0ng!Passw0rd#Bb",
            tags=["work", "cloud"],
            totp_secret="JBSWY3DPEHPK3PXP",
            favorite=True,
            updated_at=new,
            created_at=new,
        ),
    )

    s = v.stats()
    assert s["total_entries"] == 2
    assert s["logins"] == 2
    assert s["notes"] == 0
    assert s["favorites"] == 1
    assert s["with_totp"] == 1
    assert s["without_totp"] == 1
    assert isinstance(s["tags"], dict)
    assert s["tags"]["work"] == 2
    assert s["tags"]["cloud"] == 1
    assert s["oldest_updated"]["name"] == "old-entry"
    assert s["newest_updated"]["name"] == "new-entry"
    assert 0 <= s["health_score"] <= 100
    assert isinstance(s["health_score"], int)


def test_stats_empty_vault(tmp_path):
    path = tmp_path / "vault.json"
    v = Vault(str(path))
    v.create(MASTER, kdf="pbkdf2")
    s = v.stats()
    assert s["total_entries"] == 0
    assert s["favorites"] == 0
    assert s["with_totp"] == 0
    assert s["tags"] == {}
    assert s["oldest_updated"] is None
    assert s["newest_updated"] is None
    assert s["health_score"] == 100
