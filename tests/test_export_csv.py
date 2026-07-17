"""Tests for plaintext CSV export."""

from __future__ import annotations

import csv
from pathlib import Path

from pwmanager.models import Entry
from pwmanager.vault import Vault

MASTER = "test-master-pw-not-real!!"


def test_export_csv_headers_and_rows(tmp_path):
    path = tmp_path / "vault.json"
    out = tmp_path / "out.csv"
    v = Vault(str(path))
    v.create(MASTER, kdf="pbkdf2")
    v.add(
        "site1",
        Entry(
            username="alice",
            password="secret-Aa1!",
            url="https://example.com",
            notes="hello",
            tags=["work", "web"],
            totp_secret="JBSWY3DPEHPK3PXP",
            favorite=True,
        ),
    )
    v.add(
        "site2",
        Entry(username="bob", password="other-Bb2!", tags=["personal"]),
    )

    n = v.export_csv(str(out))
    assert n == 2
    assert out.is_file()

    with open(out, newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        assert reader.fieldnames == [
            "name",
            "username",
            "password",
            "url",
            "notes",
            "tags",
            "totp_secret",
            "favorite",
            "kind",
        ]
        rows = list(reader)

    names = {r["name"] for r in rows}
    assert names == {"site1", "site2"}
    # favorites first
    assert rows[0]["name"] == "site1"
    assert rows[0]["password"] == "secret-Aa1!"
    assert rows[0]["totp_secret"] == "JBSWY3DPEHPK3PXP"
    assert rows[0]["favorite"] == "true"
    assert rows[0]["kind"] == "login"
    assert "work" in rows[0]["tags"]
    assert rows[1]["favorite"] == "false"
