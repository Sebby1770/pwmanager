"""Tests for CSV import (fake data only)."""

from __future__ import annotations

from pwmanager.importers import detect_format, merge_entries, parse_csv_rows
from pwmanager.models import Entry


BITWARDEN_CSV = """name,login_username,login_password,login_uri,notes,login_totp
GitHub,user@ex.com,gh-pass-fake,https://github.com,dev notes,JBSWY3DPEHPK3PXP
Work,work@ex.com,work-pass-fake,https://work.example,,
"""

CHROME_CSV = """name,url,username,password
Google,https://accounts.google.com,me@gmail.com,chrome-pass-fake
"""

GENERIC_CSV = """title,username,password,url,notes,totp
Forum,bob,forum-pass,https://forum.example,hello,
"""


def test_detect_bitwarden():
    assert detect_format(["name", "login_username", "login_password", "login_uri"]) == "bitwarden"


def test_detect_chrome():
    assert detect_format(["name", "url", "username", "password"]) == "chrome"


def test_parse_bitwarden():
    rows = parse_csv_rows(BITWARDEN_CSV, fmt="auto")
    assert len(rows) == 2
    name, e = rows[0]
    assert name == "GitHub"
    assert e.username == "user@ex.com"
    assert e.password == "gh-pass-fake"
    assert e.url == "https://github.com"
    assert e.totp_secret == "JBSWY3DPEHPK3PXP"
    assert "imported" in e.tags


def test_parse_chrome():
    rows = parse_csv_rows(CHROME_CSV, fmt="chrome")
    assert len(rows) == 1
    assert rows[0][0] == "Google"
    assert rows[0][1].password == "chrome-pass-fake"


def test_parse_generic():
    rows = parse_csv_rows(GENERIC_CSV, fmt="generic")
    assert rows[0][0] == "Forum"
    assert rows[0][1].notes == "hello"


def test_merge_skip_and_overwrite():
    vault = {
        "GitHub": Entry(username="old", password="old-pass"),
    }
    imported = parse_csv_rows(BITWARDEN_CSV, fmt="bitwarden")

    added, overwritten, skipped = merge_entries(vault, imported, on_conflict="skip")
    assert skipped == 1
    assert added == 1
    assert vault["GitHub"].username == "old"

    vault2 = {"GitHub": Entry(username="old", password="old-pass")}
    added, overwritten, skipped = merge_entries(vault2, imported, on_conflict="overwrite")
    assert overwritten == 1
    assert added == 1
    assert vault2["GitHub"].username == "user@ex.com"
