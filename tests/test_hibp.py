"""Tests for HIBP k-anonymity client (mocked network)."""

from __future__ import annotations

import urllib.error

from pwmanager.audit import audit_vault, format_audit_report
from pwmanager.hibp import (
    check_password_hibp,
    check_vault_hibp,
    sha1_hex,
)
from pwmanager.models import Entry
from pwmanager.vault import Vault


def _vault(tmp_path, entries: dict) -> Vault:
    path = tmp_path / "vault.json"
    v = Vault(str(path))
    v.create("test-master-pw-not-real!!", kdf="pbkdf2")
    for name, e in entries.items():
        v.entries[name] = e
    v.save()
    return v


def test_sha1_hex_known():
    # SHA-1("password") = 5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8
    assert sha1_hex("password") == "5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8"


def test_check_password_breached_via_mock():
    digest = sha1_hex("password")
    suffix = digest[5:]

    def opener(url, timeout):
        assert "/range/" in url
        assert digest[:5] in url.upper() or digest[:5] in url
        # Include the matching suffix with a high count + a decoy
        return f"{suffix}:12345\nAABBCCDDEEFF00112233445566778899AABBCCDD:1\n"

    result = check_password_hibp("password", opener=opener)
    assert result.skipped is False
    assert result.breached is True
    assert result.count == 12345


def test_check_password_clean_via_mock():
    def opener(url, timeout):
        return "DEADBEEFDEADBEEFDEADBEEFDEADBEEFDEADBEEF:3\n"

    result = check_password_hibp("unique-clean-password-xyz", opener=opener)
    assert result.skipped is False
    assert result.breached is False
    assert result.count == 0


def test_check_password_offline():
    def opener(url, timeout):
        raise urllib.error.URLError("network down")

    result = check_password_hibp("anything", opener=opener)
    assert result.skipped is True
    assert result.breached is False
    assert "network" in result.skip_reason.lower() or "URLError" in result.skip_reason


def test_vault_hibp_reports_names_only(tmp_path):
    secret_pw = "breached-fake-password-!!"
    clean_pw = "totally-unique-clean-zz99"
    digest = sha1_hex(secret_pw)
    suffix = digest[5:]

    def opener(url, timeout):
        prefix = url.rsplit("/", 1)[-1].upper()
        if prefix == digest[:5]:
            return f"{suffix}:99\n"
        return "0000000000000000000000000000000000000000:1\n"

    v = _vault(
        tmp_path,
        {
            "bad-site": Entry(username="u", password=secret_pw),
            "good-site": Entry(username="u", password=clean_pw),
            "memo": Entry(kind="note", notes="secret memo", password=""),
        },
    )
    report = check_vault_hibp(v, opener=opener)
    assert "bad-site" in report.breached_names
    assert "good-site" not in report.breached_names
    assert "memo" not in report.breached_names
    assert report.clean_count >= 1
    assert report.skipped is False
    # Never include password material in name list
    assert secret_pw not in report.breached_names


def test_vault_hibp_offline_skips(tmp_path):
    def opener(url, timeout):
        raise TimeoutError("timed out")

    v = _vault(
        tmp_path,
        {"x": Entry(username="u", password="some-pass-12345")},
    )
    report = check_vault_hibp(v, opener=opener)
    assert report.skipped is True
    assert report.breached_names == []


def test_audit_with_hibp_integration(tmp_path):
    pw = "pwned-test-pass"
    digest = sha1_hex(pw)
    suffix = digest[5:]

    def opener(url, timeout):
        return f"{suffix}:7\n"

    v = _vault(tmp_path, {"leaked": Entry(username="u", password=pw)})
    report = audit_vault(v, check_hibp=True, hibp_opener=opener)
    assert "leaked" in report.hibp_breached
    text = format_audit_report(report)
    assert "leaked" in text
    assert pw not in text
    assert "HIBP" in text
