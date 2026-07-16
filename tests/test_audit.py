"""Tests for vault security audit (fake data only)."""

from __future__ import annotations

import time

from pwmanager.audit import audit_vault, compute_health_score, format_audit_report
from pwmanager.models import Entry
from pwmanager.vault import Vault


def _unlocked_vault(tmp_path, entries: dict) -> Vault:
    path = tmp_path / "vault.json"
    v = Vault(str(path))
    v.create("test-master-pw-not-real!!", kdf="pbkdf2")
    for name, e in entries.items():
        v.entries[name] = e
    v.save()
    return v


def test_audit_detects_reused_passwords(tmp_path):
    shared = "SameFakePassword1!"
    v = _unlocked_vault(
        tmp_path,
        {
            "site-a": Entry(
                username="a",
                password=shared,
                updated_at=time.time(),
            ),
            "site-b": Entry(
                username="b",
                password=shared,
                updated_at=time.time(),
            ),
            "site-c": Entry(
                username="c",
                password="UniqueOtherPass99!",
                updated_at=time.time(),
            ),
        },
    )
    report = audit_vault(v)
    assert report.reused_count == 2
    assert len(report.reused_groups) == 1
    assert set(report.reused_groups[0]) == {"site-a", "site-b"}
    # Report must never include actual password values
    text = format_audit_report(report)
    assert shared not in text
    assert "UniqueOtherPass99!" not in text


def test_audit_detects_weak_and_empty_username(tmp_path):
    v = _unlocked_vault(
        tmp_path,
        {
            "weak": Entry(username="u", password="abc", updated_at=time.time()),
            "no-user": Entry(username="", password="Str0ng!Passw0rd#Zz", updated_at=time.time()),
        },
    )
    report = audit_vault(v)
    assert "weak" in report.weak
    assert "no-user" in report.empty_usernames


def test_audit_detects_old_and_missing_totp(tmp_path):
    old_ts = time.time() - (400 * 24 * 3600)
    v = _unlocked_vault(
        tmp_path,
        {
            "ancient": Entry(
                username="u",
                password="Str0ng!Passw0rd#Aa",
                updated_at=old_ts,
                created_at=old_ts,
            ),
            "web-no-2fa": Entry(
                username="u",
                password="Str0ng!Passw0rd#Bb",
                url="https://example.com",
                totp_secret="",
                updated_at=time.time(),
            ),
            "web-with-2fa": Entry(
                username="u",
                password="Str0ng!Passw0rd#Cc",
                url="https://secure.example.com",
                totp_secret="JBSWY3DPEHPK3PXP",
                updated_at=time.time(),
            ),
        },
    )
    report = audit_vault(v)
    assert "ancient" in report.old
    assert "web-no-2fa" in report.missing_totp
    assert "web-with-2fa" not in report.missing_totp


def test_health_score_perfect_and_degraded():
    from pwmanager.audit import AuditReport

    perfect = AuditReport(total_entries=5)
    assert compute_health_score(perfect) == 100

    bad = AuditReport(
        total_entries=2,
        reused_groups=[["a", "b"]],
        weak=["a", "b"],
        old=["a"],
        missing_totp=["a"],
        empty_usernames=["b"],
    )
    score = compute_health_score(bad)
    assert 0 <= score < 100


def test_empty_vault_audit(tmp_path):
    v = _unlocked_vault(tmp_path, {})
    report = audit_vault(v)
    assert report.total_entries == 0
    assert report.health_score == 100
    assert report.issue_count == 0
