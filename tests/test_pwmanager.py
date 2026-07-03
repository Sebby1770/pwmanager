"""Test suite for pwmanager.

Covers the crypto round-trip, both storage backends, the (now enforced)
integrity check, password/passphrase generation, entropy scoring, and TOTP.
No secrets are printed; temporary vaults live in pytest's tmp_path.
"""

import base64
import json
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pwmanager as pw  # noqa: E402


# ----------------------------- crypto -----------------------------

def test_derive_key_is_deterministic():
    salt = pw.generate_salt()
    k1, kdf1 = pw.derive_key("correct horse battery staple", salt)
    k2, kdf2 = pw.derive_key("correct horse battery staple", salt)
    assert k1 == k2
    assert kdf1 == kdf2


def test_derive_key_changes_with_salt():
    k1, _ = pw.derive_key("pw", pw.generate_salt())
    k2, _ = pw.derive_key("pw", pw.generate_salt())
    assert k1 != k2


def test_encrypt_decrypt_roundtrip():
    key, _ = pw.derive_key("hunter2hunter2", pw.generate_salt())
    token = pw.encrypt_bytes(b"top secret", key)
    assert token != b"top secret"
    assert pw.decrypt_bytes(token, key) == b"top secret"


# ----------------------------- generators -----------------------------

def test_generate_password_length_and_classes():
    p = pw.generate_password(length=24, use_upper=True, use_digits=True, use_symbols=True)
    assert len(p) == 24
    assert any(c.islower() for c in p)
    assert any(c.isupper() for c in p)
    assert any(c.isdigit() for c in p)
    assert any(c in pw.SYMBOLS for c in p)


def test_generate_password_rejects_short():
    with pytest.raises(ValueError):
        pw.generate_password(length=2)


def test_avoid_ambiguous_excludes_lookalikes():
    for _ in range(20):
        p = pw.generate_password(length=40, avoid_ambiguous=True)
        assert not (set(p) & set("Il1O0o"))


def test_passphrase_word_count():
    phrase = pw.generate_passphrase(words=6, separator="-")
    assert len(phrase.split("-")) == 6


def test_entropy_monotonic_with_length():
    short = pw.password_entropy_bits("abcd")
    longer = pw.password_entropy_bits("abcdabcdabcd")
    assert longer > short


# ----------------------------- TOTP -----------------------------

def test_totp_matches_rfc6238_vector(monkeypatch):
    # RFC 6238 test secret "12345678901234567890" (ASCII) in base32,
    # at Unix time 59 the 8-digit TOTP is 94287082 (SHA-1).
    secret_b32 = base64.b32encode(b"12345678901234567890").decode()
    monkeypatch.setattr(pw.time, "time", lambda: 59)
    assert pw.totp_now(secret_b32, digits=8, period=30) == "94287082"


def test_totp_rejects_bad_secret():
    with pytest.raises(ValueError):
        pw.totp_now("not base32 @@@")


# ----------------------------- storage backends -----------------------------

@pytest.mark.parametrize("backend", ["json", "sqlite"])
def test_vault_create_unlock_roundtrip(tmp_path, backend):
    ext = "db" if backend == "sqlite" else "json"
    path = str(tmp_path / f"vault.{ext}")
    v = pw.Vault(path, backend=backend)
    assert not v.exists()
    v.create("a-strong-master-pw")
    e = pw.Entry(username="me@example.com", password="s3cr3t", url="https://x")
    v.add("github", e)
    v.lock()
    assert v.key is None

    v2 = pw.Vault(path, backend=backend)
    v2.unlock("a-strong-master-pw")
    assert "github" in v2.entries
    assert v2.entries["github"].password == "s3cr3t"
    assert v2.entries["github"].username == "me@example.com"


@pytest.mark.parametrize("backend", ["json", "sqlite"])
def test_wrong_password_raises(tmp_path, backend):
    ext = "db" if backend == "sqlite" else "json"
    path = str(tmp_path / f"vault.{ext}")
    v = pw.Vault(path, backend=backend)
    v.create("the-right-password")
    v.lock()
    with pytest.raises(pw.InvalidToken):
        pw.Vault(path, backend=backend).unlock("the-WRONG-password")


def test_vault_file_is_owner_only(tmp_path):
    path = str(tmp_path / "vault.json")
    v = pw.Vault(path, backend="json")
    v.create("a-strong-master-pw")
    mode = os.stat(path).st_mode & 0o777
    assert mode == 0o600


# ----------------------------- integrity (the bug fix) -----------------------------

def test_tampering_is_detected(tmp_path):
    """Flipping a byte of the JSON envelope must make unlock refuse — this is
    the behaviour the pre-2.0 code silently skipped (`pass`)."""
    path = str(tmp_path / "vault.json")
    v = pw.Vault(path, backend="json")
    v.create("a-strong-master-pw")
    v.add("bank", pw.Entry(username="acct", password="p"))
    v.lock()

    payload = json.loads(open(path).read())
    # Tamper with the (authenticated) salt field but keep it valid base64.
    raw = bytearray(base64.b64decode(payload["salt"]))
    raw[0] ^= 0x01
    payload["salt"] = base64.b64encode(bytes(raw)).decode()
    open(path, "w").write(json.dumps(payload))

    # Wrong salt -> wrong key -> Fernet InvalidToken (still refused, not opened).
    with pytest.raises((pw.IntegrityError, pw.InvalidToken)):
        pw.Vault(path, backend="json").unlock("a-strong-master-pw")


def test_hmac_mismatch_on_intact_ciphertext_raises(tmp_path):
    """If the ciphertext still decrypts (key correct) but the stored HMAC was
    swapped, unlock must raise IntegrityError rather than returning entries."""
    path = str(tmp_path / "vault.json")
    v = pw.Vault(path, backend="json")
    v.create("a-strong-master-pw")
    v.lock()

    payload = json.loads(open(path).read())
    payload["hmac"] = "0" * len(payload["hmac"])  # valid shape, wrong value
    open(path, "w").write(json.dumps(payload))

    with pytest.raises(pw.IntegrityError):
        pw.Vault(path, backend="json").unlock("a-strong-master-pw")


# ----------------------------- export / import -----------------------------

def test_encrypted_export_import_roundtrip(tmp_path):
    path = str(tmp_path / "vault.json")
    v = pw.Vault(path, backend="json")
    v.create("master-password-1")
    v.add("spotify", pw.Entry(username="u", password="pw123"))

    export = str(tmp_path / "backup.json")
    v.export_encrypted(export, "export-password")

    dest = pw.Vault(str(tmp_path / "vault2.json"), backend="json")
    dest.create("master-password-2")
    n = dest.import_encrypted(export, "export-password", merge=True)
    assert n == 1
    assert dest.entries["spotify"].password == "pw123"


# ----------------------------- persistent lockout -----------------------------

def test_throttle_allows_until_max_failures(tmp_path):
    t = pw.Throttle(str(tmp_path / "v.json"))
    assert t.seconds_remaining() == 0
    for _ in range(pw.MAX_UNLOCK_ATTEMPTS - 1):
        t.record_failure()
    assert t.seconds_remaining() == 0  # still under the limit


def test_throttle_locks_after_max_failures_and_persists(tmp_path):
    path = str(tmp_path / "v.json")
    t = pw.Throttle(path)
    for _ in range(pw.MAX_UNLOCK_ATTEMPTS):
        t.record_failure()
    wait = t.seconds_remaining()
    assert 0 < wait <= pw.LOCKOUT_BASE_SECONDS
    # A brand-new instance (fresh process) sees the same lockout — that's the fix.
    assert pw.Throttle(path).seconds_remaining() == wait
    # The sidecar is owner-only.
    assert os.stat(path + ".throttle").st_mode & 0o777 == 0o600


def test_throttle_backoff_doubles_and_reset_clears(tmp_path):
    t = pw.Throttle(str(tmp_path / "v.json"))
    for _ in range(pw.MAX_UNLOCK_ATTEMPTS):
        t.record_failure()
    first = t.seconds_remaining()
    t.record_failure()
    assert t.seconds_remaining() > first  # exponential growth
    t.reset()
    assert t.seconds_remaining() == 0


# ----------------------------- audit -----------------------------

def test_analyze_entries_flags_reuse_weak_and_stale():
    year_and_a_bit = pw.time.time() - 400 * 86400
    entries = {
        "github": pw.Entry(password="Sup3r-Long-Unique-Passw0rd!x"),
        "gitlab": pw.Entry(password="shared-secret-pw-123"),
        "bitbucket": pw.Entry(password="shared-secret-pw-123"),
        "oldsite": pw.Entry(password="An0ther-Unique-Passw0rd!zz", updated_at=year_and_a_bit),
        "weakone": pw.Entry(password="abc"),
    }
    findings = pw.analyze_entries(entries)
    assert findings["reused"] == [["bitbucket", "gitlab"]]
    assert "weakone" in findings["weak"]
    assert "github" not in findings["weak"]
    assert findings["stale"] == ["oldsite"]


def test_hibp_sends_only_five_char_prefix_and_parses_count():
    import hashlib as _hashlib

    password = "password123"
    digest = _hashlib.sha1(password.encode()).hexdigest().upper()
    seen = {}

    def fake_fetch(prefix):
        seen["prefix"] = prefix
        return f"0018A45C4D1DEF81644B54AB7F969B88D65:3\n{digest[5:]}:42\n"

    assert pw.hibp_breach_count(password, fetch=fake_fetch) == 42
    assert seen["prefix"] == digest[:5]
    assert len(seen["prefix"]) == 5  # k-anonymity: only the prefix leaves


def test_hibp_returns_zero_when_absent():
    assert pw.hibp_breach_count("uncrackable", fetch=lambda p: "AAAA:1\nBBBB:2\n") == 0


def test_search_finds_by_tag_and_name(tmp_path):
    path = str(tmp_path / "vault.json")
    v = pw.Vault(path, backend="json")
    v.create("master-password-1")
    v.add("github", pw.Entry(username="dev", tags=["work", "code"]))
    v.add("netflix", pw.Entry(username="me", tags=["home"]))
    assert v.search("work") == ["github"]
    assert v.search("net") == ["netflix"]
