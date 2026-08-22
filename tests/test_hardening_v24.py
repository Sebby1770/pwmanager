"""Tests for the 2.4 hardening: enforced integrity, file mode, entropy model."""

from __future__ import annotations

import base64
import json
import math
import os
import stat
import sys

import pytest
from cryptography.fernet import InvalidToken

from pwmanager.crypto import (
    derive_key,
    file_hmac,
    legacy_file_hmac,
    verify_file_hmac,
)
from pwmanager.generators import (
    generate_passphrase,
    get_wordlist,
    passphrase_entropy_bits,
    password_entropy_bits,
)
from pwmanager.constants import SYMBOLS
from pwmanager.models import Entry
from pwmanager.vault import VAULT_FILE_MODE, Vault, VaultIntegrityError

MASTER = "test-master-pw-not-real!!"


def make_vault(tmp_path, name="vault.json"):
    path = tmp_path / name
    v = Vault(str(path))
    v.create(MASTER, kdf="pbkdf2")
    return v, path


def read_payload(path):
    return json.loads(path.read_text(encoding="utf-8"))


def write_payload(path, payload):
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")


# --------------------------------------------------------------- integrity --


def test_tampering_with_an_authenticated_field_is_rejected(tmp_path):
    """Editing the KDF field used to surface as a confusing wrong-password error."""
    v, path = make_vault(tmp_path)
    v.add("a", Entry(username="u", password="p-fake-Aa1!"))
    v.lock()

    payload = read_payload(path)
    payload["version"] = 99  # authenticated but not encrypted
    write_payload(path, payload)

    v2 = Vault(str(path))
    with pytest.raises(VaultIntegrityError) as excinfo:
        v2.unlock(MASTER)
    assert "modified outside pwmanager" in str(excinfo.value)


def test_tampering_with_the_hmac_itself_is_rejected(tmp_path):
    v, path = make_vault(tmp_path)
    v.lock()

    payload = read_payload(path)
    payload["hmac"] = "0" * 64
    write_payload(path, payload)

    with pytest.raises(VaultIntegrityError):
        Vault(str(path)).unlock(MASTER)


def test_a_wrong_password_is_still_reported_as_a_wrong_password(tmp_path):
    """The integrity check must not mask the ordinary typo case."""
    v, path = make_vault(tmp_path)
    v.lock()

    with pytest.raises(InvalidToken):
        Vault(str(path)).unlock("definitely-not-the-master-pw")


def test_legacy_hmac_vaults_still_open_and_are_upgraded(tmp_path):
    """Vaults written before 2.4 signed only salt+ciphertext."""
    v, path = make_vault(tmp_path)
    v.lock()

    payload = read_payload(path)
    salt = base64.b64decode(payload["salt"])
    key, _ = derive_key(MASTER, salt, "pbkdf2")
    payload["hmac"] = legacy_file_hmac(payload, key)
    write_payload(path, payload)

    v2 = Vault(str(path))
    v2.unlock(MASTER)  # legacy MAC accepted
    assert v2.entries == {}

    v2.add("upgraded", Entry(username="u", password="p-fake-Aa1!"))
    upgraded = read_payload(path)
    assert upgraded["hmac"] == file_hmac(upgraded, v2.key)
    assert upgraded["hmac"] != legacy_file_hmac(upgraded, v2.key)


def test_file_hmac_covers_version_and_kdf(tmp_path):
    key = derive_key(MASTER, b"0123456789abcdef", "pbkdf2")[0]
    base = {"version": 2, "kdf": "pbkdf2", "salt": "c2FsdA==", "vault": "ciphertext"}
    baseline = file_hmac(base, key)

    for field, value in (("version", 3), ("kdf", "argon2id"), ("salt", "b3RoZXI=")):
        changed = dict(base, **{field: value})
        assert file_hmac(changed, key) != baseline, f"{field} is not authenticated"


def test_verify_file_hmac_rejects_a_missing_or_wrong_mac():
    key = derive_key(MASTER, b"0123456789abcdef", "pbkdf2")[0]
    payload = {"version": 2, "kdf": "pbkdf2", "salt": "c2FsdA==", "vault": "ct"}
    assert verify_file_hmac(payload, key) is False  # no hmac field at all
    payload["hmac"] = "not-a-mac"
    assert verify_file_hmac(payload, key) is False
    payload["hmac"] = file_hmac(payload, key)
    assert verify_file_hmac(payload, key) is True


def test_verify_integrity_reports_tampering_without_unlocking(tmp_path):
    v, path = make_vault(tmp_path)
    assert v.verify_integrity()[0] is True

    payload = read_payload(path)
    payload["kdf"] = "argon2id"
    write_payload(path, payload)
    ok, message = v.verify_integrity()
    assert ok is False
    assert "HMAC mismatch" in message


# -------------------------------------------------------------- file modes --


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX permission bits")
def test_new_vaults_are_owner_only(tmp_path):
    v, path = make_vault(tmp_path)
    assert path.stat().st_mode & 0o777 == VAULT_FILE_MODE
    assert v.file_mode() == VAULT_FILE_MODE


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX permission bits")
def test_saving_keeps_the_vault_owner_only(tmp_path):
    v, path = make_vault(tmp_path)
    v.add("a", Entry(username="u", password="p-fake-Aa1!"))
    assert path.stat().st_mode & 0o777 == VAULT_FILE_MODE


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX permission bits")
def test_tighten_permissions_fixes_a_loose_legacy_vault(tmp_path):
    v, path = make_vault(tmp_path)
    os.chmod(path, 0o644)
    assert v.file_mode() == 0o644

    assert v.tighten_permissions() is True
    assert v.file_mode() == VAULT_FILE_MODE
    # Already tight: nothing to do, and it says so.
    assert v.tighten_permissions() is False


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX permission bits")
def test_the_temp_file_is_never_world_readable(tmp_path, monkeypatch):
    """The old code created the temp file under the process umask."""
    seen = {}
    v, path = make_vault(tmp_path)

    real_replace = os.replace

    def spy(src, dst):
        seen["mode"] = stat.S_IMODE(os.stat(src).st_mode)
        return real_replace(src, dst)

    monkeypatch.setattr(os, "replace", spy)
    monkeypatch.setattr("pwmanager.vault.os.replace", spy)
    v.add("a", Entry(username="u", password="p-fake-Aa1!"))
    assert seen["mode"] == VAULT_FILE_MODE


def test_no_temp_file_is_left_behind(tmp_path):
    v, path = make_vault(tmp_path)
    v.add("a", Entry(username="u", password="p-fake-Aa1!"))
    assert not (tmp_path / "vault.json.tmp").exists()


# ------------------------------------------------------------------- save ---


def test_save_refuses_to_overwrite_a_corrupt_vault_file(tmp_path):
    v, path = make_vault(tmp_path)
    v.add("a", Entry(username="u", password="p-fake-Aa1!"))
    path.write_text("{ not json", encoding="utf-8")

    with pytest.raises(RuntimeError, match="Refusing to overwrite"):
        v.save()
    # The damaged file is left exactly as found, for the user to restore.
    assert path.read_text(encoding="utf-8") == "{ not json"


def test_save_reports_a_missing_vault_file_clearly(tmp_path):
    v, path = make_vault(tmp_path)
    path.unlink()
    with pytest.raises(RuntimeError, match="disappeared"):
        v.save()


# ---------------------------------------------------------------- entropy ---


def test_passphrase_entropy_is_words_times_log2_listsize():
    assert passphrase_entropy_bits(5, 2048) == pytest.approx(55.0)
    assert passphrase_entropy_bits(0, 2048) == 0.0
    assert passphrase_entropy_bits(5, 1) == 0.0


def test_a_generated_passphrase_is_scored_by_words_not_characters():
    """The character-pool model overstated passphrases by ~3x."""
    words = get_wordlist()
    phrase = generate_passphrase(words=5, separator="-")
    expected = 5 * math.log2(len(words))

    assert password_entropy_bits(phrase) == pytest.approx(expected, rel=1e-9)
    # The old per-character model treated every letter as an independent
    # choice, which for a 30-odd character phrase claimed roughly triple.
    naive = len(phrase) * math.log2(26 + 32)
    assert password_entropy_bits(phrase) < naive / 2


def test_capitalised_passphrases_are_recognised_too():
    words = get_wordlist()
    phrase = generate_passphrase(words=6, separator=".", capitalize=True)
    expected = 6 * math.log2(len(words))
    assert password_entropy_bits(phrase) == pytest.approx(expected, rel=1e-9)


def test_random_passwords_keep_the_character_model():
    pw = "aB3!xY9$qW2@mN7#"
    pool = 26 + 26 + 10 + len(SYMBOLS)
    assert password_entropy_bits(pw) == pytest.approx(len(pw) * math.log2(pool))


def test_a_hyphenated_non_dictionary_password_is_not_downgraded():
    """Only recognisable wordlist phrases get the lower score."""
    pw = "Xk4-Qp9-Zr2-Vt7"
    pool = 26 + 26 + 10 + len(SYMBOLS)
    assert password_entropy_bits(pw) == pytest.approx(len(pw) * math.log2(pool))


def test_empty_password_is_zero_bits():
    assert password_entropy_bits("") == 0.0
