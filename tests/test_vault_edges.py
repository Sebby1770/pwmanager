"""Failure paths of pwmanager.vault that must stay safe (no silent overwrite, no data loss)."""

from __future__ import annotations

import base64
import json
import os
import runpy

import pytest

import pwmanager.crypto as pcrypto
from pwmanager.constants import CIPHER_FERNET
from pwmanager.models import Entry
from pwmanager.vault import Vault, VaultIntegrityError

PW = "edge case master password"


@pytest.fixture(autouse=True)
def fast_kdf(monkeypatch):
    monkeypatch.setattr(pcrypto, "PBKDF2_ITERATIONS", 1_000)


@pytest.fixture
def vault(tmp_path):
    v = Vault(str(tmp_path / "v.json"))
    v.create(PW, kdf="pbkdf2")
    v.add("a", Entry(password="pa"))
    return v


def test_save_refuses_when_file_vanished_or_corrupt(vault):
    os.unlink(vault.path)
    with pytest.raises(RuntimeError, match="disappeared"):
        vault.save()
    with open(vault.path, "w") as f:
        f.write("{not json")
    with pytest.raises(RuntimeError, match="unreadable"):
        vault.save()
    with open(vault.path, "w") as f:
        json.dump({"vault": "x"}, f)
    with pytest.raises(RuntimeError, match="missing its salt"):
        vault.save()


def test_locked_vault_operations(tmp_path):
    v = Vault(str(tmp_path / "none.json"))
    with pytest.raises(RuntimeError):
        v.save()
    with pytest.raises(RuntimeError):
        v.change_master("x" * 12)
    assert v.verify_integrity() == (False, "Vault is locked")
    with pytest.raises(FileNotFoundError):
        v.unlock(PW)
    assert v.file_mode() is None and v.tighten_permissions() is False


def test_unlock_rejects_malformed_files(tmp_path):
    path = tmp_path / "bad.json"
    path.write_text("{oops")
    with pytest.raises(ValueError, match="not valid JSON"):
        Vault(str(path)).unlock(PW)
    path.write_text(json.dumps({"kdf": "pbkdf2"}))
    with pytest.raises(ValueError, match="missing field"):
        Vault(str(path)).unlock(PW)


def test_inner_payload_must_be_an_object(vault):
    payload = json.load(open(vault.path))
    key = vault.key
    payload["vault"] = pcrypto.encrypt_bytes(b"[1, 2]", key).decode()
    payload["hmac"] = pcrypto.file_hmac(payload, key)
    json.dump(payload, open(vault.path, "w"))
    with pytest.raises(ValueError, match="not a JSON object"):
        Vault(vault.path).unlock(PW)


def test_legacy_flat_inner_format_and_fernet(tmp_path):
    salt = os.urandom(16)
    key, _ = pcrypto.derive_key(PW, salt, "pbkdf2")
    inner = json.dumps({"old": Entry(password="legacy").to_dict()}).encode()
    payload = {"version": 1, "kdf": "pbkdf2", "salt": base64.b64encode(salt).decode(),
               "vault": pcrypto.encrypt_bytes(inner, key, CIPHER_FERNET).decode()}
    payload["hmac"] = pcrypto.legacy_file_hmac(payload, key)
    path = tmp_path / "legacy.json"
    path.write_text(json.dumps(payload))
    v = Vault(str(path))
    v.unlock(PW)
    assert v.cipher == CIPHER_FERNET and v.entries["old"].password == "legacy"
    v.save()
    upgraded = json.loads(path.read_text())
    assert upgraded["cipher"] == "aes256gcm" and upgraded["version"] == 3


def test_change_master_rekeys(vault):
    vault.change_master("a brand new master password", kdf="pbkdf2")
    with pytest.raises(pcrypto.InvalidToken):
        Vault(vault.path).unlock(PW)
    w = Vault(vault.path)
    w.unlock("a brand new master password")
    assert w.entries["a"].password == "pa"


def test_failed_write_leaves_no_temp_file(vault, monkeypatch):
    def boom(*a, **k):
        raise OSError("disk full")

    monkeypatch.setattr(os, "fsync", boom)
    with pytest.raises(OSError):
        vault.save()
    assert not os.path.exists(vault.path + ".tmp")


def test_permissions_tightened(vault):
    os.chmod(vault.path, 0o644)
    assert vault.tighten_permissions() is True
    assert vault.file_mode() == 0o600
    assert vault.tighten_permissions() is False


def test_entry_ops_on_missing_names(vault):
    for op in (vault.pin, vault.unpin, vault.touch_entry, vault.mark_accessed):
        with pytest.raises(KeyError):
            op("missing")
    with pytest.raises(KeyError):
        vault.rename("missing", "b")
    vault.add("b", Entry())
    with pytest.raises(ValueError):
        vault.rename("a", "b")
    assert vault.undelete() is None
    vault.delete("a")
    vault.add("a", Entry())
    assert vault.undelete() is None  # name taken again: refuse rather than clobber


def test_verify_integrity_reports_each_problem(vault):
    assert vault.verify_integrity()[0] is True
    payload = json.load(open(vault.path))

    def write(p):
        json.dump(p, open(vault.path, "w"))

    write({k: v for k, v in payload.items() if k != "hmac"})
    assert "no HMAC" in vault.verify_integrity()[1]
    write({k: v for k, v in payload.items() if k != "salt"})
    assert "missing salt" in vault.verify_integrity()[1]
    write({**payload, "hmac": "0" * 64})
    assert "HMAC mismatch" in vault.verify_integrity()[1]
    open(vault.path, "w").write("{")
    assert "Cannot read" in vault.verify_integrity()[1]
    os.unlink(vault.path)
    assert "not found" in vault.verify_integrity()[1]


def test_verify_integrity_detects_undecryptable_ciphertext(vault):
    payload = json.load(open(vault.path))
    payload["vault"] = pcrypto.encrypt_bytes(b"{}", base64.urlsafe_b64encode(os.urandom(32))).decode()
    payload["hmac"] = pcrypto.file_hmac(payload, vault.key)
    json.dump(payload, open(vault.path, "w"))
    assert vault.verify_integrity() == (False, "Ciphertext failed to decrypt")
    with pytest.raises(pcrypto.InvalidToken):
        Vault(vault.path).unlock(PW)


def test_import_encrypted_replace_and_flat(vault, tmp_path):
    out = str(tmp_path / "exp.json")
    vault.add("b", Entry(password="pb"))
    vault.export_encrypted(out, "export password")
    other = Vault(str(tmp_path / "o.json"))
    other.create(PW, kdf="pbkdf2")
    other.add("keep", Entry())
    assert other.import_encrypted(out, "export password", merge=False) == 2
    assert sorted(other.entries) == ["a", "b"]
    tampered = json.load(open(out))
    tampered["version"] = 99
    json.dump(tampered, open(out, "w"))
    with pytest.raises(ValueError, match="integrity"):
        other.import_encrypted(out, "export password")


def test_integrity_error_message_names_the_cause(vault):
    payload = json.load(open(vault.path))
    payload["hmac"] = "é" * 64
    json.dump(payload, open(vault.path, "w"))
    with pytest.raises(VaultIntegrityError, match="does not match"):
        Vault(vault.path).unlock(PW)


def test_crypto_rejects_unknown_names():
    key = base64.urlsafe_b64encode(os.urandom(32))
    with pytest.raises(ValueError):
        pcrypto.derive_key(PW, b"s" * 16, "scrypt")
    with pytest.raises(ValueError):
        pcrypto.encrypt_bytes(b"x", key, "rot13")
    with pytest.raises(ValueError, match="Unknown cipher"):
        pcrypto.decrypt_bytes(b"x", key, "rot13")
    buf = bytearray(b"secret")
    pcrypto.secure_wipe(buf)
    assert buf == bytearray(6)
    assert pcrypto.verify_file_hmac({"hmac": 5}, key) is False
    assert pcrypto.verify_file_hmac({"hmac": "x"}, key) is False  # missing fields


def test_saas_module_entrypoint(monkeypatch):
    import saas.server

    called = []
    monkeypatch.setattr(saas.server, "main", lambda: called.append(True))
    runpy.run_module("saas", run_name="__main__")
    assert called == [True]
