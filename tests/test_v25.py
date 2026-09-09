"""2.5: AES-256-GCM, atomic rekey, trash, rename."""

from __future__ import annotations

import json

import pytest
from cryptography.fernet import InvalidToken

from pwmanager.constants import CIPHER_AESGCM, CIPHER_FERNET, CURRENT_CIPHER
from pwmanager.crypto import decrypt_bytes, derive_key, encrypt_bytes, file_hmac_v2
from pwmanager.models import Entry
from pwmanager.vault import Vault

MASTER = "test-master-pw-not-real!!"
NEW_MASTER = "replacement-master-pw!!"


def make_vault(tmp_path, name="vault.json"):
    path = tmp_path / name
    v = Vault(str(path))
    v.create(MASTER, kdf="pbkdf2")
    return v, path


def test_new_vaults_use_aes256gcm(tmp_path):
    v, path = make_vault(tmp_path)
    payload = json.loads(path.read_text(encoding="utf-8"))
    assert payload["cipher"] == CIPHER_AESGCM
    assert payload["version"] == 3
    assert v.cipher == CURRENT_CIPHER


def test_fernet_vaults_still_unlock_and_migrate(tmp_path):
    path = tmp_path / "legacy.json"
    salt = b"0123456789abcdef"
    key, _ = derive_key(MASTER, salt, "pbkdf2")
    inner = json.dumps({"old": {"username": "u", "password": "legacy-Aa1!"}}).encode()
    from cryptography.fernet import Fernet

    token = Fernet(key).encrypt(inner).decode("ascii")
    payload = {
        "version": 2,
        "kdf": "pbkdf2",
        "salt": __import__("base64").b64encode(salt).decode("ascii"),
        "vault": token,
    }
    payload["hmac"] = file_hmac_v2(payload, key)
    path.write_text(json.dumps(payload), encoding="utf-8")

    v = Vault(str(path))
    v.unlock(MASTER)
    assert v.cipher == CIPHER_FERNET
    assert v.entries["old"].username == "u"
    v.add("new", Entry(password="BrandNew-99!!"))
    v.lock()

    again = Vault(str(path))
    again.unlock(MASTER)
    assert again.cipher == CIPHER_AESGCM
    assert "old" in again.entries
    assert "new" in again.entries
    again.lock()


def test_gcm_wrong_password_is_invalid_token(tmp_path):
    v, path = make_vault(tmp_path)
    v.lock()
    with pytest.raises(InvalidToken):
        Vault(str(path)).unlock("definitely-wrong-password!!")


def test_change_master_is_atomic_and_keeps_entries(tmp_path):
    v, path = make_vault(tmp_path)
    v.add("mail", Entry(username="me", password="Mailbox-22!!"))
    v.change_master(NEW_MASTER, kdf="pbkdf2")
    v.lock()
    with pytest.raises(InvalidToken):
        Vault(str(path)).unlock(MASTER)
    other = Vault(str(path))
    other.unlock(NEW_MASTER)
    assert other.entries["mail"].username == "me"
    other.lock()


def test_delete_undelete_survives_relock(tmp_path):
    v, _ = make_vault(tmp_path)
    v.add("keep", Entry(password="KeepMe-1234!!"))
    v.add("gone", Entry(password="GoneNow-1234!!"))
    v.delete("gone")
    assert "gone" not in v.entries
    v.lock()
    v.unlock(MASTER)
    assert v.undelete() == "gone"
    assert "gone" in v.entries


def test_rename(tmp_path):
    v, _ = make_vault(tmp_path)
    v.add("gh", Entry(username="seb", url="https://github.com"))
    v.rename("gh", "github")
    assert "github" in v.entries
    assert "gh" not in v.entries
    with pytest.raises(ValueError):
        v.rename("github", "github")


def test_encrypt_decrypt_aesgcm_roundtrip():
    salt = b"0123456789abcdef"
    key, _ = derive_key("pw-not-real-enough", salt, "pbkdf2")
    token = encrypt_bytes(b"hello", key, CIPHER_AESGCM)
    assert decrypt_bytes(token, key, CIPHER_AESGCM) == b"hello"
    with pytest.raises(InvalidToken):
        decrypt_bytes(token, key, CIPHER_FERNET)
