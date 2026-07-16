"""Tests for key derivation and encryption (no real secrets)."""

from __future__ import annotations

import pytest
from cryptography.fernet import InvalidToken

from pwmanager.crypto import (
    decrypt_bytes,
    derive_key,
    encrypt_bytes,
    file_hmac,
    generate_salt,
)


def test_generate_salt_length_and_uniqueness():
    s1 = generate_salt()
    s2 = generate_salt()
    assert len(s1) == 16
    assert s1 != s2


def test_derive_key_and_encrypt_decrypt_roundtrip():
    password = "test-master-password-not-real"
    salt = generate_salt()
    key, kdf_used = derive_key(password, salt, kdf="pbkdf2")
    assert kdf_used == "pbkdf2"
    assert isinstance(key, bytes)
    assert len(key) > 0

    plaintext = b'{"hello": "world", "n": 42}'
    token = encrypt_bytes(plaintext, key)
    assert token != plaintext
    recovered = decrypt_bytes(token, key)
    assert recovered == plaintext


def test_wrong_password_raises_invalid_token():
    salt = generate_salt()
    key_good, _ = derive_key("correct-horse-battery", salt, kdf="pbkdf2")
    key_bad, _ = derive_key("wrong-password-here!!", salt, kdf="pbkdf2")
    token = encrypt_bytes(b"secret-payload", key_good)
    with pytest.raises(InvalidToken):
        decrypt_bytes(token, key_bad)


def test_file_hmac_stable_and_key_dependent():
    salt = generate_salt()
    key_a, _ = derive_key("password-aaaaaa", salt, kdf="pbkdf2")
    key_b, _ = derive_key("password-bbbbbb", salt, kdf="pbkdf2")
    payload = {"salt": "abc", "vault": "def"}
    h1 = file_hmac(payload, key_a)
    h2 = file_hmac(payload, key_a)
    h3 = file_hmac(payload, key_b)
    assert h1 == h2
    assert h1 != h3
    assert len(h1) == 64  # sha256 hex


def test_derive_key_unknown_kdf():
    with pytest.raises(ValueError, match="Unknown KDF"):
        derive_key("x", b"0" * 16, kdf="scrypt")
