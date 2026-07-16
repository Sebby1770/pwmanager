"""Tests for password / passphrase generators."""

from __future__ import annotations

import string

import pytest

from pwmanager.constants import SYMBOLS
from pwmanager.generators import (
    generate_passphrase,
    generate_password,
    password_entropy_bits,
)


def test_generate_password_length():
    for length in (8, 16, 32, 64):
        pw = generate_password(length=length)
        assert len(pw) == length


def test_generate_password_charset_includes_classes():
    pw = generate_password(length=40, use_upper=True, use_digits=True, use_symbols=True)
    assert any(c.islower() for c in pw)
    assert any(c.isupper() for c in pw)
    assert any(c.isdigit() for c in pw)
    assert any(c in SYMBOLS for c in pw)


def test_generate_password_no_symbols():
    pw = generate_password(length=24, use_symbols=False)
    assert not any(c in SYMBOLS for c in pw)
    allowed = set(string.ascii_letters + string.digits)
    assert all(c in allowed for c in pw)


def test_generate_password_avoid_ambiguous():
    ambiguous = set("Il1O0o`'\"|")
    for _ in range(20):
        pw = generate_password(length=32, avoid_ambiguous=True)
        assert not any(c in ambiguous for c in pw)


def test_generate_password_min_length():
    with pytest.raises(ValueError):
        generate_password(length=3)


def test_generate_passphrase_word_count():
    phrase = generate_passphrase(words=5, separator="-")
    parts = phrase.split("-")
    assert len(parts) == 5
    assert all(parts)


def test_generate_passphrase_min_words():
    with pytest.raises(ValueError):
        generate_passphrase(words=2)


def test_password_entropy_empty_and_strong():
    assert password_entropy_bits("") == 0.0
    weak = password_entropy_bits("abc")
    strong = password_entropy_bits("aB3!xY9$qW2@mN7#")
    assert weak < 50
    assert strong > 50
