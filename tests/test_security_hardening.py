"""Regression tests for secret-file and CLI password handling."""

from __future__ import annotations

import io
import json
import os
import stat
from pathlib import Path
from unittest.mock import patch

import pytest
from cryptography.fernet import InvalidToken

from pwmanager.cli import main, read_secret_input
from pwmanager.generators import password_entropy_bits
from pwmanager.models import Entry
from pwmanager.secure_io import atomic_private_text_writer
from pwmanager.vault import Vault

MASTER = "test-master-pw-not-real!!"
NEW_MASTER = "replacement-master-pw-not-real!!"


def _mode(path: Path) -> int:
    return stat.S_IMODE(path.stat().st_mode)


@pytest.mark.skipif(os.name == "nt", reason="POSIX permission bits")
def test_vault_and_all_exports_are_private_despite_umask(tmp_path):
    vault_path = tmp_path / "vault.json"
    encrypted_path = tmp_path / "encrypted.json"
    csv_path = tmp_path / "plaintext.csv"
    json_path = tmp_path / "plaintext.json"

    previous_umask = os.umask(0)
    try:
        vault = Vault(str(vault_path))
        vault.create(MASTER, kdf="pbkdf2")
        vault.add("site", Entry(username="alice", password="secret-Aa1!"))
        vault.export_encrypted(str(encrypted_path), "export-password-not-real!!")
        vault.export_csv(str(csv_path))
        vault.export_json(str(json_path))
    finally:
        os.umask(previous_umask)

    for path in (vault_path, encrypted_path, csv_path, json_path):
        assert _mode(path) == 0o600


def test_predictable_legacy_temp_symlink_cannot_overwrite_victim(tmp_path):
    victim = tmp_path / "victim.txt"
    victim.write_text("do not replace", encoding="utf-8")
    vault_path = tmp_path / "vault.json"
    legacy_temp = Path(f"{vault_path}.tmp")
    try:
        legacy_temp.symlink_to(victim)
    except (NotImplementedError, OSError):
        pytest.skip("symlinks unavailable")

    Vault(str(vault_path)).create(MASTER, kdf="pbkdf2")

    assert victim.read_text(encoding="utf-8") == "do not replace"
    assert legacy_temp.is_symlink()
    assert json.loads(vault_path.read_text(encoding="utf-8"))["version"] >= 2


def test_export_replaces_destination_symlink_instead_of_following_it(tmp_path):
    victim = tmp_path / "victim.txt"
    victim.write_text("keep me", encoding="utf-8")
    output = tmp_path / "export.json"
    try:
        output.symlink_to(victim)
    except (NotImplementedError, OSError):
        pytest.skip("symlinks unavailable")

    vault = Vault(str(tmp_path / "vault.json"))
    vault.create(MASTER, kdf="pbkdf2")
    vault.add("site", Entry(username="alice", password="secret-Aa1!"))
    vault.export_json(str(output))

    assert victim.read_text(encoding="utf-8") == "keep me"
    assert not output.is_symlink()
    assert "site" in json.loads(output.read_text(encoding="utf-8"))["entries"]


def test_atomic_writer_keeps_old_file_and_cleans_temp_on_failure(tmp_path):
    destination = tmp_path / "secret.txt"
    destination.write_text("old contents", encoding="utf-8")

    with pytest.raises(RuntimeError, match="simulated"):
        with atomic_private_text_writer(destination) as output:
            output.write("new contents")
            raise RuntimeError("simulated failure")

    assert destination.read_text(encoding="utf-8") == "old contents"
    assert list(tmp_path.glob(".secret.txt.*.tmp")) == []


def test_master_password_change_is_atomic_and_preserves_entries(tmp_path):
    path = tmp_path / "vault.json"
    vault = Vault(str(path))
    vault.create(MASTER, kdf="pbkdf2")
    vault.add("site", Entry(username="alice", password="secret-Aa1!"))

    vault.change_master_password(NEW_MASTER, kdf="pbkdf2")

    with pytest.raises(InvalidToken):
        Vault(str(path)).unlock(MASTER)
    reopened = Vault(str(path))
    reopened.unlock(NEW_MASTER)
    assert reopened.entries["site"].password == "secret-Aa1!"


def test_failed_master_password_change_leaves_old_vault_usable(tmp_path):
    path = tmp_path / "vault.json"
    vault = Vault(str(path))
    vault.create(MASTER, kdf="pbkdf2")
    vault.add("site", Entry(username="alice", password="secret-Aa1!"))
    original_file = path.read_bytes()
    original_key = vault.key

    with patch.object(vault, "_write", side_effect=OSError("disk full")):
        with pytest.raises(OSError, match="disk full"):
            vault.change_master_password(NEW_MASTER, kdf="pbkdf2")

    assert path.read_bytes() == original_file
    assert vault.key == original_key
    reopened = Vault(str(path))
    reopened.unlock(MASTER)
    assert "site" in reopened.entries


@pytest.mark.parametrize("tampered_hmac", ["0" * 64, None, "é" * 64])
def test_tampered_wrapper_hmac_is_rejected_during_unlock(tmp_path, tampered_hmac):
    path = tmp_path / "vault.json"
    vault = Vault(str(path))
    vault.create(MASTER, kdf="pbkdf2")
    payload = json.loads(path.read_text(encoding="utf-8"))
    payload["hmac"] = tampered_hmac
    path.write_text(json.dumps(payload), encoding="utf-8")

    assert vault.verify_integrity()[0] is False
    vault.lock()
    with pytest.raises(InvalidToken):
        Vault(str(path)).unlock(MASTER)


def test_legacy_vault_without_wrapper_hmac_still_unlocks(tmp_path):
    path = tmp_path / "vault.json"
    vault = Vault(str(path))
    vault.create(MASTER, kdf="pbkdf2")
    vault.add("site", Entry(username="alice", password="secret-Aa1!"))
    vault.lock()
    payload = json.loads(path.read_text(encoding="utf-8"))
    del payload["hmac"]
    path.write_text(json.dumps(payload), encoding="utf-8")

    reopened = Vault(str(path))
    reopened.unlock(MASTER)
    assert reopened.entries["site"].username == "alice"


@pytest.mark.parametrize(
    "password",
    [
        "aaaaaaaaaaaaaaaaaaaa",
        "abcabcabcabcabcabc",
        "12345678901234567890",
        "passwordpassword",
        "horse-horse-horse-horse",
    ],
)
def test_repetition_does_not_inflate_master_password_strength(tmp_path, password):
    assert password_entropy_bits(password) < 28
    with pytest.raises(ValueError, match="predictable"):
        Vault(str(tmp_path / "vault.json")).create(password, kdf="pbkdf2")


def test_legacy_argv_password_is_rejected_without_echoing_secret(capsys):
    secret = "must-not-appear-in-output"
    with patch("pwmanager.cli.unlock_or_create") as unlock:
        result = main(["add", "site", "--password", secret])

    assert result == 2
    unlock.assert_not_called()
    output = capsys.readouterr()
    assert "--password is disabled" in output.err
    assert secret not in output.out + output.err


def test_legacy_argv_note_is_rejected_without_echoing_secret(capsys):
    secret = "private note that must not appear"
    with patch("pwmanager.cli.unlock_or_create") as unlock:
        result = main(["add-note", "recovery", f"--notes={secret}"])

    assert result == 2
    unlock.assert_not_called()
    output = capsys.readouterr()
    assert "--notes is disabled" in output.err
    assert secret not in output.out + output.err


@pytest.mark.parametrize(
    "source_args",
    [
        ["--password-fd", "3", "--notes-fd", "3"],
        ["--password-stdin", "--notes-stdin"],
        ["--password-fd", "0", "--notes-stdin"],
    ],
)
def test_password_and_notes_require_distinct_input_sources(capsys, source_args):
    with patch("pwmanager.cli.unlock_or_create") as unlock:
        result = main(["add", "site", *source_args])

    assert result == 2
    unlock.assert_not_called()
    assert "different input sources" in capsys.readouterr().err


def test_notes_stdin_requires_noninteractive_password_path(capsys):
    with patch("pwmanager.cli.unlock_or_create") as unlock:
        result = main(["add", "site", "--notes-stdin"])

    assert result == 2
    unlock.assert_not_called()
    assert "requires --gen" in capsys.readouterr().err


def test_add_password_can_be_read_from_standard_input(tmp_path, monkeypatch):
    path = tmp_path / "vault.json"
    Vault(str(path)).create(MASTER, kdf="pbkdf2")
    monkeypatch.setenv("PWMANAGER_PASSWORD", MASTER)
    monkeypatch.setattr("sys.stdin", io.StringIO("entry-password-Aa1!\n"))

    result = main(
        [
            "--password-env",
            "--vault",
            str(path),
            "add",
            "site",
            "--username",
            "alice",
            "--password-stdin",
        ]
    )

    assert result == 0
    reopened = Vault(str(path))
    reopened.unlock(MASTER)
    assert reopened.entries["site"].password == "entry-password-Aa1!"


@pytest.mark.parametrize("command", [["add-note"], ["add", "--note"]])
def test_secure_note_can_be_read_from_standard_input(tmp_path, monkeypatch, command):
    path = tmp_path / "vault.json"
    Vault(str(path)).create(MASTER, kdf="pbkdf2")
    monkeypatch.setenv("PWMANAGER_PASSWORD", MASTER)
    monkeypatch.setattr(
        "sys.stdin", io.StringIO("private recovery note\nsecond private line\n")
    )
    monkeypatch.setattr(
        "pwmanager.cli.prompt_yn",
        lambda *args, **kwargs: pytest.fail("Piped notes must not prompt interactively"),
    )

    result = main(
        [
            "--password-env",
            "--vault",
            str(path),
            *command,
            "recovery",
            "--notes-stdin",
        ]
    )

    assert result == 0
    reopened = Vault(str(path))
    reopened.unlock(MASTER)
    assert reopened.entries["recovery"].notes == (
        "private recovery note\nsecond private line"
    )


def test_password_file_descriptor_is_duplicated_and_left_open():
    read_fd, write_fd = os.pipe()
    try:
        os.write(write_fd, b"fd-password-Aa1!\n")
        os.close(write_fd)
        write_fd = -1

        assert read_secret_input(fd=read_fd) == "fd-password-Aa1!"
        assert os.fstat(read_fd)
    finally:
        if write_fd >= 0:
            os.close(write_fd)
        os.close(read_fd)
