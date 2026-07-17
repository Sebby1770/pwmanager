"""Tests for vault profile path resolution."""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from pwmanager.profiles import (
    resolve_profile_vault_path,
    resolve_vault_path,
)


def test_resolve_profile_default_path(tmp_path, monkeypatch):
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path))
    monkeypatch.delenv("PWMANAGER_PROFILE", raising=False)
    monkeypatch.delenv("PWMANAGER_VAULT", raising=False)

    path = resolve_profile_vault_path("work")
    assert path.endswith("work.vault.json")
    assert str(tmp_path) in path
    assert "pwmanager" in path


def test_resolve_profile_from_map(tmp_path, monkeypatch):
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path))
    cfg = tmp_path / "pwmanager"
    cfg.mkdir()
    custom = tmp_path / "custom" / "my.vault.json"
    (cfg / "profiles.json").write_text(
        json.dumps({"work": str(custom)}), encoding="utf-8"
    )

    path = resolve_profile_vault_path("work")
    assert path == str(custom)


def test_resolve_vault_priority_explicit(tmp_path, monkeypatch):
    monkeypatch.setenv("PWMANAGER_PROFILE", "work")
    monkeypatch.setenv("PWMANAGER_VAULT", "/env/vault.json")
    path = resolve_vault_path(vault_arg=str(tmp_path / "explicit.json"), profile_arg="work")
    assert path.endswith("explicit.json")


def test_resolve_vault_priority_profile_over_env(tmp_path, monkeypatch):
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path))
    monkeypatch.setenv("PWMANAGER_VAULT", "/env/vault.json")
    monkeypatch.delenv("PWMANAGER_PROFILE", raising=False)

    path = resolve_vault_path(vault_arg=None, profile_arg="personal")
    assert path.endswith("personal.vault.json")
    assert "env/vault" not in path


def test_resolve_vault_env_profile(tmp_path, monkeypatch):
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path))
    monkeypatch.setenv("PWMANAGER_PROFILE", "travel")
    monkeypatch.delenv("PWMANAGER_VAULT", raising=False)

    path = resolve_vault_path()
    assert path.endswith("travel.vault.json")


def test_resolve_vault_env_vault(tmp_path, monkeypatch):
    monkeypatch.delenv("PWMANAGER_PROFILE", raising=False)
    monkeypatch.setenv("PWMANAGER_VAULT", str(tmp_path / "from-env.json"))

    path = resolve_vault_path()
    assert path.endswith("from-env.json")


def test_invalid_profile_name():
    with pytest.raises(ValueError):
        resolve_profile_vault_path("../escape")
    with pytest.raises(ValueError):
        resolve_profile_vault_path("")
