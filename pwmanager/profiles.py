"""Vault profile resolution for multi-vault setups.

Profiles live under ``~/.config/pwmanager/``:
  - Named vault: ``~/.config/pwmanager/{name}.vault.json``
  - Optional map: ``~/.config/pwmanager/profiles.json``
    e.g. ``{"work": "/path/to/work.vault.json"}``

Resolution order for vault path:
  1. Explicit ``--vault`` path
  2. Profile from ``--profile`` / ``PWMANAGER_PROFILE``
  3. ``PWMANAGER_VAULT`` env
  4. Default ``./vault.json``
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Dict, Optional

from pwmanager.constants import DEFAULT_VAULT_PATH

CONFIG_DIR_NAME = "pwmanager"
PROFILES_FILENAME = "profiles.json"


def config_dir() -> Path:
    """Return ``~/.config/pwmanager`` (XDG-style)."""
    xdg = os.environ.get("XDG_CONFIG_HOME")
    if xdg:
        return Path(xdg) / CONFIG_DIR_NAME
    return Path.home() / ".config" / CONFIG_DIR_NAME


def profiles_map_path() -> Path:
    return config_dir() / PROFILES_FILENAME


def load_profiles_map() -> Dict[str, str]:
    """Load optional profiles.json mapping name -> vault path."""
    path = profiles_map_path()
    if not path.is_file():
        return {}
    try:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
    except (OSError, json.JSONDecodeError):
        return {}
    if not isinstance(data, dict):
        return {}
    return {str(k): str(v) for k, v in data.items() if k and v}


def resolve_profile_vault_path(profile: str) -> str:
    """Resolve a profile name to an absolute vault file path.

    Uses profiles.json override if present; otherwise
    ``~/.config/pwmanager/{profile}.vault.json``.
    """
    name = (profile or "").strip()
    if not name:
        raise ValueError("Profile name is empty")
    # Safety: no path separators in profile names
    if "/" in name or "\\" in name or name in (".", ".."):
        raise ValueError(f"Invalid profile name: {profile!r}")

    mapping = load_profiles_map()
    if name in mapping:
        return str(Path(mapping[name]).expanduser())

    return str(config_dir() / f"{name}.vault.json")


def resolve_vault_path(
    vault_arg: Optional[str] = None,
    profile_arg: Optional[str] = None,
) -> str:
    """Resolve the vault path from CLI args and environment.

    Priority:
      1. ``vault_arg`` (``--vault``)
      2. ``profile_arg`` or ``PWMANAGER_PROFILE``
      3. ``PWMANAGER_VAULT``
      4. ``DEFAULT_VAULT_PATH`` (cwd/vault.json)
    """
    if vault_arg:
        return str(Path(vault_arg).expanduser())

    profile = profile_arg or os.environ.get("PWMANAGER_PROFILE") or ""
    profile = profile.strip()
    if profile:
        return resolve_profile_vault_path(profile)

    env_vault = os.environ.get("PWMANAGER_VAULT")
    if env_vault:
        return str(Path(env_vault).expanduser())

    return DEFAULT_VAULT_PATH
