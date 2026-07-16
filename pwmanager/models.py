"""Vault entry data model."""

from __future__ import annotations

import time
from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List


@dataclass
class Entry:
    username: str = ""
    password: str = ""
    url: str = ""
    notes: str = ""
    tags: List[str] = field(default_factory=list)
    totp_secret: str = ""
    history: List[Dict[str, Any]] = field(default_factory=list)  # [{password, changed_at}]
    created_at: float = field(default_factory=time.time)
    updated_at: float = field(default_factory=time.time)

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: dict) -> "Entry":
        return cls(
            username=d.get("username", ""),
            password=d.get("password", ""),
            url=d.get("url", ""),
            notes=d.get("notes", ""),
            tags=list(d.get("tags", [])),
            totp_secret=d.get("totp_secret", ""),
            history=list(d.get("history", [])),
            created_at=d.get("created_at", time.time()),
            updated_at=d.get("updated_at", time.time()),
        )
