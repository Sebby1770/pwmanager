"""Vault entry data model."""

from __future__ import annotations

import time
from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List

# Entry kinds
KIND_LOGIN = "login"
KIND_NOTE = "note"
VALID_KINDS = frozenset({KIND_LOGIN, KIND_NOTE})


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
    favorite: bool = False
    kind: str = KIND_LOGIN  # "login" | "note"

    def is_note(self) -> bool:
        return self.kind == KIND_NOTE

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: dict) -> "Entry":
        kind = d.get("kind", KIND_LOGIN) or KIND_LOGIN
        if kind not in VALID_KINDS:
            kind = KIND_LOGIN
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
            favorite=bool(d.get("favorite", False)),
            kind=kind,
        )
