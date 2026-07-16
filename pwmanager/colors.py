"""ANSI color helpers (auto-disabled when not a TTY)."""

from __future__ import annotations

import sys


class C:
    USE = sys.stdout.isatty()

    @classmethod
    def w(cls, code: str, text: str) -> str:
        return f"\033[{code}m{text}\033[0m" if cls.USE else text

    @classmethod
    def bold(cls, t: str) -> str:
        return cls.w("1", t)

    @classmethod
    def dim(cls, t: str) -> str:
        return cls.w("2", t)

    @classmethod
    def red(cls, t: str) -> str:
        return cls.w("31", t)

    @classmethod
    def green(cls, t: str) -> str:
        return cls.w("32", t)

    @classmethod
    def yellow(cls, t: str) -> str:
        return cls.w("33", t)

    @classmethod
    def blue(cls, t: str) -> str:
        return cls.w("34", t)

    @classmethod
    def cyan(cls, t: str) -> str:
        return cls.w("36", t)

    @classmethod
    def magenta(cls, t: str) -> str:
        return cls.w("35", t)
