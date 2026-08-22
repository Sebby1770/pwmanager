#!/usr/bin/env python3
"""Regenerate web/wordlist.js from the packaged EFF short wordlist.

The web generator must draw from exactly the same list as the CLI so that a
passphrase produced in the browser has the same entropy as one produced by
``pwmanager gen --passphrase``. Run this after editing
``pwmanager/data/eff_short.txt``::

    python3 scripts/build_web_wordlist.py

``tests/test_web_parity.py`` fails if the two lists drift apart.
"""

from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SOURCE = ROOT / "pwmanager" / "data" / "eff_short.txt"
TARGET = ROOT / "web" / "wordlist.js"
WRAP_AT = 96


def load_words() -> list[str]:
    words = [
        line.strip()
        for line in SOURCE.read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.startswith("#")
    ]
    if len(words) < 1000:
        raise SystemExit(f"{SOURCE} only has {len(words)} words; expected >= 1000")
    if any(" " in w for w in words):
        raise SystemExit("wordlist entries must not contain spaces")
    return words


def wrap(words: list[str]) -> list[str]:
    lines: list[str] = []
    current = ""
    for word in words:
        if current and len(current) + len(word) + 1 > WRAP_AT:
            lines.append(current)
            current = word
        else:
            current = f"{current} {word}" if current else word
    if current:
        lines.append(current)
    return lines


def render(words: list[str]) -> str:
    body = wrap(words)
    out = [
        "/* AUTO-GENERATED from pwmanager/data/eff_short.txt — do not edit by hand.",
        "   Regenerate with: python3 scripts/build_web_wordlist.py */",
        "(function (root, factory) {",
        '  if (typeof module === "object" && module.exports) { module.exports = factory(); }',
        "  else { root.PW_WORDLIST = factory(); }",
        '})(typeof globalThis !== "undefined" ? globalThis : this, function () {',
        '  "use strict";',
        "  var BLOB = [",
    ]
    for index, line in enumerate(body):
        comma = "," if index < len(body) - 1 else ""
        out.append(f'    "{line}"{comma}')
    out += ['  ].join(" ");', '  return BLOB.split(" ");', "});"]
    return "\n".join(out) + "\n"


def main() -> None:
    words = load_words()
    TARGET.write_text(render(words), encoding="utf-8")
    print(f"wrote {TARGET.relative_to(ROOT)} with {len(words)} words")


if __name__ == "__main__":
    main()
