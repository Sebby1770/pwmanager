"""The browser generator must stay in step with the Python one.

``web/`` ships a second implementation of the generator so the site can run
with no server. That is only safe while the two agree: same symbol set, same
lookalike set, same presets, same wordlist. These tests fail the moment one
side is edited without the other, which is the failure mode that would
otherwise ship a browser password weaker than the CLI's for the same policy.

The JavaScript is read as text rather than executed, so the suite has no Node
dependency.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

from pwmanager.constants import SYMBOLS
from pwmanager.generators import GENERATOR_PRESETS, get_wordlist

ROOT = Path(__file__).resolve().parent.parent
WEB = ROOT / "web"
GENERATOR_JS = WEB / "generator.js"
WORDLIST_JS = WEB / "wordlist.js"

# Python option name -> JavaScript option name
OPTION_NAMES = {
    "length": "length",
    "use_lower": "useLower",
    "use_upper": "useUpper",
    "use_digits": "useDigits",
    "use_symbols": "useSymbols",
    "avoid_ambiguous": "avoidAmbiguous",
    "digits_only": "digitsOnly",
}


def js_source() -> str:
    return GENERATOR_JS.read_text(encoding="utf-8")


def js_string_constant(name: str) -> str:
    """Pull `var NAME = "...";` out of the generator and unescape it."""
    match = re.search(rf'var {name} = ("(?:[^"\\]|\\.)*");', js_source())
    assert match, f"{name} not found in {GENERATOR_JS.name}"
    return json.loads(match.group(1))


def js_presets() -> dict:
    """Parse the PRESETS object literal into plain Python data."""
    source = js_source()
    start = source.index("var PRESETS = {")
    depth = 0
    for index in range(source.index("{", start), len(source)):
        if source[index] == "{":
            depth += 1
        elif source[index] == "}":
            depth -= 1
            if depth == 0:
                body = source[source.index("{", start) : index + 1]
                break
    else:  # pragma: no cover — unbalanced braces would be a syntax error anyway
        pytest.fail("Could not find the end of the PRESETS literal")

    # Object-literal keys are bare identifiers; JSON needs them quoted.
    quoted = re.sub(r"(?m)^(\s*)([A-Za-z_][A-Za-z0-9_]*):", r'\1"\2":', body)
    quoted = re.sub(r",(\s*[}\]])", r"\1", quoted)  # tolerate trailing commas
    return json.loads(quoted)


def test_web_directory_is_present():
    for name in ("index.html", "styles.css", "app.js", "generator.js", "wordlist.js"):
        assert (WEB / name).is_file(), f"web/{name} is missing"


def test_symbols_match():
    assert js_string_constant("SYMBOLS") == SYMBOLS


def test_ambiguous_set_matches_generate_password():
    # generate_password() builds this set inline; keep the literal in step.
    assert set(js_string_constant("AMBIGUOUS")) == set("Il1O0o`'\"|")


def test_preset_names_match():
    assert set(js_presets()) == set(GENERATOR_PRESETS)


@pytest.mark.parametrize("name", sorted(GENERATOR_PRESETS))
def test_preset_policies_match(name):
    web = js_presets()[name]
    py = GENERATOR_PRESETS[name]

    for py_key, js_key in OPTION_NAMES.items():
        if py_key == "length":
            assert web["length"] == py["length"], f"{name}: length differs"
            continue
        # Python presets rely on defaults for some keys; mirror generate_password's.
        default = py_key != "avoid_ambiguous" and py_key != "digits_only"
        expected = bool(py.get(py_key, default))
        assert bool(web[js_key]) is expected, f"{name}: {py_key} differs"


def test_preset_labels_and_hints_are_present():
    for name, preset in js_presets().items():
        assert preset.get("label"), f"{name} has no label"
        assert preset.get("hint"), f"{name} has no hint"


def test_wordlist_matches_the_packaged_list():
    words = get_wordlist()
    source = WORDLIST_JS.read_text(encoding="utf-8")
    literal = re.search(r"var BLOB = \[(.*?)\]\.join", source, re.S)
    assert literal, "web/wordlist.js does not contain the expected BLOB array"
    web_words = " ".join(re.findall(r'"([^"]*)"', literal.group(1))).split()
    assert web_words == words, (
        "web/wordlist.js is stale — regenerate it with "
        "`python3 scripts/build_web_wordlist.py`"
    )


def test_every_flag_the_site_suggests_exists_in_the_cli():
    """The 'same policy from the terminal' hint must be a runnable command.

    The site used to print flags like --no-upper that `pwmanager gen` did not
    accept, so anyone who copied the hint got an argparse error.
    """
    from pwmanager.cli import build_parser

    source = js_source()
    start = source.index("function cliCommand(")
    end = source.index("\n  }", start)
    body = source[start:end]

    suggested = set(re.findall(r'"(--[a-z-]+)"', body))
    assert suggested, "cliCommand suggests no flags at all — did it move?"

    gen_parser = build_parser()._subparsers._group_actions[0].choices["gen"]
    known = {opt for action in gen_parser._actions for opt in action.option_strings}

    unknown = sorted(suggested - known)
    assert not unknown, f"web hint suggests flags `pwmanager gen` does not accept: {unknown}"


def test_web_page_declares_a_restrictive_csp():
    """The generator page (moved to generator.html) keeps its original CSP."""
    html = (WEB / "generator.html").read_text(encoding="utf-8")
    csp = re.search(r'http-equiv="Content-Security-Policy" content="([^"]+)"', html)
    assert csp, "generator.html has no Content-Security-Policy meta tag"
    policy = csp.group(1)
    assert "default-src 'none'" in policy
    assert "script-src 'self'" in policy
    assert "unsafe-inline" not in policy
    # The HIBP range endpoint is the only outbound connection the generator may make.
    connect = re.search(r"connect-src ([^;]+)", policy)
    assert connect, "CSP has no connect-src"
    assert connect.group(1).split() == ["https://api.pwnedpasswords.com"]


def test_landing_page_declares_a_restrictive_csp():
    html = (WEB / "index.html").read_text(encoding="utf-8")
    csp = re.search(r'http-equiv="Content-Security-Policy" content="([^"]+)"', html)
    assert csp, "index.html has no Content-Security-Policy meta tag"
    policy = csp.group(1)
    assert "default-src 'none'" in policy
    assert "script-src 'self'" in policy
    assert "unsafe-inline" not in policy
    assert "unsafe-eval" not in policy
    connect = re.search(r"connect-src ([^;]+)", policy)
    assert connect, "CSP has no connect-src"
    tokens = connect.group(1).split()
    assert "'self'" in tokens
    assert "https://api.pwnedpasswords.com" in tokens


def test_web_scripts_never_persist_a_secret():
    """localStorage is for interface preferences only."""
    app = (WEB / "app.js").read_text(encoding="utf-8")
    for line in app.splitlines():
        if "localStorage.setItem" in line:
            assert "PREFS_KEY" in line, f"suspicious persistence: {line.strip()}"


def test_no_remote_assets_in_the_page():
    """The page must stay self-contained so it works offline and pins its code."""
    html = (WEB / "index.html").read_text(encoding="utf-8")
    for match in re.finditer(r'(?:src|href)="([^"]+)"', html):
        url = match.group(1)
        if url.startswith(("http://", "https://", "//")):
            # Links out to GitHub/HIBP are fine; loading code or styles is not.
            assert "rel=\"stylesheet\"" not in match.string[max(0, match.start() - 80) : match.start()], (
                f"remote stylesheet: {url}"
            )
            assert not re.search(r"<script[^>]*$", html[: match.start()]), f"remote script: {url}"
