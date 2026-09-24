"""Fuzz / property tests for the CSV and JSON importers.

Contract: an importer either returns (name, Entry) pairs with unique names, or
raises ValueError / csv.Error, which the CLI reports cleanly. Nothing else.
"""

from __future__ import annotations

import csv
import io
import json

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from pwmanager.importers import import_csv_file, parse_bitwarden_json, parse_csv_rows, parse_import_text
from pwmanager.models import Entry
from pwmanager.vault import Vault

SETTINGS = settings(max_examples=300, deadline=None)
OK_ERRORS = (ValueError, csv.Error)

HEADERS = {
    "bitwarden": ["folder", "favorite", "type", "name", "notes", "fields", "reprompt",
                  "login_uri", "login_username", "login_password", "login_totp"],
    "chrome": ["name", "url", "username", "password", "note"],
    "onepassword": ["Title", "Website", "Username", "Password", "OTPAuth", "Favorite", "Archived", "Tags", "Notes"],
    "generic": ["name", "username", "password", "url", "notes", "tags", "totp_secret"],
}

cell = st.text(max_size=40)


def _csv(header, rows) -> str:
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(header)
    writer.writerows(rows)
    return buf.getvalue()


@st.composite
def export_csv(draw):
    header = HEADERS[draw(st.sampled_from(sorted(HEADERS)))]
    rows = draw(st.lists(st.lists(cell, min_size=0, max_size=len(header) + 2), max_size=12))
    return _csv(header, rows)


def _check(result):
    names = [name for name, _ in result]
    assert len(names) == len(set(names)), f"duplicate names would overwrite entries: {names}"
    for name, entry in result:
        assert isinstance(name, str) and name
        assert isinstance(entry, Entry)
        for field in (entry.username, entry.password, entry.url, entry.notes, entry.totp_secret):
            assert isinstance(field, str)


@SETTINGS
@given(text=export_csv())
def test_realistic_exports_parse_or_fail_cleanly(text):
    try:
        result = parse_csv_rows(text)
    except OK_ERRORS:
        return
    _check(result)


@SETTINGS
@given(text=st.text(max_size=400))
def test_arbitrary_text_parses_or_fails_cleanly(text):
    try:
        result = parse_csv_rows(text)
    except OK_ERRORS:
        return
    _check(result)


@SETTINGS
@given(names=st.lists(st.sampled_from(["a", "a (2)", "a (3)", "b", "a (2) (2)"]), max_size=10))
def test_imported_names_are_unique_even_when_rows_look_renamed(names):
    text = _csv(["name", "password"], [[n, "pw"] for n in names])
    _check(parse_csv_rows(text))
    assert len(parse_csv_rows(text)) == len(names)


def test_field_larger_than_csv_limit_fails_cleanly():
    text = "name,password\nbig," + "x" * 200_000 + "\n"
    with pytest.raises(OK_ERRORS):
        parse_csv_rows(text)


printable = st.text(st.characters(codec="utf-8", exclude_categories=["Cs"]), max_size=40)


@settings(max_examples=60, deadline=None, suppress_health_check=[HealthCheck.function_scoped_fixture])
@given(
    entries=st.dictionaries(
        st.text(st.characters(codec="utf-8", exclude_categories=["Cs", "Cc", "Zs"]), min_size=1, max_size=15),
        st.fixed_dictionaries({"username": printable, "password": printable, "url": printable,
                               "notes": printable, "totp_secret": st.text("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567", max_size=32)}),
        min_size=1, max_size=6,
    )
)
def test_csv_export_then_import_roundtrips_secrets(tmp_path, entries):
    """Whatever pwmanager exports, pwmanager must read back unchanged."""
    import pwmanager.crypto as pcrypto

    old = pcrypto.PBKDF2_ITERATIONS
    pcrypto.PBKDF2_ITERATIONS = 1_000
    try:
        v = Vault(str(tmp_path / "rt.json"))
        v.create("roundtrip master password", kdf="pbkdf2")
        for name, fields in entries.items():
            v.entries[name] = Entry(**fields)
        out = tmp_path / "export.csv"
        v.export_csv(str(out))
    finally:
        pcrypto.PBKDF2_ITERATIONS = old
    imported = dict(import_csv_file(str(out)))
    for name, fields in entries.items():
        if not (name.strip() or fields["username"].strip() or fields["password"]):
            continue
        got = imported[name.strip()]
        assert got.password == fields["password"], "password changed on round trip"
        assert got.notes == fields["notes"], "notes changed on round trip"
        assert got.totp_secret == fields["totp_secret"], "TOTP secret lost on round trip"
        assert got.username == fields["username"].strip()


# ------------------------------------------------------------------ Bitwarden JSON


bw_item = st.fixed_dictionaries(
    {"type": st.sampled_from([1, 2, 3, "1", None]), "name": st.one_of(st.none(), cell)},
    optional={
        "notes": st.one_of(st.none(), cell),
        "favorite": st.booleans(),
        "login": st.one_of(
            st.none(),
            st.fixed_dictionaries(
                {},
                optional={
                    "username": st.one_of(st.none(), cell),
                    "password": st.one_of(st.none(), cell),
                    "totp": st.one_of(st.none(), cell),
                    "uris": st.one_of(st.none(), st.lists(st.fixed_dictionaries({"uri": st.one_of(st.none(), cell)}), max_size=3)),
                },
            ),
        ),
    },
)

junk = st.recursive(
    st.none() | st.booleans() | st.integers() | st.text(max_size=10),
    lambda c: st.lists(c, max_size=3) | st.dictionaries(st.text(max_size=6), c, max_size=3),
    max_leaves=10,
)


@SETTINGS
@given(items=st.lists(st.one_of(bw_item, junk), max_size=8), encrypted=st.booleans())
def test_bitwarden_json_parses_or_fails_cleanly(items, encrypted):
    doc = {"encrypted": encrypted, "items": items}
    try:
        result = parse_bitwarden_json(json.dumps(doc))
    except ValueError:
        return
    _check(result)


@SETTINGS
@given(text=st.text(max_size=200))
def test_bitwarden_json_arbitrary_text(text):
    try:
        _check(parse_bitwarden_json(text))
    except ValueError:
        pass


def test_bitwarden_json_login_and_note():
    doc = {
        "encrypted": False,
        "items": [
            {"type": 1, "name": "GitHub", "notes": "n", "favorite": True,
             "login": {"username": "octo", "password": " pw with spaces ", "totp": "JBSWY3DPEHPK3PXP",
                       "uris": [{"uri": "https://github.com"}]}},
            {"type": 2, "name": "Wifi", "notes": "ssid guest"},
        ],
    }
    result = dict(parse_bitwarden_json(json.dumps(doc)))
    gh = result["GitHub"]
    assert (gh.username, gh.password, gh.url, gh.totp_secret) == ("octo", " pw with spaces ", "https://github.com", "JBSWY3DPEHPK3PXP")
    assert gh.favorite is True
    assert result["Wifi"].kind == "note" and result["Wifi"].notes == "ssid guest"


def test_encrypted_bitwarden_json_is_refused():
    with pytest.raises(ValueError, match="encrypted"):
        parse_bitwarden_json(json.dumps({"encrypted": True, "items": []}))


def test_parse_import_text_dispatches_json_and_csv():
    assert parse_import_text(json.dumps({"items": [{"type": 1, "name": "x", "login": {"password": "p"}}]}))[0][0] == "x"
    assert parse_import_text("name,password\ny,p\n")[0][0] == "y"


def test_onepassword_csv_columns():
    text = _csv(HEADERS["onepassword"], [["Bank", "https://bank.example", "me", "pw", "otpauth://totp/x?secret=ABC", "", "", "", "note"]])
    (name, entry), = parse_csv_rows(text)
    assert name == "Bank" and entry.url == "https://bank.example" and entry.totp_secret.startswith("otpauth://")
