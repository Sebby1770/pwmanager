"""KDF v2 (Argon2id + HKDF): cross-language agreement, server rules, vendored code pin."""

from __future__ import annotations

import base64
import hashlib
import json
import re
import shutil
import subprocess
from pathlib import Path

import pytest

from pwmanager import cloudkdf
from saas import kdf as skdf
from saas.envelope import EnvelopeError, parse_envelope
from tests.conftest import b64

ROOT = Path(__file__).resolve().parent.parent
VENDOR = ROOT / "web" / "vendor" / "hash-wasm-argon2-4.13.0.umd.min.js"
VENDOR_SHA256 = "acfe11b015852f593aaddc51116f71dc7850e4551e6b34d42c1f88cf39635f03"


def _js_auth_key(password, email, salt, params) -> str:
    out = subprocess.run(
        ["node", "tests/js/saas_kdf.mjs", "--print", password, email, base64.b64encode(salt).decode(), json.dumps(params)],
        cwd=ROOT, capture_output=True, text=True, check=True, timeout=120,
    )
    return out.stdout.strip().splitlines()[-1]


@pytest.mark.skipif(shutil.which("node") is None, reason="node not installed")
@pytest.mark.parametrize("scheme", ["v1", "v2", "v2-heavier"])
def test_browser_and_python_derive_the_same_auth_key(scheme):
    params = {
        "v1": cloudkdf.legacy_params(),
        "v2": cloudkdf.default_params(),
        "v2-heavier": {**cloudkdf.default_params(), "m": 131072, "t": 4, "p": 2},
    }[scheme]
    salt = hashlib.sha256(scheme.encode()).digest()
    password, email = "Interop Master Password ✓", "  Mixed.Case@Example.com "
    _vault, auth, _ = cloudkdf.derive_keys(password, email, salt, params)
    assert _js_auth_key(password, email, salt, params) == base64.b64encode(auth).decode()


def test_v2_keys_are_independent_and_email_bound():
    salt = bytes(32)
    vault, auth, params = cloudkdf.derive_keys("correct horse battery", "a@example.com", salt, cloudkdf.default_params())
    assert params["alg"] == "argon2id" and vault != auth and len(vault) == len(auth) == 32
    _, other_auth, _ = cloudkdf.derive_keys("correct horse battery", "b@example.com", salt, cloudkdf.default_params())
    assert other_auth != auth


@pytest.mark.parametrize(
    "bad",
    [
        {"alg": "argon2id", "m": 1024, "t": 3, "p": 4},
        {"alg": "argon2id", "m": 65536, "t": 1, "p": 4},
        {"alg": "argon2id", "m": 10**9, "t": 3, "p": 4},
        {"alg": "argon2id", "m": True, "t": 3, "p": 4},
        {"alg": "scrypt"},
        {"alg": "PBKDF2-HMAC-SHA256", "iterations": 10},
    ],
)
def test_client_and_server_refuse_the_same_weak_params(bad):
    with pytest.raises(cloudkdf.KdfError):
        cloudkdf.normalize(bad)
    with pytest.raises(ValueError):
        skdf.canonical(bad)


def test_server_canonicalises_v2_and_keeps_v1_compatible():
    out = skdf.canonical({"alg": "Argon2id", "m": 131072, "t": 4, "p": 2, "note": "dropped"})
    assert out == {**skdf.default_params(), "m": 131072, "t": 4, "p": 2}
    assert skdf.canonical({"iterations": 600000})["alg"] == "PBKDF2-HMAC-SHA256"  # pre-3.3 clients
    assert skdf.canonical(None)["alg"] == "argon2id"
    assert skdf.rank(skdf.default_params()) == 2 and skdf.rank(skdf.legacy_params()) == 1


def test_register_with_v2_and_prelogin_defaults(make_api):
    api = make_api()
    status, body, *_ = api.register("v2@example.com", kdf_params=skdf.default_params())
    assert status == 201 and body["account"]["kdf_params"]["alg"] == "argon2id"
    # Unknown emails get the v2 defaults new accounts use.
    status, pre = api.request("POST", "/api/prelogin", {"email": "nobody@example.com"})
    assert pre["kdf_params"] == skdf.default_params()
    status, pre = api.request("POST", "/api/prelogin", {"email": "v2@example.com"})
    assert pre["kdf_params"]["alg"] == "argon2id"


def test_envelope_accepts_v2_and_rejects_weak_v2():
    env = {"v": 1, "nonce": b64(12), "ct": b64(48), "kdf": {**skdf.default_params(), "salt": b64(32)}}
    assert parse_envelope(env)["kdf"]["alg"] == "argon2id"
    with pytest.raises(EnvelopeError):
        parse_envelope({**env, "kdf": {**env["kdf"], "t": 1}})
    with pytest.raises(EnvelopeError):
        parse_envelope({**env, "kdf": {"salt": b64(32)}})


def test_vendored_argon2_is_pinned_and_served_with_sri():
    assert hashlib.sha256(VENDOR.read_bytes()).hexdigest() == VENDOR_SHA256, "vendored file changed"
    sri = "sha384-" + base64.b64encode(hashlib.sha384(VENDOR.read_bytes()).digest()).decode()
    html = (ROOT / "web" / "vault.html").read_text()
    tag = re.search(r'<script[^>]+hash-wasm-argon2[^>]+>', html)
    assert tag, "vault.html must load the vendored Argon2 build"
    assert f'integrity="{sri}"' in tag.group(0)
    readme = (ROOT / "web" / "vendor" / "README.md").read_text()
    assert VENDOR_SHA256 in readme
    text = VENDOR.read_text()
    for banned in ("fetch(", "XMLHttpRequest", "importScripts", "eval(", "new Function"):
        assert banned not in text, banned
