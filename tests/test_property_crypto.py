"""Property-based tests (hypothesis) for the CLI vault format and SaaS envelope."""

from __future__ import annotations

import base64
import binascii
import copy
import hashlib
import json
import shutil
import subprocess
from pathlib import Path

import pytest
from cryptography.exceptions import InvalidTag
from cryptography.fernet import InvalidToken
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from hypothesis import HealthCheck, assume, given, settings
from hypothesis import strategies as st

import pwmanager.crypto as pcrypto
from pwmanager.constants import CIPHER_AESGCM, CIPHER_FERNET
from pwmanager.models import Entry
from pwmanager.vault import Vault, VaultIntegrityError
from saas.envelope import EnvelopeError, parse_envelope

ROOT = Path(__file__).resolve().parent.parent
SETTINGS = settings(max_examples=150, deadline=None, suppress_health_check=[HealthCheck.too_slow])

# One fixed key per cipher; key derivation is not what these properties test.
KEY = base64.urlsafe_b64encode(bytes(range(32)))


@pytest.fixture(scope="module", autouse=True)
def fast_pbkdf2():
    """Vault tamper tests unlock hundreds of times; 600k iterations each is minutes."""
    original = pcrypto.PBKDF2_ITERATIONS
    pcrypto.PBKDF2_ITERATIONS = 1_000
    yield
    pcrypto.PBKDF2_ITERATIONS = original


# ------------------------------------------------------------------ AEAD layer


@SETTINGS
@given(data=st.binary(max_size=4096), cipher=st.sampled_from([CIPHER_AESGCM, CIPHER_FERNET]))
def test_encrypt_decrypt_roundtrip(data, cipher):
    token = pcrypto.encrypt_bytes(data, KEY, cipher)
    assert pcrypto.decrypt_bytes(token, KEY, cipher) == data


@SETTINGS
@given(data=st.binary(max_size=256))
def test_gcm_nonces_never_repeat_for_same_plaintext(data):
    a = base64.urlsafe_b64decode(pcrypto.encrypt_bytes(data, KEY, CIPHER_AESGCM))
    b = base64.urlsafe_b64decode(pcrypto.encrypt_bytes(data, KEY, CIPHER_AESGCM))
    assert a[:12] != b[:12]


@SETTINGS
@given(
    data=st.binary(max_size=512),
    cipher=st.sampled_from([CIPHER_AESGCM, CIPHER_FERNET]),
    where=st.floats(min_value=0, max_value=1, exclude_max=True),
    mask=st.integers(min_value=1, max_value=255),
)
def test_flipping_any_ciphertext_byte_fails(data, cipher, where, mask):
    raw = bytearray(base64.urlsafe_b64decode(pcrypto.encrypt_bytes(data, KEY, cipher)))
    raw[int(where * len(raw))] ^= mask
    with pytest.raises(InvalidToken):
        pcrypto.decrypt_bytes(base64.urlsafe_b64encode(bytes(raw)), KEY, cipher)


@SETTINGS
@given(data=st.binary(max_size=64), cut=st.integers(min_value=1, max_value=40))
def test_truncated_gcm_token_fails(data, cut):
    raw = base64.urlsafe_b64decode(pcrypto.encrypt_bytes(data, KEY, CIPHER_AESGCM))
    with pytest.raises(InvalidToken):
        pcrypto.decrypt_bytes(base64.urlsafe_b64encode(raw[:-cut]), KEY, CIPHER_AESGCM)


@SETTINGS
@given(
    payload=st.fixed_dictionaries(
        {
            "version": st.integers(0, 10),
            "kdf": st.sampled_from(["argon2id", "pbkdf2"]),
            "cipher": st.sampled_from([CIPHER_AESGCM, CIPHER_FERNET]),
            "salt": st.text(min_size=1, max_size=30),
            "vault": st.text(min_size=1, max_size=60),
        }
    ),
    field=st.sampled_from(["version", "kdf", "cipher", "salt", "vault"]),
    replacement=st.text(max_size=30),
)
def test_file_hmac_binds_every_header_field(payload, field, replacement):
    changed = dict(payload, **{field: replacement})
    assume(str(changed[field]) != str(payload[field]))
    assert pcrypto.file_hmac(payload, KEY) != pcrypto.file_hmac(changed, KEY)


# ------------------------------------------------------------------ vault file


PASSWORD = "property based master password"


@pytest.fixture(scope="module")
def vault_template(tmp_path_factory, fast_pbkdf2):
    path = tmp_path_factory.mktemp("prop") / "vault.json"
    v = Vault(str(path))
    v.create(PASSWORD, kdf="pbkdf2")
    v.add("github", Entry(username="octo", password="hunter2-but-longer", totp_secret="JBSWY3DPEHPK3PXP"))
    v.add("note", Entry(notes="line one\nline two", kind="note"))
    return json.loads(path.read_text())


def _write(tmp_path, payload) -> str:
    path = tmp_path / "v.json"
    path.write_text(json.dumps(payload))
    return str(path)


def _mutate_str(value: str, index: int, char: str) -> str:
    i = index % len(value)
    return value[:i] + char + value[i + 1 :]


@settings(max_examples=120, deadline=None, suppress_health_check=[HealthCheck.function_scoped_fixture])
@given(
    field=st.sampled_from(["version", "kdf", "cipher", "salt", "vault", "hmac"]),
    index=st.integers(min_value=0, max_value=10_000),
    char=st.characters(codec="utf-8", exclude_characters="\x00"),
)
def test_tampering_any_vault_field_never_opens_silently(tmp_path, vault_template, field, index, char):
    payload = copy.deepcopy(vault_template)
    if field == "version":
        payload["version"] = payload["version"] + 1 + index % 5
    elif field == "kdf":
        payload["kdf"] = "argon2id" if index % 2 else "scrypt"
    else:
        mutated = _mutate_str(payload[field], index, char)
        assume(mutated != payload[field])
        payload[field] = mutated
    with pytest.raises((InvalidToken, VaultIntegrityError, ValueError, binascii.Error)):
        Vault(_write(tmp_path, payload)).unlock(PASSWORD)


@settings(max_examples=30, deadline=None, suppress_health_check=[HealthCheck.function_scoped_fixture])
@given(field=st.sampled_from(["version", "kdf", "cipher", "salt", "vault", "hmac"]))
def test_removing_any_vault_field_never_opens_silently(tmp_path, vault_template, field):
    payload = copy.deepcopy(vault_template)
    del payload[field]
    with pytest.raises((InvalidToken, VaultIntegrityError, ValueError)):
        Vault(_write(tmp_path, payload)).unlock(PASSWORD)


def test_untampered_template_still_opens(tmp_path, vault_template):
    v = Vault(_write(tmp_path, vault_template))
    v.unlock(PASSWORD)
    assert v.entries["github"].password == "hunter2-but-longer"


@settings(max_examples=40, deadline=None, suppress_health_check=[HealthCheck.function_scoped_fixture])
@given(
    names=st.lists(st.text(min_size=1, max_size=20), min_size=1, max_size=5, unique=True),
    secret=st.text(max_size=80),
)
def test_vault_save_unlock_roundtrip(tmp_path, names, secret):
    path = str(tmp_path / "rt.json")
    v = Vault(path)
    v.create(PASSWORD, kdf="pbkdf2")
    for name in names:
        v.entries[name] = Entry(password=secret, notes=secret)
    v.save()
    w = Vault(path)
    w.unlock(PASSWORD)
    assert sorted(w.entries) == sorted(names)
    assert all(e.password == secret and e.notes == secret for e in w.entries.values())


# ------------------------------------------------------------------ SaaS envelope


json_values = st.recursive(
    st.none() | st.booleans() | st.integers() | st.floats(allow_nan=False) | st.text(max_size=20),
    lambda children: st.lists(children, max_size=4) | st.dictionaries(st.text(max_size=8), children, max_size=4),
    max_leaves=12,
)


def _b64(n: int) -> str:
    return base64.b64encode(bytes(range(n))).decode()


def _valid_envelope() -> dict:
    return {"v": 1, "nonce": _b64(12), "ct": _b64(32),
            "kdf": {"alg": "PBKDF2-HMAC-SHA256", "iterations": 600000, "salt": _b64(32)}}


@SETTINGS
@given(value=json_values)
def test_parse_envelope_rejects_garbage_cleanly(value):
    try:
        parse_envelope(value)
    except EnvelopeError:
        pass


@SETTINGS
@given(key=st.sampled_from(["v", "nonce", "ct", "kdf"]), value=json_values)
def test_parse_envelope_field_fuzz(key, value):
    env = _valid_envelope()
    env[key] = value
    try:
        out = parse_envelope(env)
    except EnvelopeError:
        return
    # Anything accepted is canonical and stable under re-parsing.
    assert parse_envelope(out) == out
    assert set(out) <= {"v", "nonce", "ct", "kdf", "updated_at"}


@SETTINGS
@given(extra=st.dictionaries(st.text(min_size=1, max_size=12), json_values, max_size=4))
def test_parse_envelope_never_keeps_unknown_kdf_fields(extra):
    env = _valid_envelope()
    env["kdf"] = {**extra, **env["kdf"]}
    out = parse_envelope(env)
    assert set(out["kdf"]) == {"alg", "hash", "iterations", "dk_len", "salt", "email_mix"}


JS_ENVELOPE = """
import { deriveKeys, encryptVault, b64ToBytes } from "./web/saas/crypto.js";
const [password, email, salt] = process.argv.slice(-3);
const keys = await deriveKeys(password, email, b64ToBytes(salt));
const env = await encryptVault(keys.vaultKey, { version: 1, entries: [{ name: "x", password: "y" }] }, keys.saltB64);
console.log(JSON.stringify(env));
"""


@pytest.fixture(scope="module")
def js_envelope():
    """A real envelope produced by the browser crypto module, plus its vaultKey."""
    if shutil.which("node") is None:
        pytest.skip("node not installed")
    email, password = "interop@example.com", "interop master password"
    salt = bytes(range(32))
    out = subprocess.run(
        ["node", "--input-type=module", "-e", JS_ENVELOPE, password, email, base64.b64encode(salt).decode()],
        cwd=ROOT, capture_output=True, text=True, check=True, timeout=60,
    )
    envelope = json.loads(out.stdout)
    mixed = hashlib.sha256(salt + email.encode()).digest()
    vault_key = hashlib.pbkdf2_hmac("sha256", password.encode(), mixed, 600_000, 64)[:32]
    return envelope, vault_key


def _open_js(envelope, key):
    nonce = base64.b64decode(envelope["nonce"])
    ct = base64.b64decode(envelope["ct"])
    return json.loads(AESGCM(key).decrypt(nonce, ct, b"pwmanager-vault-v1"))


def test_js_envelope_decrypts_in_python(js_envelope):
    envelope, key = js_envelope
    parse_envelope(envelope)
    assert _open_js(envelope, key)["entries"][0]["password"] == "y"


@SETTINGS
@given(
    field=st.sampled_from(["nonce", "ct"]),
    where=st.floats(min_value=0, max_value=1, exclude_max=True),
    mask=st.integers(min_value=1, max_value=255),
)
def test_tampering_any_js_envelope_byte_fails(js_envelope, field, where, mask):
    envelope, key = js_envelope
    raw = bytearray(base64.b64decode(envelope[field]))
    raw[int(where * len(raw))] ^= mask
    tampered = dict(envelope, **{field: base64.b64encode(bytes(raw)).decode()})
    with pytest.raises(InvalidTag):
        _open_js(tampered, key)


def test_js_envelope_is_bound_to_its_aad(js_envelope):
    envelope, key = js_envelope
    nonce, ct = base64.b64decode(envelope["nonce"]), base64.b64decode(envelope["ct"])
    with pytest.raises(InvalidTag):
        AESGCM(key).decrypt(nonce, ct, b"pwmanager-vault-v2")
