"""POST /api/account/rekey: master-password change and KDF upgrade, atomically."""

from __future__ import annotations

import json

import pytest

from saas import kdf as skdf
from tests.cloud_helpers import register, v1, v2, vault_doc
from tests.conftest import ApiClient, b64, make_pro

EMAIL = "rekey@example.com"


@pytest.fixture
def pro_v1(make_api):
    """A Pro account on the legacy PBKDF2 scheme, with a cloud vault and a revision."""
    api = make_api()
    old = v1(EMAIL)
    status, body = register(api, EMAIL, old)
    assert status == 201, body
    make_pro(api, body["account"]["id"])
    for saved_at in (1, 2):
        assert api.request("PUT", "/api/vault", old.seal(vault_doc("a", "b", saved_at=saved_at)))[0] == 200
    assert len(api.request("GET", "/api/vault/revisions")[1]["revisions"]) == 2
    return api, old, body["account"]["id"]


def _rekey(api, current, new, envelope=None, reason="change", **override):
    body = {
        "auth_key": current.auth_b64,
        "new_auth_key": new.auth_b64,
        "new_kdf_salt": new.salt_b64,
        "new_kdf_params": new.params,
        "envelope": envelope,
        "reason": reason,
    }
    body.update(override)
    return api.request("POST", "/api/account/rekey", body)


def test_kdf_upgrade_swaps_everything_atomically(pro_v1):
    api, old, account_id = pro_v1
    new = v2(EMAIL)  # same password, new scheme, new salt
    status, body = _rekey(api, old, new, new.seal(vault_doc("a", "b", saved_at=3)), reason="kdf_upgrade")
    assert status == 200, body
    assert body["vault_replaced"] is True and body["account"]["kdf_params"]["alg"] == "argon2id"

    # The cloud copy now opens with the new key only, and old revisions are gone.
    status, got = api.request("GET", "/api/vault")
    assert new.open(got["envelope"])["entries"][0]["name"] == "a"
    assert got["envelope"]["kdf"]["alg"] == "argon2id" and got["envelope"]["kdf"]["salt"] == new.salt_b64
    with pytest.raises(Exception):
        old.open(got["envelope"])
    assert api.request("GET", "/api/vault/revisions")[1]["revisions"][1:] == []

    # Prelogin advertises the new scheme; old key no longer signs in, new key does.
    status, pre = api.request("POST", "/api/prelogin", {"email": EMAIL})
    assert pre["kdf_salt"] == new.salt_b64 and pre["kdf_params"]["alg"] == "argon2id"
    fresh = ApiClient(api.base)
    assert fresh.request("POST", "/api/login", {"email": EMAIL, "auth_key": old.auth_b64})[0] == 401
    assert fresh.request("POST", "/api/login", {"email": EMAIL, "auth_key": new.auth_b64})[0] == 200
    events = [r["event"] for r in api.db.execute("SELECT event FROM audit_events WHERE account_id = ?", (account_id,))]
    assert "kdf_upgraded" in events


def test_rekey_revokes_every_other_session(pro_v1):
    api, old, _ = pro_v1
    other = ApiClient(api.base)
    assert other.request("POST", "/api/login", {"email": EMAIL, "auth_key": old.auth_b64})[0] == 200
    assert other.request("GET", "/api/me")[0] == 200
    new = v2(EMAIL, "a brand new master password")
    assert _rekey(api, old, new, new.seal(vault_doc("a")))[0] == 200
    assert other.request("GET", "/api/me")[0] == 401, "other devices must sign in again"
    assert api.request("GET", "/api/me")[0] == 200, "the caller gets a fresh session"


def test_rekey_requires_current_master_password(pro_v1):
    api, old, _ = pro_v1
    new = v2(EMAIL)
    status, body = _rekey(api, old, new, new.seal(vault_doc("a")), auth_key=b64(32))
    assert status == 401 and body["error"] == "reauth_required"
    api.cookie = None
    assert _rekey(api, old, new, new.seal(vault_doc("a")))[0] == 401


@pytest.mark.parametrize(
    "case,error",
    [
        ("downgrade", "kdf_downgrade"),
        ("same_salt", "salt_reused"),
        ("same_key", "key_unchanged"),
        ("no_envelope", "envelope_required"),
        ("wrong_envelope_salt", "envelope_mismatch"),
        ("weak_params", "bad_request"),
        ("bad_key", "bad_request"),
    ],
)
def test_rekey_refuses_anything_half_migrated(make_api, case, error):
    api = make_api()
    cur = v2(EMAIL)
    status, body = register(api, EMAIL, cur)
    make_pro(api, body["account"]["id"])
    assert api.request("PUT", "/api/vault", cur.seal(vault_doc("a")))[0] == 200
    new = v2(EMAIL, "a different master password")
    kwargs = {}
    envelope = new.seal(vault_doc("a"))
    if case == "downgrade":
        new = v1(EMAIL, "a different master password")
        envelope = new.seal(vault_doc("a"))
    elif case == "same_salt":
        kwargs["new_kdf_salt"] = cur.salt_b64
    elif case == "same_key":
        kwargs.update(new_auth_key=cur.auth_b64)
    elif case == "no_envelope":
        envelope = None
    elif case == "wrong_envelope_salt":
        envelope = {**envelope, "kdf": {**envelope["kdf"], "salt": b64(32)}}
    elif case == "weak_params":
        kwargs["new_kdf_params"] = {**skdf.default_params(), "m": 1024}
    elif case == "bad_key":
        kwargs["new_auth_key"] = b64(4)
    status, err = _rekey(api, cur, new, envelope, **kwargs)
    assert status == 400 and err["error"] == error, err
    # Nothing changed.
    fresh = ApiClient(api.base)
    assert fresh.request("POST", "/api/login", {"email": EMAIL, "auth_key": cur.auth_b64})[0] == 200
    assert cur.open(api.request("GET", "/api/vault")[1]["envelope"])["entries"][0]["name"] == "a"


def test_free_account_cannot_create_a_blob_through_rekey(make_api):
    api = make_api()
    cur = v2(EMAIL)
    register(api, EMAIL, cur)
    new = v2(EMAIL, "a different master password")
    status, body = _rekey(api, cur, new, new.seal(vault_doc("a")))
    assert status == 200 and body["vault_replaced"] is False
    assert api.db.get_vault(body["account"]["id"]) is None


def test_failed_transaction_leaves_account_untouched(pro_v1, monkeypatch):
    api, old, account_id = pro_v1
    before = dict(api.db.get_account_by_id(account_id))
    real = api.db._insert_session

    def boom(*a, **k):
        raise RuntimeError("disk full mid-transaction")

    monkeypatch.setattr(api.db, "_insert_session", boom)
    new = v2(EMAIL)
    assert _rekey(api, old, new, new.seal(vault_doc("a")))[0] == 500
    monkeypatch.setattr(api.db, "_insert_session", real)
    after = dict(api.db.get_account_by_id(account_id))
    assert after["auth_verifier"] == before["auth_verifier"] and after["kdf_salt"] == before["kdf_salt"]
    assert len(api.request("GET", "/api/vault/revisions")[1]["revisions"]) == 2, "revisions kept"
    assert old.open(api.request("GET", "/api/vault")[1]["envelope"])["saved_at"] == 2


def test_rekey_body_may_carry_a_large_vault(pro_v1):
    api, old, _ = pro_v1
    new = v2(EMAIL)
    big = vault_doc(*[f"entry-{i}" for i in range(4000)])
    envelope = new.seal(big)
    assert len(json.dumps(envelope)) > 64 * 1024  # well past the 16 KiB JSON cap
    status, body = _rekey(api, old, new, envelope)
    assert status == 200, body
    assert len(new.open(api.request("GET", "/api/vault")[1]["envelope"])["entries"]) == 4000


def test_passkeys_survive_a_rekey(make_api):
    pytest.importorskip("webauthn")
    from tests.soft_authenticator import SoftAuthenticator

    api = make_api()
    cur = v2(EMAIL)
    register(api, EMAIL, cur)
    auth = SoftAuthenticator(api.app.mfa.rp_id, api.app.mfa.origins[0])
    status, opts = api.request("POST", "/api/webauthn/register/options", {})
    api.request("POST", "/api/webauthn/register/verify",
                {"ceremony": opts["ceremony"], "credential": auth.create(opts["publicKey"]), "auth_key": cur.auth_b64})
    new = v2(EMAIL, "a different master password")
    assert _rekey(api, cur, new)[0] == 200
    api.cookie = None
    status, body = api.request("POST", "/api/login", {"email": EMAIL, "auth_key": new.auth_b64})
    assert body.get("mfa_required") is True, "2FA still enforced after a password change"


