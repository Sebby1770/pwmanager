"""Passkey (WebAuthn) second factor for cloud sign-in."""

from __future__ import annotations

import pytest

pytest.importorskip("webauthn")

import saas.mfa as mfa  # noqa: E402
from saas.mfa import rp_for  # noqa: E402
from tests.conftest import b64  # noqa: E402
from tests.soft_authenticator import SoftAuthenticator  # noqa: E402


@pytest.fixture
def site(make_api):
    api = make_api()
    auth = SoftAuthenticator(api.app.mfa.rp_id, api.app.mfa.origins[0])
    return api, auth


def _login(api, email, auth_key):
    api.cookie = None
    return api.request("POST", "/api/login", {"email": email, "auth_key": auth_key})


def _enroll(api, authenticator, auth_key, name="Laptop"):
    status, opts = api.request("POST", "/api/webauthn/register/options", {})
    assert status == 200, opts
    credential = authenticator.create(opts["publicKey"])
    return api.request(
        "POST", "/api/webauthn/register/verify",
        {"ceremony": opts["ceremony"], "credential": credential, "name": name, "auth_key": auth_key},
    )


@pytest.fixture
def enrolled(site):
    api, authenticator = site
    _, created, auth_key, _ = api.register("mfa@example.com")
    status, body = _enroll(api, authenticator, auth_key)
    assert status == 201, body
    return api, authenticator, auth_key, body["recovery_codes"], created["account"]["id"]


def test_rp_mapping():
    assert rp_for("https://vault.example.com") == ("vault.example.com", ["https://vault.example.com"])
    assert rp_for("http://127.0.0.1:8787") == ("localhost", ["http://127.0.0.1:8787"])
    assert rp_for("https://a.example", "example", ["https://b.example"]) == ("example", ["https://b.example", "https://a.example"])


def test_login_without_passkeys_is_unchanged(site):
    api, _ = site
    _, _, auth_key, _ = api.register("plain@example.com")
    status, body = _login(api, "plain@example.com", auth_key)
    assert status == 200 and body["account"]["mfa_enabled"] is False and api.cookie


def test_enrolment_returns_recovery_codes_once(enrolled):
    api, _, auth_key, codes, _ = enrolled
    assert len(codes) == 10 and len(set(codes)) == 10
    status, me = api.request("GET", "/api/me")
    assert me["account"]["mfa_enabled"] is True and me["account"]["recovery_codes_left"] == 10
    status, listing = api.request("GET", "/api/webauthn/credentials")
    assert [c["name"] for c in listing["credentials"]] == ["Laptop"]
    assert "public_key" not in listing["credentials"][0] and "credential_id" not in listing["credentials"][0]


def test_enrolment_requires_session_and_master_password(site):
    api, authenticator = site
    api.cookie = None
    assert api.request("POST", "/api/webauthn/register/options", {})[0] == 401
    _, _, auth_key, _ = api.register("reauth2@example.com")
    status, opts = api.request("POST", "/api/webauthn/register/options", {})
    credential = authenticator.create(opts["publicKey"])
    status, body = api.request("POST", "/api/webauthn/register/verify",
                               {"ceremony": opts["ceremony"], "credential": credential, "auth_key": b64(32)})
    assert status == 401 and body["error"] == "reauth_required"


def test_passkey_required_after_enrolment(enrolled):
    api, authenticator, auth_key, _, _ = enrolled
    status, body = _login(api, "mfa@example.com", auth_key)
    assert status == 200 and body["mfa_required"] is True
    assert api.cookie is None, "no session before the second factor"
    assert "account" not in body
    assert api.request("GET", "/api/me")[0] == 401

    assertion = authenticator.get(body["publicKey"])
    status, done = api.request("POST", "/api/login/webauthn", {"ceremony": body["ceremony"], "credential": assertion})
    assert status == 200, done
    assert done["account"]["email"] == "mfa@example.com" and api.cookie
    assert api.request("GET", "/api/me")[0] == 200
    assert api.request("GET", "/api/webauthn/credentials")[1]["credentials"][0]["last_used_at"]


def test_wrong_master_password_never_reaches_passkey_step(enrolled):
    api, _, _, _, _ = enrolled
    status, body = _login(api, "mfa@example.com", b64(32))
    assert status == 401 and "ceremony" not in body


def test_ceremony_is_single_use(enrolled):
    api, authenticator, auth_key, _, _ = enrolled
    _, body = _login(api, "mfa@example.com", auth_key)
    assertion = authenticator.get(body["publicKey"])
    assert api.request("POST", "/api/login/webauthn", {"ceremony": body["ceremony"], "credential": assertion})[0] == 200
    api.cookie = None
    replay = authenticator.get(body["publicKey"])
    status, err = api.request("POST", "/api/login/webauthn", {"ceremony": body["ceremony"], "credential": replay})
    assert status == 401 and err["error"] == "mfa_ceremony_invalid" and api.cookie is None


def test_failed_attempt_burns_the_ceremony(enrolled):
    api, authenticator, auth_key, _, _ = enrolled
    _, body = _login(api, "mfa@example.com", auth_key)
    bad = authenticator.get(body["publicKey"], challenge="AAAA")
    assert api.request("POST", "/api/login/webauthn", {"ceremony": body["ceremony"], "credential": bad})[0] == 401
    good = authenticator.get(body["publicKey"])
    status, err = api.request("POST", "/api/login/webauthn", {"ceremony": body["ceremony"], "credential": good})
    assert status == 401 and err["error"] == "mfa_ceremony_invalid"


@pytest.mark.parametrize("override", [{"origin": "https://evil.example"}, {"rp_id": "evil.example"}])
def test_assertion_from_another_origin_or_rp_is_rejected(enrolled, override):
    api, authenticator, auth_key, _, _ = enrolled
    _, body = _login(api, "mfa@example.com", auth_key)
    assertion = authenticator.get(body["publicKey"], **override)
    status, err = api.request("POST", "/api/login/webauthn", {"ceremony": body["ceremony"], "credential": assertion})
    assert status == 401 and err["error"] == "passkey_invalid" and api.cookie is None


def test_cloned_authenticator_counter_is_rejected(enrolled):
    api, authenticator, auth_key, _, _ = enrolled
    _, body = _login(api, "mfa@example.com", auth_key)
    assert api.request("POST", "/api/login/webauthn",
                       {"ceremony": body["ceremony"], "credential": authenticator.get(body["publicKey"])})[0] == 200
    _, body = _login(api, "mfa@example.com", auth_key)
    stale = authenticator.get(body["publicKey"], advance=False)  # same counter again
    status, err = api.request("POST", "/api/login/webauthn", {"ceremony": body["ceremony"], "credential": stale})
    assert status == 401 and err["error"] == "passkey_invalid"


def test_another_accounts_passkey_does_not_satisfy_mfa(enrolled):
    api, victim_auth, victim_key, _, _ = enrolled
    attacker = SoftAuthenticator(api.app.mfa.rp_id, api.app.mfa.origins[0])
    api.cookie = None
    _, _, attacker_key, _ = api.register("attacker@example.com")
    assert _enroll(api, attacker, attacker_key)[0] == 201
    # The attacker knows the victim's master password but holds only their own passkey.
    _, body = _login(api, "mfa@example.com", victim_key)
    status, err = api.request("POST", "/api/login/webauthn",
                              {"ceremony": body["ceremony"], "credential": attacker.get(body["publicKey"])})
    assert status == 401 and err["error"] == "passkey_invalid"


def test_registration_ceremony_cannot_complete_a_login(enrolled):
    api, authenticator, auth_key, _, _ = enrolled
    status, opts = api.request("POST", "/api/webauthn/register/options", {})
    api.cookie = None
    status, err = api.request("POST", "/api/login/webauthn",
                              {"ceremony": opts["ceremony"], "credential": authenticator.get(opts["publicKey"])})
    assert status == 401 and err["error"] == "mfa_ceremony_invalid"


def test_expired_ceremony_is_rejected(enrolled):
    api, authenticator, auth_key, _, _ = enrolled
    _, body = _login(api, "mfa@example.com", auth_key)
    api.db.execute("UPDATE mfa_ceremonies SET expires_at = 0")
    status, err = api.request("POST", "/api/login/webauthn",
                              {"ceremony": body["ceremony"], "credential": authenticator.get(body["publicKey"])})
    assert status == 401 and err["error"] == "mfa_ceremony_invalid"


def test_malformed_credential_is_rejected(enrolled):
    api, _, auth_key, _, _ = enrolled
    for bad in (None, "x", {"id": 5}, {"id": "nope"}):
        _, body = _login(api, "mfa@example.com", auth_key)
        status, _ = api.request("POST", "/api/login/webauthn", {"ceremony": body["ceremony"], "credential": bad})
        assert status == 401


def test_recovery_code_works_exactly_once(enrolled):
    api, _, auth_key, codes, _ = enrolled
    _, body = _login(api, "mfa@example.com", auth_key)
    sloppy = codes[0].lower().replace("-", " ")
    status, done = api.request("POST", "/api/login/recovery", {"ceremony": body["ceremony"], "code": sloppy})
    assert status == 200 and done["account"]["recovery_codes_left"] == 9
    _, body = _login(api, "mfa@example.com", auth_key)
    status, err = api.request("POST", "/api/login/recovery", {"ceremony": body["ceremony"], "code": codes[0]})
    assert status == 401 and err["error"] == "recovery_invalid"
    _, body = _login(api, "mfa@example.com", auth_key)
    assert api.request("POST", "/api/login/recovery", {"ceremony": "made-up", "code": codes[1]})[0] == 401


def test_regenerating_recovery_codes_invalidates_old_ones(enrolled):
    api, _, auth_key, codes, _ = enrolled
    assert api.request("POST", "/api/webauthn/recovery-codes", {"auth_key": b64(32)})[0] == 401
    status, body = api.request("POST", "/api/webauthn/recovery-codes", {"auth_key": auth_key})
    assert status == 200 and set(body["recovery_codes"]).isdisjoint(codes)
    _, login = _login(api, "mfa@example.com", auth_key)
    assert api.request("POST", "/api/login/recovery", {"ceremony": login["ceremony"], "code": codes[0]})[0] == 401


def test_removing_last_passkey_turns_mfa_off(enrolled):
    api, _, auth_key, codes, _ = enrolled
    cred = api.request("GET", "/api/webauthn/credentials")[1]["credentials"][0]
    assert api.request("POST", "/api/webauthn/credentials/delete", {"id": cred["id"]})[0] == 401
    assert api.request("POST", "/api/webauthn/credentials/delete", {"id": "nope", "auth_key": auth_key})[0] == 404
    status, body = api.request("POST", "/api/webauthn/credentials/delete", {"id": cred["id"], "auth_key": auth_key})
    assert status == 200 and body["mfa_enabled"] is False
    assert api.request("POST", "/api/webauthn/recovery-codes", {"auth_key": auth_key})[1]["error"] == "mfa_not_enabled"
    status, body = _login(api, "mfa@example.com", auth_key)
    assert status == 200 and "account" in body


def test_duplicate_registration_and_exclude_list(enrolled):
    api, authenticator, auth_key, _, _ = enrolled
    status, opts = api.request("POST", "/api/webauthn/register/options", {})
    assert opts["publicKey"]["excludeCredentials"][0]["id"]
    credential = authenticator.create(opts["publicKey"])
    status, err = api.request("POST", "/api/webauthn/register/verify",
                              {"ceremony": opts["ceremony"], "credential": credential, "auth_key": auth_key})
    assert status == 409 and err["error"] == "passkey_exists"


def test_second_passkey_does_not_reset_recovery_codes(enrolled):
    api, _, auth_key, codes, _ = enrolled
    second = SoftAuthenticator(api.app.mfa.rp_id, api.app.mfa.origins[0])
    status, body = _enroll(api, second, auth_key, name="Phone")
    assert status == 201 and "recovery_codes" not in body
    _, login = _login(api, "mfa@example.com", auth_key)
    status, _ = api.request("POST", "/api/login/webauthn",
                            {"ceremony": login["ceremony"], "credential": second.get(login["publicKey"])})
    assert status == 200


def test_bad_registration_is_rejected(site):
    api, authenticator = site
    _, _, auth_key, _ = api.register("badreg@example.com")
    status, opts = api.request("POST", "/api/webauthn/register/options", {})
    credential = authenticator.create(opts["publicKey"], origin="https://evil.example")
    status, err = api.request("POST", "/api/webauthn/register/verify",
                              {"ceremony": opts["ceremony"], "credential": credential, "auth_key": auth_key})
    assert status == 400 and err["error"] == "passkey_invalid"
    assert api.request("GET", "/api/me")[1]["account"]["mfa_enabled"] is False


def test_passkey_limit(site, monkeypatch):
    api, _ = site
    monkeypatch.setattr(mfa, "MAX_CREDENTIALS", 1)
    _, _, auth_key, _ = api.register("limit@example.com")
    assert _enroll(api, SoftAuthenticator(api.app.mfa.rp_id, api.app.mfa.origins[0]), auth_key)[0] == 201
    status, err = api.request("POST", "/api/webauthn/register/options", {})
    assert status == 400 and err["error"] == "too_many_passkeys"


def test_mfa_endpoints_are_rate_limited(enrolled):
    api, _, _, _, _ = enrolled
    statuses = [api.request("POST", "/api/login/recovery", {"ceremony": "x", "code": "y"})[0] for _ in range(12)]
    assert statuses[-1] == 429


def test_fails_closed_without_the_webauthn_library(enrolled, monkeypatch):
    api, _, auth_key, _, _ = enrolled
    monkeypatch.setattr(mfa, "WEBAUTHN_AVAILABLE", False)
    status, err = _login(api, "mfa@example.com", auth_key)
    assert status == 503 and err["error"] == "webauthn_unavailable" and api.cookie is None


def test_account_deletion_removes_passkeys(enrolled):
    api, _, auth_key, _, account_id = enrolled
    _, body = _login(api, "mfa@example.com", auth_key)
    status, _ = api.request("POST", "/api/login/recovery",
                            {"ceremony": body["ceremony"], "code": enrolled[3][0]})
    assert status == 200
    assert api.request("POST", "/api/account/delete", {"confirm": "DELETE", "auth_key": auth_key})[0] == 200
    for table in ("webauthn_credentials", "recovery_codes", "mfa_ceremonies"):
        assert api.db.execute(f"SELECT COUNT(*) AS n FROM {table} WHERE account_id = ?", (account_id,)).fetchone()["n"] == 0


def test_open_ceremonies_are_bounded(site):
    api, _ = site
    _, created, _, _ = api.register("spam@example.com")
    for _ in range(20):
        assert api.request("POST", "/api/webauthn/register/options", {})[0] == 200
    n = api.db.execute("SELECT COUNT(*) AS n FROM mfa_ceremonies WHERE account_id = ?",
                       (created["account"]["id"],)).fetchone()["n"]
    assert n == mfa.MAX_OPEN_CEREMONIES
