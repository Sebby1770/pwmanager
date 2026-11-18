"""CLI <-> cloud sync against a live server, speaking the web vault's format."""

from __future__ import annotations

import json
import os
import stat

import pytest

from pwmanager import cloud
from pwmanager.cli import main as cli_main
from pwmanager.models import Entry
from pwmanager.vault import Vault
from saas import kdf as skdf
from tests.cloud_helpers import PASSWORD, register, v2, vault_doc
from tests.conftest import ApiClient, make_pro

EMAIL = "cli-sync@example.com"
LOCAL_PW = "local cli master password"


@pytest.fixture(autouse=True)
def isolated_config(tmp_path, monkeypatch):
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "config"))


@pytest.fixture
def account(make_api):
    api = make_api()
    keys = v2(EMAIL)
    status, body = register(api, EMAIL, keys)
    assert status == 201
    return api, keys, body["account"]["id"]


@pytest.fixture
def vault(tmp_path):
    v = Vault(str(tmp_path / "vault.json"))
    v.create(LOCAL_PW, kdf="pbkdf2")
    return v


def _server(api):
    return f"http://127.0.0.1:{api.port}"


def _login(api, vault, password=PASSWORD, code=lambda: ""):
    return cloud.login(vault.path, _server(api), EMAIL, password, code)


def _remote(api, keys):
    """Read the cloud vault the way the browser does."""
    reader = ApiClient(api.base)
    reader.request("POST", "/api/login", {"email": EMAIL, "auth_key": keys.auth_b64})
    status, body = reader.request("GET", "/api/vault")
    return keys.open(body["envelope"]) if status == 200 else None


def _web_put(api, keys, doc):
    writer = ApiClient(api.base)
    writer.request("POST", "/api/login", {"email": EMAIL, "auth_key": keys.auth_b64})
    assert writer.request("PUT", "/api/vault", keys.seal(doc))[0] == 200


def test_login_stores_nothing_that_opens_the_vault(account, vault):
    api, keys, _ = account
    state = _login(api, vault)
    path = cloud.state_path(vault.path)
    assert stat.S_IMODE(os.stat(path).st_mode) == 0o600
    text = path.read_text()
    for secret in (PASSWORD, keys.auth_b64, keys.vault_key.hex(), keys.auth_key.hex()):
        assert secret not in text
    saved = json.loads(text)
    assert set(saved) == {"server", "email", "token", "account_id", "kdf_rank", "key_check", "base", "linked_at"}
    assert saved["kdf_rank"] == 2 and state["account"]["email"] == EMAIL
    sessions = api.db.execute("SELECT device_label FROM sessions").fetchall()
    assert any(r["device_label"] == "pwmanager CLI" for r in sessions)


def test_wrong_password_and_insecure_server_are_refused(account, vault):
    api, _, _ = account
    with pytest.raises(cloud.CloudError) as err:
        _login(api, vault, password="not the cloud password")
    assert err.value.code == "invalid_credentials"
    with pytest.raises(cloud.CloudError) as err:
        cloud.login(vault.path, "http://vault.example.com", EMAIL, PASSWORD, lambda: "")
    assert err.value.code == "insecure_server"
    assert cloud.check_server_url("https://vault.example.com/some/path") == "https://vault.example.com"
    assert cloud.check_server_url("http://localhost:8787") == "http://localhost:8787"


def test_two_way_sync_with_the_web_format(account, vault):
    api, keys, account_id = account
    make_pro(api, account_id)
    _web_put(api, keys, vault_doc("from-web", saved_at=1))
    vault.add("from-cli", Entry(username="me", password="cli-secret-1", totp_secret="JBSWY3DPEHPK3PXP"))
    _login(api, vault)

    report = cloud.sync(vault, PASSWORD)
    assert report.added_local == ["from-web"] and report.added_remote == ["from-cli"]
    assert sorted(vault.entries) == ["from-cli", "from-web"]
    remote = _remote(api, keys)
    by_name = {e["name"]: e for e in remote["entries"]}
    assert by_name["from-cli"]["password"] == "cli-secret-1" and by_name["from-cli"]["totp_secret"] == "JBSWY3DPEHPK3PXP"
    assert by_name["from-cli"]["id"] == vault.entries["from-cli"].cloud_id
    assert remote["saved_at"] > 1, "sealed timestamp moves so web clients pick the new copy"

    # The local vault on disk keeps the cloud ids (reopen from file).
    reopened = Vault(vault.path)
    reopened.unlock(LOCAL_PW)
    assert reopened.entries["from-web"].cloud_id == by_name["from-web"]["id"]

    # Delete locally -> gone remotely; delete remotely -> gone locally.
    reopened.delete("from-web")
    cloud.sync(reopened, PASSWORD)
    remote = _remote(api, keys)
    assert [e["name"] for e in remote["entries"]] == ["from-cli"]
    _web_put(api, keys, {**remote, "entries": [], "saved_at": remote["saved_at"] + 1})
    report = cloud.sync(reopened, PASSWORD)
    assert report.deleted_local == ["from-cli"] and reopened.entries == {}
    assert cloud.sync(reopened, PASSWORD).lines() == []


def test_free_plan_can_pull_but_not_upload(account, vault):
    api, keys, account_id = account
    make_pro(api, account_id)
    _web_put(api, keys, vault_doc("cloud-entry"))
    api.db.execute("UPDATE accounts SET plan = 'free', plan_status = 'canceled' WHERE id = ?", (account_id,))
    vault.add("local-entry", Entry(password="x"))
    _login(api, vault)
    with pytest.raises(cloud.CloudError) as err:
        cloud.sync(vault, PASSWORD)
    assert err.value.code == "pro_required"
    assert sorted(vault.entries) == ["local-entry"], "a refused sync changes nothing"
    report = cloud.sync(vault, PASSWORD, mode="pull")
    assert sorted(vault.entries) == ["cloud-entry", "local-entry"] and report.added_local == ["cloud-entry"]
    assert [e["name"] for e in _remote(api, keys)["entries"]] == ["cloud-entry"]


def test_dry_run_changes_nothing(account, vault):
    api, keys, account_id = account
    make_pro(api, account_id)
    vault.add("x", Entry(password="x"))
    _login(api, vault)
    report = cloud.sync(vault, PASSWORD, dry_run=True)
    assert report.added_remote == ["x"] and _remote(api, keys) is None
    assert vault.entries["x"].cloud_id == ""


def test_sync_refuses_wrong_password_downgrade_and_revoked_sessions(account, vault):
    api, keys, account_id = account
    make_pro(api, account_id)
    _login(api, vault)
    with pytest.raises(cloud.CloudError) as err:
        cloud.sync(vault, "a wrong cloud master password")
    assert err.value.code == "wrong_password"

    api.db.execute("UPDATE accounts SET kdf_params = ? WHERE id = ?", (json.dumps(skdf.legacy_params()), account_id))
    with pytest.raises(cloud.CloudError) as err:
        cloud.sync(vault, PASSWORD)
    assert err.value.code == "kdf_downgrade"
    api.db.execute("UPDATE accounts SET kdf_params = ? WHERE id = ?", (json.dumps(keys.params), account_id))

    api.db.execute("DELETE FROM sessions")  # e.g. a password change on another device
    with pytest.raises(cloud.CloudError) as err:
        cloud.sync(vault, PASSWORD)
    assert err.value.code == "session_expired"
    with pytest.raises(cloud.CloudError):
        cloud.status(vault.path)


def test_concurrent_write_is_merged_not_clobbered(account, vault, monkeypatch):
    api, keys, account_id = account
    make_pro(api, account_id)
    _web_put(api, keys, vault_doc("base"))
    vault.add("cli-edit", Entry(password="c"))
    _login(api, vault)
    real_get = cloud.CloudClient.get_vault
    calls = {"n": 0}

    def get_then_race(self):
        envelope, etag = real_get(self)
        calls["n"] += 1
        if calls["n"] == 1:  # another device saves right after we read
            doc = keys.open(envelope)
            doc["entries"].append({"id": "web-2", "name": "web-edit", "password": "w", "updated_at": 5})
            _web_put(api, keys, doc)
        return envelope, etag

    monkeypatch.setattr(cloud.CloudClient, "get_vault", get_then_race)
    cloud.sync(vault, PASSWORD)
    assert calls["n"] == 2, "the 409 triggered one re-read and re-merge"
    assert {e["name"] for e in _remote(api, keys)["entries"]} == {"base", "web-edit", "cli-edit"}
    assert sorted(vault.entries) == ["base", "cli-edit", "web-edit"]


def test_server_if_match_semantics(account):
    api, keys, account_id = account
    make_pro(api, account_id)
    first = keys.seal(vault_doc("a"))
    assert api.request("PUT", "/api/vault", first, headers={"If-None-Match": "*"})[0] == 200
    status, body = api.request("GET", "/api/vault")
    etag = body["etag"]
    status, err = api.request("PUT", "/api/vault", keys.seal(vault_doc("b")), headers={"If-None-Match": "*"})
    assert status == 409 and err["error"] == "vault_conflict" and err["etag"] == etag
    assert api.request("PUT", "/api/vault", keys.seal(vault_doc("c")), headers={"If-Match": '"stale"'})[0] == 409
    status, ok = api.request("PUT", "/api/vault", keys.seal(vault_doc("d")), headers={"If-Match": etag})
    assert status == 200 and ok["etag"] != etag
    assert api.request("PUT", "/api/vault", keys.seal(vault_doc("e")))[0] == 200, "no header: unconditional (web client)"


def test_passkey_account_signs_in_with_a_recovery_code(account, vault):
    pytest.importorskip("webauthn")
    from tests.soft_authenticator import SoftAuthenticator

    api, keys, _ = account
    auth = SoftAuthenticator(api.app.mfa.rp_id, api.app.mfa.origins[0])
    status, opts = api.request("POST", "/api/webauthn/register/options", {})
    status, enrolled = api.request("POST", "/api/webauthn/register/verify",
                                   {"ceremony": opts["ceremony"], "credential": auth.create(opts["publicKey"]),
                                    "auth_key": keys.auth_b64})
    codes = enrolled["recovery_codes"]
    with pytest.raises(cloud.CloudError) as err:
        _login(api, vault)
    assert err.value.code == "mfa_required"
    state = _login(api, vault, code=lambda: codes[0])
    assert state["account"]["recovery_codes_left"] == 9


def test_cli_end_to_end(account, vault, monkeypatch, capsys):
    api, keys, account_id = account
    make_pro(api, account_id)
    monkeypatch.setenv("PWMANAGER_PASSWORD", LOCAL_PW)
    monkeypatch.setenv("PWMANAGER_CLOUD_PASSWORD", PASSWORD)
    vault.add("shell-entry", Entry(password="from the shell"))
    base = ["--vault", vault.path, "--password-env", "cloud"]
    assert cli_main(base + ["login", "--server", _server(api), "--email", EMAIL]) == 0
    assert cli_main(base + ["sync"]) == 0
    assert "uploaded new: shell-entry" in capsys.readouterr().out
    assert cli_main(base + ["status"]) == 0
    assert "Plan: Pro" in capsys.readouterr().out
    assert cli_main(base + ["sync"]) == 0
    assert "Already in sync" in capsys.readouterr().out
    assert [e["name"] for e in _remote(api, keys)["entries"]] == ["shell-entry"]
    assert cli_main(base + ["logout"]) == 0
    assert not cloud.state_path(vault.path).exists()
    assert cli_main(base + ["sync"]) == 1
    assert "not linked" in capsys.readouterr().err


def test_cli_works_in_the_browser(account, vault, browser):
    """Entries pushed from the terminal open in the web vault, and back."""
    pytest.importorskip("playwright.sync_api")
    from tests.e2e_helpers import VaultPage

    api, keys, account_id = account
    make_pro(api, account_id)
    vault.add("terminal", Entry(password="t-pass", username="cli"))
    _login(api, vault)
    cloud.sync(vault, PASSWORD)
    ctx = browser.new_context(bypass_csp=True)
    try:
        page = ctx.new_page()
        v = VaultPage(page, _server(api)).open()
        v.unlock(EMAIL)
        assert v.entry_names() == ["terminal"]
        v.add_entry("browser", password="b-pass")
        v.wait_synced()
    finally:
        ctx.close()
    report = cloud.sync(vault, PASSWORD, mode="pull")
    assert report.added_local == ["browser"] and vault.entries["browser"].password == "b-pass"
