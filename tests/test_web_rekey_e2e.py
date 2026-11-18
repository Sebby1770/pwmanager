"""Browser: Argon2id migration, master-password change across devices, downgrade guard."""

from __future__ import annotations

import base64
import json

import pytest

from pwmanager import cloudkdf
from saas import kdf as skdf
from tests.cloud_helpers import PASSWORD, register, v1, vault_doc
from tests.conftest import ApiClient, make_pro
from tests.e2e_helpers import VaultPage

pytest.importorskip("playwright.sync_api")

NEW_PASSWORD = "an entirely new master passphrase"


def _ctx(browser):
    return browser.new_context(bypass_csp=True)


def _server_keys(api, email, password):
    row = api.db.get_account_by_email(email)
    salt = base64.b64decode(row["kdf_salt"])
    vault_key, auth_key, params = cloudkdf.derive_keys(password, email, salt, json.loads(row["kdf_params"]))
    return row, vault_key, auth_key, params


def test_legacy_pbkdf2_account_migrates_to_argon2id_on_unlock(browser, make_api):
    api = make_api()
    email = "legacy@example.com"
    old = v1(email)
    status, body = register(api, email, old)
    make_pro(api, body["account"]["id"])
    assert api.request("PUT", "/api/vault", old.seal(vault_doc("legacy-entry", saved_at=5)))[0] == 200
    assert api.request("PUT", "/api/vault", old.seal(vault_doc("legacy-entry", saved_at=6)))[0] == 200

    ctx = _ctx(browser)
    try:
        v = VaultPage(ctx.new_page(), f"http://127.0.0.1:{api.port}").open()
        v.unlock(email)
        assert v.entry_names() == ["legacy-entry"]
        assert "Argon2id" in v.page.text_content("#sync-status")

        row, vault_key, auth_key, params = _server_keys(api, email, PASSWORD)
        assert params["alg"] == "argon2id"
        assert ApiClient(api.base).request("POST", "/api/login", {"email": email, "auth_key": old.auth_b64})[0] == 401
        assert api.request("GET", "/api/vault")[0] == 401, "the rekey revoked every other session"
        blob = api.db.get_vault(row["id"])
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM

        plain = AESGCM(vault_key).decrypt(base64.b64decode(blob["nonce"]), base64.b64decode(blob["ciphertext"]),
                                          b"pwmanager-vault-v1")
        assert json.loads(plain)["entries"][0]["name"] == "legacy-entry"
        revisions = api.db.execute("SELECT COUNT(*) AS n FROM vault_revisions WHERE account_id = ?", (row["id"],))
        assert revisions.fetchone()["n"] == 0, "PBKDF2-sealed revisions are retired"
        record = v.idb_record(email)
        assert record["envelope"]["kdf"]["alg"] == "argon2id" and record["cloud"] is True

        # Next unlock is a plain Argon2id unlock with no further migration.
        v.lock()
        v.unlock(email)
        assert v.entry_names() == ["legacy-entry"]
    finally:
        ctx.close()


def test_local_only_legacy_vault_migrates_without_a_server_account(browser, make_api):
    api = make_api()
    email = "offline-legacy@example.com"
    ctx = _ctx(browser)
    try:
        v = VaultPage(ctx.new_page(), f"http://127.0.0.1:{api.port}").open()
        v.page.evaluate(
            """async ([email, password]) => {
                 const c = await import('/saas/crypto.js');
                 const v = await import('/saas/vault.js');
                 const keys = await c.deriveKeys(password, email, c.randomBytes(32), c.legacyKdfParams());
                 const data = { version: 1, saved_at: 1, entries: [v.newEntry({ name: 'old-local' })] };
                 const env = await c.encryptVault(keys.vaultKey, data, keys.saltB64, keys.kdfParams);
                 await v.idbPut(email, env, { cloud: false });
               }""",
            [email, PASSWORD],
        )
        assert v.idb_record(email)["envelope"]["kdf"]["alg"] == "PBKDF2-HMAC-SHA256"
        v.unlock(email)
        assert v.entry_names() == ["old-local"]
        assert v.idb_record(email)["envelope"]["kdf"]["alg"] == "argon2id"
        assert api.db.get_account_by_email(email) is None
    finally:
        ctx.close()


def test_master_password_change_across_two_devices(browser, make_api):
    api = make_api()
    base = f"http://127.0.0.1:{api.port}"
    email = "change@example.com"
    a_ctx, b_ctx = _ctx(browser), _ctx(browser)
    try:
        a = VaultPage(a_ctx.new_page(), base).open()
        a.create(email, cloud=True)
        make_pro(api, api.db.get_account_by_email(email)["id"])
        a.lock()
        a.unlock(email)
        a.add_entry("one")
        a.wait_synced()

        b = VaultPage(b_ctx.new_page(), base).open()
        b.unlock(email)
        assert b.entry_names() == ["one"]

        # Wrong current password: refused, nothing changes.
        a.change_password("not the current password", NEW_PASSWORD)
        a.page.wait_for_function("() => document.getElementById('pw-status').dataset.kind === 'error'")
        assert "wrong" in a.page.text_content("#pw-status")
        a.page.click("#pw-cancel")

        a.change_password(PASSWORD, NEW_PASSWORD)
        a.page.wait_for_selector("#password-dialog", state="hidden")
        _, _, new_auth, params = _server_keys(api, email, NEW_PASSWORD)
        assert params["alg"] == "argon2id"
        assert ApiClient(base).request("POST", "/api/login", {"email": email, "auth_key": base64.b64encode(new_auth).decode()})[0] == 200
        assert api.db.execute("SELECT COUNT(*) AS n FROM vault_revisions").fetchone()["n"] == 0

        # B's session was revoked; with the new password B adopts the new key.
        b_cookie = [c for c in b_ctx.cookies() if c["name"] == "pwmanager_session"][0]["value"]
        assert api.db.session_account(b_cookie) is None
        b.lock()
        b.unlock(email, NEW_PASSWORD)
        assert b.entry_names() == ["one"]
        assert "another device" in b.page.text_content("#sync-status")
        assert b.page.text_content("#plan-badge") == "Pro"

        # B's local copy is now sealed with the new key: the old password no longer opens it.
        b.lock()
        b.page.click("#tab-unlock")
        b.page.fill("#unlock-email", email)
        b.page.fill("#unlock-password", PASSWORD)
        b.page.click("#unlock-form button[type=submit]")
        b.page.wait_for_function("() => document.getElementById('lock-status').dataset.kind === 'error'")
        assert b.page.is_hidden("#view-app")

        # A keeps working with the new password after a lock.
        a.lock()
        a.unlock(email, NEW_PASSWORD)
        assert a.entry_names() == ["one"]
    finally:
        a_ctx.close()
        b_ctx.close()


def test_server_cannot_downgrade_a_device_to_pbkdf2(browser, make_api):
    api = make_api()
    email = "downgrade@example.com"
    ctx = _ctx(browser)
    try:
        page = ctx.new_page()
        v = VaultPage(page, f"http://127.0.0.1:{api.port}").open()
        v.create(email, cloud=True)
        v.add_entry("kept-local")
        v.lock()
        # A compromised server now claims the account uses PBKDF2.
        api.db.execute("UPDATE accounts SET kdf_params = ? WHERE email = ?", (json.dumps(skdf.legacy_params()), email))
        logins = []
        page.on("request", lambda r: logins.append(r.url) if r.url.endswith("/api/login") else None)
        v.unlock(email)
        assert v.entry_names() == ["kept-local"]
        assert "weaker" in page.text_content("#sync-status")
        assert logins == [], "no key derived under the server's weaker scheme is ever sent"
        assert page.text_content("#plan-badge") == "Local"
        assert v.idb_record(email)["envelope"]["kdf"]["alg"] == "argon2id"
    finally:
        ctx.close()


def test_local_only_password_change(browser, make_api):
    api = make_api()
    email = "local-change@example.com"
    ctx = _ctx(browser)
    try:
        v = VaultPage(ctx.new_page(), f"http://127.0.0.1:{api.port}").open()
        v.create(email, cloud=False)
        v.add_entry("note-1")
        v.change_password(PASSWORD, NEW_PASSWORD, confirm="mismatch mismatch")
        v.page.wait_for_function("() => document.getElementById('pw-status').dataset.kind === 'error'")
        v.page.fill("#pw-new2", NEW_PASSWORD)
        v.page.click("#pw-submit")
        v.page.wait_for_selector("#password-dialog", state="hidden")
        v.lock()
        v.unlock(email, NEW_PASSWORD)
        assert v.entry_names() == ["note-1"]
    finally:
        ctx.close()
