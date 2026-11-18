"""Browser regression tests for the 3.3 audit findings in web/saas (F5–F7)."""

from __future__ import annotations

import pytest

from tests.conftest import make_pro
from tests.e2e_helpers import VaultPage

pytest.importorskip("playwright.sync_api")


@pytest.fixture
def server(make_api):
    return make_api()


def _context(browser, api):
    origin = f"http://127.0.0.1:{api.port}"
    # bypass_csp only lets Playwright evaluate its own predicates; CSP itself
    # is asserted separately against the served headers.
    ctx = browser.new_context(bypass_csp=True)
    ctx.grant_permissions(["clipboard-read", "clipboard-write"], origin=origin)
    return ctx


def test_f5_locking_clears_a_copied_password_from_the_clipboard(browser, server):
    ctx = _context(browser, server)
    try:
        page = ctx.new_page()
        v = VaultPage(page, f"http://127.0.0.1:{server.port}").open()
        v.create("clip@example.com", cloud=False)
        v.add_entry("bank", password="S3cret-clipboard-value!")
        page.click("#entry-list .entry-row")
        page.click("#entry-copy-password")
        page.wait_for_function("navigator.clipboard.readText().then(t => t.length > 0)")
        assert page.evaluate("navigator.clipboard.readText()") == "S3cret-clipboard-value!"
        # Lock before the 20-second auto-clear fires.
        v.lock()
        page.wait_for_timeout(300)
        assert page.evaluate("navigator.clipboard.readText()") != "S3cret-clipboard-value!"
    finally:
        ctx.close()


def test_f6_locking_removes_decrypted_fields_from_the_dom(browser, server):
    ctx = _context(browser, server)
    try:
        page = ctx.new_page()
        v = VaultPage(page, f"http://127.0.0.1:{server.port}").open()
        v.create("dom@example.com", cloud=False)
        v.add_entry("mail", password="pw-value-123!", username="alice", notes="recovery code 1234", totp="JBSWY3DPEHPK3PXP")
        page.click("#entry-list .entry-row")
        v.lock()
        leftovers = page.evaluate(
            """() => {
              const ids = ['entry-name','entry-username','entry-password','entry-url',
                           'entry-notes','entry-totp','entry-tags','entry-id'];
              const vals = ids.map(id => document.getElementById(id).value).filter(Boolean);
              const list = document.getElementById('entry-list').textContent;
              const totp = document.getElementById('totp-display').textContent;
              return {vals, list, totp};
            }"""
        )
        assert leftovers["vals"] == []
        assert "mail" not in leftovers["list"]
        assert not any(ch.isdigit() for ch in leftovers["totp"])
    finally:
        ctx.close()


def test_f7_second_device_sees_newer_cloud_copy(browser, server):
    """Device B has an older local copy; the newer cloud copy must win on unlock."""
    base = f"http://127.0.0.1:{server.port}"
    email = "sync@example.com"
    a_ctx, b_ctx = _context(browser, server), _context(browser, server)
    try:
        a = VaultPage(a_ctx.new_page(), base).open()
        a.create(email, cloud=True)
        make_pro(server, server.db.get_account_by_email(email)["id"])
        a.lock()
        a.unlock(email)
        a.add_entry("one")
        a.wait_synced()

        b = VaultPage(b_ctx.new_page(), base).open()
        b.unlock(email)
        assert b.entry_names() == ["one"]
        b.add_entry("from-b")  # B now has a local copy written by persist()
        b.wait_synced()
        b.lock()

        a.lock()
        a.unlock(email)
        assert sorted(a.entry_names()) == ["from-b", "one"]
        a.add_entry("two")
        a.wait_synced()

        b.unlock(email)
        assert sorted(b.entry_names()) == ["from-b", "one", "two"]
    finally:
        a_ctx.close()
        b_ctx.close()


def test_f7_rolled_back_cloud_copy_does_not_replace_newer_local(browser, server):
    """A server (or attacker) replaying an old ciphertext must not roll the vault back."""
    base = f"http://127.0.0.1:{server.port}"
    email = "rollback@example.com"
    ctx = _context(browser, server)
    try:
        v = VaultPage(ctx.new_page(), base).open()
        v.create(email, cloud=True)
        account_id = server.db.get_account_by_email(email)["id"]
        make_pro(server, account_id)
        v.lock()
        v.unlock(email)
        v.add_entry("old")
        v.wait_synced()
        old = server.db.get_vault(account_id)
        v.add_entry("new")
        v.wait_synced()
        v.lock()
        server.db.execute(
            "UPDATE vault_blobs SET ciphertext = ?, nonce = ?, updated_at = '2999-01-01T00:00:00Z' WHERE account_id = ?",
            (old["ciphertext"], old["nonce"], account_id),
        )
        v.unlock(email)
        assert sorted(v.entry_names()) == ["new", "old"]
    finally:
        ctx.close()


def test_zero_knowledge_nothing_but_auth_key_leaves_the_browser(browser, server, capfd):
    """Record every request; recompute the keys; only authKey may appear on the wire.

    Covers sign-up, sync, a master-password change (rekey) and account deletion.
    """
    import base64
    import hashlib
    import json

    from pwmanager import cloudkdf
    from tests.e2e_helpers import PASSWORD

    new_password = "the replacement master password"
    base = f"http://127.0.0.1:{server.port}"
    email = "zk@example.com"
    ctx = _context(browser, server)
    seen = []
    try:
        page = ctx.new_page()
        page.on("request", lambda r: seen.append((r.url, dict(r.headers), r.post_data or "")))
        v = VaultPage(page, base).open()
        v.create(email, cloud=True)
        before = server.db.get_account_by_email(email)
        make_pro(server, before["id"])
        v.lock()
        v.unlock(email)
        v.add_entry("site", password="entry-secret-Zq9!", notes="private note text")
        v.wait_synced()
        v.change_password(PASSWORD, new_password)
        page.wait_for_selector("#password-dialog", state="hidden")
        after = server.db.get_account_by_email(email)
        dump = "\n".join(str(tuple(r)) for r in server.db.execute("SELECT * FROM accounts").fetchall())
        dump += "\n".join(str(tuple(r)) for r in server.db.execute("SELECT * FROM vault_blobs").fetchall())
        page.on("dialog", lambda d: d.accept())
        page.click("#btn-account")
        page.click("#btn-delete-account")
        page.wait_for_function("() => document.getElementById('plan-badge').textContent === 'Local'")
    finally:
        ctx.close()

    keys = {}
    for label, password, row in (("old", PASSWORD, before), ("new", new_password, after)):
        salt = base64.b64decode(row["kdf_salt"])
        params = json.loads(row["kdf_params"])
        assert params["alg"] == "argon2id", "accounts use Argon2id"
        keys[label] = cloudkdf.derive_keys(password, email, salt, params)
    assert before["kdf_salt"] != after["kdf_salt"]
    mixed = hashlib.sha256(base64.b64decode(before["kdf_salt"]) + email.encode()).digest()
    material = hashlib.pbkdf2_hmac("sha256", PASSWORD.encode(), mixed, 600_000, 64)

    forbidden = {
        "old master password": PASSWORD,
        "new master password": new_password,
        "entry password": "entry-secret-Zq9!",
        "entry notes": "private note text",
        "PBKDF2 output (v1 scheme)": base64.b64encode(material).decode(),
    }
    for label, (vault_key, _auth, _p) in keys.items():
        forbidden[f"{label} vaultKey (b64)"] = base64.b64encode(vault_key).decode()
        forbidden[f"{label} vaultKey (hex)"] = vault_key.hex()
    wire = json.dumps(seen)
    for label, value in forbidden.items():
        assert value not in wire, f"{label} reached the network"

    old_auth = base64.b64encode(keys["old"][1]).decode()
    new_auth = base64.b64encode(keys["new"][1]).decode()
    api_bodies = [json.loads(body) for url, _h, body in seen if "/api/" in url and body]
    sent_auth = {b[k] for b in api_bodies for k in ("auth_key", "new_auth_key") if k in b}
    assert sent_auth == {old_auth, new_auth}, "the only derived values sent are authKeys"
    rekey = [b for b in api_bodies if "new_auth_key" in b]
    assert len(rekey) == 1 and rekey[0]["auth_key"] == old_auth and rekey[0]["new_auth_key"] == new_auth
    allowed = {"email", "auth_key", "kdf_salt", "kdf_params", "confirm", "v", "nonce", "ct", "kdf", "updated_at",
               "new_auth_key", "new_kdf_salt", "new_kdf_params", "envelope", "reason"}
    for body in api_bodies:
        assert set(body) <= allowed, set(body) - allowed

    # The server never stores an authKey itself, and its log shows only request lines.
    for auth in (old_auth, new_auth):
        assert auth not in dump and base64.b64decode(auth).hex() not in dump
    log = capfd.readouterr().err
    for secret in (old_auth, new_auth, PASSWORD, new_password):
        assert secret not in log
