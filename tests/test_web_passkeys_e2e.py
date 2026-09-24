"""Browser passkey flow with Chrome's virtual authenticator (CDP WebAuthn domain)."""

from __future__ import annotations

import pytest

pytest.importorskip("playwright.sync_api")
pytest.importorskip("webauthn")

from tests.e2e_helpers import VaultPage  # noqa: E402


def _site(make_api):
    api = make_api()
    base = f"http://localhost:{api.port}"  # browsers refuse IP-literal RP ids
    api.app.mfa.origins = [base]
    return api, base


def _with_authenticator(ctx, page):
    cdp = ctx.new_cdp_session(page)
    cdp.send("WebAuthn.enable", {"enableUI": False})
    result = cdp.send(
        "WebAuthn.addVirtualAuthenticator",
        {"options": {"protocol": "ctap2", "transport": "internal", "hasResidentKey": True,
                     "hasUserVerification": True, "isUserVerified": True,
                     "automaticPresenceSimulation": True}},
    )
    return cdp, result["authenticatorId"]


def _events(api, email):
    acct = api.db.get_account_by_email(email)
    rows = api.db.execute("SELECT event FROM audit_events WHERE account_id = ? ORDER BY at", (acct["id"],))
    return [r["event"] for r in rows]


def _enrol(page):
    page.click("#btn-account")
    page.wait_for_selector("#passkey-section", state="visible")
    page.click("#btn-passkey-add")
    page.wait_for_selector("#recovery-box", state="visible", timeout=15_000)
    codes = page.text_content("#recovery-codes").split("\n")
    page.wait_for_selector("#passkey-list li")
    page.click("#account-close")
    return codes


def test_passkey_enrol_then_sign_in_with_it(browser, make_api):
    api, base = _site(make_api)
    email = "passkey@example.com"
    ctx = browser.new_context(bypass_csp=True)
    try:
        page = ctx.new_page()
        cdp, authenticator = _with_authenticator(ctx, page)
        v = VaultPage(page, base).open()
        v.create(email, cloud=True)
        v.add_entry("mail", password="m-Secret-1!")

        codes = _enrol(page)
        assert len(codes) == 10
        assert len(cdp.send("WebAuthn.getCredentials", {"authenticatorId": authenticator})["credentials"]) == 1

        v.lock()
        assert page.text_content("#recovery-codes") == "", "recovery codes wiped on lock"
        v.unlock(email)
        assert page.text_content("#plan-badge") == "Free"  # signed in to the cloud
        assert v.entry_names() == ["mail"]
        assert "login_passkey" in _events(api, email)
    finally:
        ctx.close()


def test_new_device_without_the_passkey_uses_a_recovery_code(browser, make_api):
    api, base = _site(make_api)
    email = "recover@example.com"
    first = browser.new_context(bypass_csp=True)
    second = browser.new_context(bypass_csp=True)
    try:
        page = first.new_page()
        _with_authenticator(first, page)
        v = VaultPage(page, base).open()
        v.create(email, cloud=True)
        codes = _enrol(page)

        # A second browser whose authenticator does not hold the passkey.
        other = second.new_page()
        cdp, auth_id = _with_authenticator(second, other)
        cdp.send("WebAuthn.setUserVerified", {"authenticatorId": auth_id, "isUserVerified": True})
        prompts = []
        other.on("dialog", lambda d: (prompts.append(d.message), d.accept(codes[0])))
        w = VaultPage(other, base).open()
        w.unlock(email)
        assert prompts and "recovery code" in prompts[0]
        assert other.text_content("#plan-badge") == "Free"
        assert "login_recovery_code" in _events(api, email)
        assert api.app.mfa.remaining_recovery_codes(api.db.get_account_by_email(email)["id"]) == 9
    finally:
        first.close()
        second.close()


def test_declining_the_second_factor_keeps_the_vault_local(browser, make_api):
    api, base = _site(make_api)
    email = "decline@example.com"
    first = browser.new_context(bypass_csp=True)
    second = browser.new_context(bypass_csp=True)
    try:
        page = first.new_page()
        _with_authenticator(first, page)
        v = VaultPage(page, base).open()
        v.create(email, cloud=True)
        _enrol(page)

        other = second.new_page()
        _with_authenticator(second, other)
        other.on("dialog", lambda d: d.dismiss())
        w = VaultPage(other, base).open()
        w.unlock(email)
        assert other.text_content("#plan-badge") == "Local"
        cookies = [c for c in second.cookies() if c["name"] == "pwmanager_session"]
        assert cookies == [], "no cloud session without the second factor"
    finally:
        first.close()
        second.close()
