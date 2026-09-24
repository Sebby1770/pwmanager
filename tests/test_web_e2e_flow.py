"""End-to-end: the browser vault against the local SaaS server, Stripe disabled."""

from __future__ import annotations

import base64

import pytest

from tests.conftest import make_pro
from tests.e2e_helpers import PASSWORD, VaultPage

pytest.importorskip("playwright.sync_api")


def test_signup_add_lock_unlock_sync(browser, make_api):
    api = make_api()
    base = f"http://127.0.0.1:{api.port}"
    email = "flow@example.com"
    ctx = browser.new_context(bypass_csp=True)
    other = browser.new_context(bypass_csp=True)
    try:
        page = ctx.new_page()
        errors = []
        page.on("pageerror", lambda exc: errors.append(str(exc)))
        v = VaultPage(page, base).open()

        # Sign up: local vault plus a cloud account on the free plan.
        v.create(email, cloud=True)
        account = api.db.get_account_by_email(email)
        assert account is not None and account["plan"] == "free"
        assert page.text_content("#plan-badge") == "Free"

        # Add an entry; it is saved on this device only (free plan: no sync).
        v.add_entry("github", password="gh-Secret-123!", username="octo", notes="2fa codes in drawer")
        assert v.entry_names() == ["github"]
        assert api.db.get_vault(account["id"]) is None

        # Lock, then fail to unlock with the wrong password.
        v.lock()
        page.click("#tab-unlock")
        page.fill("#unlock-email", email)
        page.fill("#unlock-password", "not the right password at all")
        page.click("#unlock-form button[type=submit]")
        page.wait_for_function("() => document.getElementById('lock-status').dataset.kind === 'error'")
        assert "Check the master password" in page.text_content("#lock-status")
        assert page.is_hidden("#view-app")

        # Unlock with the right one: the entry is back, decrypted locally.
        v.unlock(email)
        assert v.entry_names() == ["github"]
        page.click("#entry-list .entry-row")
        assert page.input_value("#entry-username") == "octo"
        assert page.input_value("#entry-password") == "gh-Secret-123!"

        # Checkout with Stripe disabled explains itself instead of faking Pro.
        page.click("#btn-account")
        page.click("#btn-checkout-month")
        page.wait_for_function("() => (document.getElementById('toast') || {}).textContent?.includes('Checkout is unavailable')")
        page.click("#account-close")

        # Pro (granted in the DB, as Stripe would): sync uploads ciphertext only.
        make_pro(api, account["id"])
        v.lock()
        v.unlock(email)
        assert page.text_content("#plan-badge") == "Pro"
        page.click("#btn-sync")
        v.wait_synced()
        blob = api.db.get_vault(account["id"])
        assert blob is not None
        raw = base64.b64decode(blob["ciphertext"])
        for secret in (b"gh-Secret-123!", b"octo", b"github", b"2fa codes"):
            assert secret not in raw

        # A second device with no local copy pulls and decrypts the cloud vault.
        w = VaultPage(other.new_page(), base).open()
        w.unlock(email)
        assert w.entry_names() == ["github"]
        assert w.page.text_content("#sync-status") == "Loaded cloud copy"

        assert errors == []
    finally:
        ctx.close()
        other.close()


def test_local_only_vault_needs_no_server(browser, make_api):
    """The web vault keeps working offline: API down, local vault still opens."""
    api = make_api()
    base = f"http://127.0.0.1:{api.port}"
    ctx = browser.new_context(bypass_csp=True)
    try:
        page = ctx.new_page()
        v = VaultPage(page, base).open()
        v.create("offline@example.com", cloud=False)
        v.add_entry("router", password="r0uter-pass!")
        v.lock()
        page.route("**/api/**", lambda route: route.abort())
        v.unlock("offline@example.com")
        assert v.entry_names() == ["router"]
        assert page.text_content("#plan-badge") == "Local"
        assert api.db.get_account_by_email("offline@example.com") is None
    finally:
        ctx.close()


def test_served_vault_page_has_strict_csp(browser, make_api):
    api = make_api()
    ctx = browser.new_context()  # CSP enforced here
    try:
        page = ctx.new_page()
        response = page.goto(f"http://127.0.0.1:{api.port}/vault.html")
        csp = response.headers["content-security-policy"]
        assert "script-src 'self'" in csp and "unsafe-inline" not in csp and "unsafe-eval" not in csp
        # An injected inline script (the usual XSS payload shape) must not run.
        ran = page.evaluate(
            """() => new Promise(resolve => {
                 const s = document.createElement('script');
                 s.textContent = 'window.__inlineRan = true';
                 document.head.appendChild(s);
                 setTimeout(() => resolve(window.__inlineRan === true), 100);
               })"""
        )
        assert ran is False
    finally:
        ctx.close()
