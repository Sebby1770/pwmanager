"""Page helpers for driving web/vault.html with Playwright."""

from __future__ import annotations

PASSWORD = "correct horse battery staple 42"


class VaultPage:
    def __init__(self, page, base: str):
        self.page = page
        self.base = base.rstrip("/")

    def open(self):
        self.page.goto(self.base + "/vault.html")
        self.page.wait_for_selector("#unlock-form")
        return self

    def create(self, email: str, password: str = PASSWORD, cloud: bool = True):
        p = self.page
        p.click("#tab-create")
        p.fill("#create-email", email)
        p.fill("#create-password", password)
        p.fill("#create-password2", password)
        p.check("#create-age")
        p.check("#create-warning")
        if cloud:
            p.check("#create-cloud")
        p.click("#create-form button[type=submit]")
        p.wait_for_selector("#view-app[data-ready='true']", state="visible", timeout=15_000)

    def unlock(self, email: str, password: str = PASSWORD):
        p = self.page
        p.click("#tab-unlock")
        p.fill("#unlock-email", email)
        p.fill("#unlock-password", password)
        p.click("#unlock-form button[type=submit]")
        # afterUnlock pulls the cloud copy asynchronously after showing the app.
        p.wait_for_selector("#view-app[data-ready='true']", state="visible", timeout=15_000)

    def add_entry(self, name: str, password: str = "", username: str = "", notes: str = "", totp: str = ""):
        p = self.page
        p.click("#btn-add")
        p.fill("#entry-name", name)
        if username:
            p.fill("#entry-username", username)
        if password:
            p.fill("#entry-password", password)
        if notes:
            p.fill("#entry-notes", notes)
        if totp:
            p.fill("#entry-totp", totp)
        p.click("#entry-save")
        p.wait_for_selector(f"#entry-list .entry-title:text-is('{name}')")

    def entry_names(self):
        return self.page.eval_on_selector_all("#entry-list .entry-title", "els => els.map(e => e.textContent)")

    def lock(self):
        self.page.click("#btn-lock")
        self.page.wait_for_selector("#view-lock", state="visible")

    def wait_synced(self):
        self.page.wait_for_function(
            "document.getElementById('sync-status').textContent === 'Cloud copy updated'", timeout=10_000
        )

    def change_password(self, current: str, new: str, confirm: str = None):
        p = self.page
        p.click("#btn-account")
        p.click("#btn-change-password")
        p.fill("#pw-current", current)
        p.fill("#pw-new", new)
        p.fill("#pw-new2", confirm if confirm is not None else new)
        p.click("#pw-submit")

    def idb_record(self, email: str):
        """The raw IndexedDB record (ciphertext envelope + flags) for an email."""
        return self.page.evaluate(
            "async (email) => { const v = await import('/saas/vault.js'); return v.idbGet(email); }", email
        )
