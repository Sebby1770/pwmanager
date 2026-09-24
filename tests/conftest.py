"""Shared fixtures: a live SaaS server on an ephemeral port, and a browser."""

from __future__ import annotations

import base64
import glob
import json
import os
import secrets
import urllib.error
import urllib.request
from typing import Optional

import pytest

from saas.config import WEB_DIR, Config
from saas.db import Database
from saas.server import serve_in_thread


def b64(n: int) -> str:
    return base64.b64encode(os.urandom(n)).decode("ascii")


def fake_webhook_secret() -> str:
    # Built at runtime so no secret-shaped literal lands in the repo.
    return "whsec" + "_" + secrets.token_hex(16)


class ApiClient:
    def __init__(self, base: str):
        self.base = base.rstrip("/")
        self.cookie: Optional[str] = None

    def request(self, method, path, body=None, headers=None, raw=False):
        data = None
        req_headers = dict(headers or {})
        if body is not None and not raw:
            data = json.dumps(body).encode("utf-8")
            req_headers.setdefault("Content-Type", "application/json")
        elif raw:
            data = body
        if self.cookie:
            req_headers.setdefault("Cookie", self.cookie)
        req = urllib.request.Request(self.base + path, data=data, method=method, headers=req_headers)
        try:
            with urllib.request.urlopen(req, timeout=10) as resp:
                payload = resp.read()
                self._take_cookie(resp.headers.get("Set-Cookie"))
                return resp.status, (json.loads(payload) if payload else {})
        except urllib.error.HTTPError as exc:
            payload = exc.read()
            try:
                parsed = json.loads(payload) if payload else {}
            except json.JSONDecodeError:
                parsed = {"raw": payload.decode("utf-8", errors="replace")}
            return exc.code, parsed

    def _take_cookie(self, cookie):
        if cookie and "pwmanager_session=" in cookie:
            token = cookie.split("pwmanager_session=", 1)[1].split(";", 1)[0]
            self.cookie = ("pwmanager_session=" + token) if token else None

    def register(self, email="user@example.com", auth=None, salt=None, kdf_params=None):
        auth = auth or b64(32)
        salt = salt or b64(32)
        params = kdf_params or {"alg": "PBKDF2-HMAC-SHA256", "iterations": 600000, "hash": "SHA-256", "dk_len": 64}
        status, body = self.request(
            "POST",
            "/api/register",
            {"email": email, "auth_key": auth, "kdf_salt": salt, "kdf_params": params},
        )
        return status, body, auth, salt


@pytest.fixture
def make_api(tmp_path):
    """Factory: make_api(**config_overrides) -> ApiClient bound to a fresh server."""
    servers = []

    def factory(**overrides):
        db_path = str(tmp_path / f"saas-{len(servers)}.sqlite")
        cfg = Config(host="127.0.0.1", port=0, db_path=db_path, public_url="http://127.0.0.1", web_root=WEB_DIR)
        for key, value in overrides.items():
            setattr(cfg, key, value)
        db = Database(db_path)
        httpd, app, _thread = serve_in_thread(cfg=cfg, db=db)
        servers.append((httpd, db))
        host, port = httpd.server_address[:2]
        client = ApiClient(f"http://{host}:{port}")
        client.db, client.app, client.port = db, app, port
        return client

    yield factory
    for httpd, db in servers:
        httpd.shutdown()
        httpd.server_close()
        db.close()


def make_pro(client: ApiClient, account_id: str) -> None:
    client.db.execute("UPDATE accounts SET plan = 'pro', plan_status = 'active' WHERE id = ?", (account_id,))


# ---------------------------------------------------------------- browser


def _chromium_executable() -> Optional[str]:
    explicit = os.environ.get("PWMANAGER_CHROMIUM")
    if explicit:
        return explicit
    root = os.environ.get("PLAYWRIGHT_BROWSERS_PATH", "/opt/pw-browsers")
    found = sorted(glob.glob(os.path.join(root, "chromium-*", "chrome-linux*", "chrome")))
    return found[-1] if found else None


@pytest.fixture(scope="session")
def browser():
    sync_api = pytest.importorskip("playwright.sync_api")
    with sync_api.sync_playwright() as p:
        try:
            b = p.chromium.launch()
        except Exception:
            exe = _chromium_executable()
            if not exe:
                pytest.skip("no Chromium available for Playwright")
            # The preinstalled browser may not match this Playwright version.
            b = p.chromium.launch(executable_path=exe)
        yield b
        b.close()
