"""HTTP tests for register/login, vault limits, and Stripe webhook HMAC."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import time
import urllib.error
import urllib.request
import pytest

from saas.config import Config, PRO_VAULT_MAX_BYTES
from saas.db import Database
from saas.envelope import parse_envelope
from saas.server import serve_in_thread
from saas.stripeutil import verify_stripe_signature


def _b64(n: int) -> str:
    return base64.b64encode(os.urandom(n)).decode("ascii")


def _envelope() -> dict:
    return {
        "v": 1,
        "nonce": _b64(12),
        "ct": _b64(48),
        "kdf": {
            "alg": "PBKDF2-HMAC-SHA256",
            "hash": "SHA-256",
            "iterations": 600000,
            "salt": _b64(32),
        },
        "updated_at": int(time.time()),
    }


class ApiClient:
    def __init__(self, base: str):
        self.base = base.rstrip("/")
        self.cookie = None

    def request(self, method: str, path: str, body=None, headers=None, raw=False):
        data = None
        req_headers = dict(headers or {})
        if body is not None and not raw:
            data = json.dumps(body).encode("utf-8")
            req_headers.setdefault("Content-Type", "application/json")
        elif raw:
            data = body
        if self.cookie:
            req_headers.setdefault("Cookie", self.cookie)
        req = urllib.request.Request(
            self.base + path,
            data=data,
            method=method,
            headers=req_headers,
        )
        try:
            with urllib.request.urlopen(req, timeout=10) as resp:
                payload = resp.read()
                cookie = resp.headers.get("Set-Cookie")
                if cookie and "pwmanager_session=" in cookie:
                    token = cookie.split("pwmanager_session=", 1)[1].split(";", 1)[0]
                    if token:
                        self.cookie = "pwmanager_session=" + token
                    else:
                        self.cookie = None
                parsed = json.loads(payload.decode("utf-8")) if payload else {}
                return resp.status, parsed
        except urllib.error.HTTPError as exc:
            payload = exc.read()
            try:
                parsed = json.loads(payload.decode("utf-8")) if payload else {}
            except json.JSONDecodeError:
                parsed = {"raw": payload.decode("utf-8", errors="replace")}
            return exc.code, parsed


@pytest.fixture
def api(tmp_path):
    db_path = str(tmp_path / "test.sqlite")
    cfg = Config(
        host="127.0.0.1",
        port=0,
        db_path=db_path,
        public_url="http://127.0.0.1",
        web_root=__import__("saas.config", fromlist=["WEB_DIR"]).WEB_DIR,
        stripe_secret="",
        stripe_webhook_secret="",
        stripe_price_monthly="",
        stripe_price_yearly="",
        secure_cookies=False,
    )
    db = Database(db_path)
    httpd, app, _thread = serve_in_thread(cfg=cfg, db=db)
    host, port = httpd.server_address[:2]
    client = ApiClient(f"http://{host}:{port}")
    client.db = db
    client.app = app
    try:
        yield client
    finally:
        httpd.shutdown()
        httpd.server_close()
        db.close()


def register(client: ApiClient, email="user@example.com"):
    salt = _b64(32)
    auth = _b64(32)
    status, body = client.request(
        "POST",
        "/api/register",
        {
            "email": email,
            "auth_key": auth,
            "kdf_salt": salt,
            "kdf_params": {
                "alg": "PBKDF2-HMAC-SHA256",
                "iterations": 600000,
                "hash": "SHA-256",
                "dk_len": 64,
            },
        },
    )
    return status, body, auth, salt


def test_health(api):
    status, body = api.request("GET", "/api/health")
    assert status == 200
    assert body["ok"] is True
    assert body["stripe_configured"] is False


def test_register_login_me_logout(api):
    status, body, auth, salt = register(api)
    assert status == 201, body
    assert body["account"]["email"] == "user@example.com"
    assert body["account"]["plan"] == "free"
    assert body["account"]["kdf_salt"] == salt
    assert "password" not in json.dumps(body).lower() or "auth_key" not in json.dumps(body)

    status, me = api.request("GET", "/api/me")
    assert status == 200
    assert me["account"]["email"] == "user@example.com"

    status, _ = api.request("POST", "/api/logout", {})
    assert status == 200
    status, err = api.request("GET", "/api/me")
    assert status == 401

    status, pre = api.request("POST", "/api/login", {"email": "user@example.com"})
    assert status == 200
    assert pre["kdf_salt"] == salt

    status, logged = api.request(
        "POST",
        "/api/login",
        {"email": "user@example.com", "auth_key": auth},
    )
    assert status == 200, logged
    assert logged["account"]["email"] == "user@example.com"


def test_login_rejects_wrong_auth_key(api):
    register(api)
    api.cookie = None
    status, body = api.request(
        "POST",
        "/api/login",
        {"email": "user@example.com", "auth_key": _b64(32)},
    )
    assert status == 401
    assert body["error"] == "invalid_credentials"


def test_duplicate_register_conflict(api):
    assert register(api)[0] == 201
    status, body, *_ = register(api)
    assert status == 409
    assert body["error"] == "email_taken"


def test_prelogin_unknown_email_still_returns_salt(api):
    status, body = api.request("POST", "/api/prelogin", {"email": "nobody@example.com"})
    assert status == 200
    assert body["kdf_salt"]
    # Dummy salt must be stable so we do not leak existence via jitter.
    status, again = api.request("POST", "/api/prelogin", {"email": "nobody@example.com"})
    assert again["kdf_salt"] == body["kdf_salt"]


def test_vault_put_requires_pro(api):
    register(api)
    status, body = api.request("PUT", "/api/vault", _envelope())
    assert status == 403
    assert body["error"] == "pro_required"


def test_vault_put_rejects_plaintext_and_oversize(api):
    status, body, auth, salt = register(api, email="pro@example.com")
    assert status == 201
    account_id = body["account"]["id"]
    api.db.execute(
        "UPDATE accounts SET plan = 'pro', plan_status = 'active' WHERE id = ?",
        (account_id,),
    )

    bad = _envelope()
    bad["password"] = "should-not-be-here"
    status, err = api.request("PUT", "/api/vault", bad)
    assert status == 400
    assert err["error"] == "bad_envelope"

    env = _envelope()
    parse_envelope(env)
    status, ok = api.request("PUT", "/api/vault", env)
    assert status == 200, ok
    status, got = api.request("GET", "/api/vault")
    assert status == 200
    assert got["envelope"]["ct"] == env["ct"]
    assert got["envelope"]["nonce"] == env["nonce"]

    huge = _envelope()
    # Stay under the HTTP body cap so the client can read the JSON error, but
    # make the stored envelope just over the 8 MiB Pro limit.
    skeleton = json.dumps({**huge, "ct": ""}, separators=(",", ":"))
    pad = PRO_VAULT_MAX_BYTES - len(skeleton) + 64
    pad -= pad % 4
    huge["ct"] = "A" * max(32, pad)
    status, too_big = api.request("PUT", "/api/vault", huge)
    assert status == 413
    assert too_big["error"] in {"vault_too_large", "payload_too_large"}


def test_checkout_without_stripe_keys_is_503(api):
    register(api)
    status, body = api.request("POST", "/api/checkout", {"interval": "monthly"})
    assert status == 503
    assert body["error"] == "stripe_not_configured"
    assert "PWMANAGER_STRIPE_SECRET" in body["message"]


def test_webhook_rejects_bad_signature(api):
    api.app.cfg.stripe_webhook_secret = "whsec_test_secret"
    status, body = api.request(
        "POST",
        "/api/stripe/webhook",
        b'{"id":"evt_1","type":"ping"}',
        headers={"Content-Type": "application/json", "Stripe-Signature": "t=1,v1=deadbeef"},
        raw=True,
    )
    assert status == 400
    assert body["error"] == "invalid_signature"


def test_webhook_accepts_valid_hmac_and_is_idempotent(api):
    secret = "whsec_test_secret"
    api.app.cfg.stripe_webhook_secret = secret
    status, created, *_ = register(api, email="paid@example.com")
    account_id = created["account"]["id"]
    payload = json.dumps(
        {
            "id": "evt_test_1",
            "type": "checkout.session.completed",
            "data": {
                "object": {
                    "object": "checkout.session",
                    "customer": "cus_test_123",
                    "client_reference_id": account_id,
                    "metadata": {"account_id": account_id},
                }
            },
        }
    ).encode("utf-8")
    ts = str(int(time.time()))
    sig = hmac.new(secret.encode(), f"{ts}.".encode() + payload, hashlib.sha256).hexdigest()
    header = f"t={ts},v1={sig}"
    status, body = api.request(
        "POST",
        "/api/stripe/webhook",
        payload,
        headers={"Content-Type": "application/json", "Stripe-Signature": header},
        raw=True,
    )
    assert status == 200, body
    row = api.db.get_account_by_id(account_id)
    assert row["plan"] == "pro"
    assert row["stripe_customer_id"] == "cus_test_123"

    status, dup = api.request(
        "POST",
        "/api/stripe/webhook",
        payload,
        headers={"Content-Type": "application/json", "Stripe-Signature": header},
        raw=True,
    )
    assert status == 200
    assert dup.get("duplicate") is True


def test_webhook_without_secret_is_503(api):
    status, body = api.request(
        "POST",
        "/api/stripe/webhook",
        b'{"id":"evt_x","type":"ping"}',
        headers={"Content-Type": "application/json"},
        raw=True,
    )
    assert status == 503
    assert body["error"] == "stripe_not_configured"


def test_account_delete_wipes_blobs_and_tombstones_email(api):
    status, created, *_ = register(api, email="gone@example.com")
    account_id = created["account"]["id"]
    api.db.execute(
        "UPDATE accounts SET plan = 'pro', plan_status = 'active' WHERE id = ?",
        (account_id,),
    )
    assert api.request("PUT", "/api/vault", _envelope())[0] == 200
    status, body = api.request("POST", "/api/account/delete", {"confirm": "DELETE"})
    assert status == 200, body
    assert api.db.get_vault(account_id) is None
    assert api.db.get_account_by_email("gone@example.com") is None
    row = api.db.execute("SELECT email, deleted_at FROM accounts WHERE id = ?", (account_id,)).fetchone()
    assert row["deleted_at"]
    assert row["email"].startswith("deleted+")


def test_stripe_signature_helper_rejects_old_timestamp():
    secret = "whsec_x"
    payload = b'{"id":"evt"}'
    ts = str(int(time.time()) - 10_000)
    sig = hmac.new(secret.encode(), f"{ts}.".encode() + payload, hashlib.sha256).hexdigest()
    assert verify_stripe_signature(payload, f"t={ts},v1={sig}", secret) is False


def test_export_is_ciphertext_only(api):
    status, created, *_ = register(api, email="export@example.com")
    api.db.execute(
        "UPDATE accounts SET plan = 'pro', plan_status = 'active' WHERE id = ?",
        (created["account"]["id"],),
    )
    env = _envelope()
    assert api.request("PUT", "/api/vault", env)[0] == 200
    status, body = api.request("GET", "/api/account/export")
    assert status == 200
    dumped = json.dumps(body)
    assert "hunter" not in dumped
    assert body["vault"]["ct"] == env["ct"]
    assert "password" not in body["vault"]
    assert body["account"]["email"] == "export@example.com"


def test_unauthenticated_vault_is_401(api):
    status, body = api.request("GET", "/api/vault")
    assert status == 401
    assert body["error"] == "unauthorized"
