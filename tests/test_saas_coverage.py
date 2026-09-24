"""Behavioural tests for the SaaS paths the main API tests do not reach."""

from __future__ import annotations

import io
import json
import socket
import time
import urllib.error
import urllib.request
from datetime import timedelta

import pytest

import saas.auth as auth
import saas.stripeutil as su
from saas import server as saas_server
from saas.auth import isoformat, utcnow
from saas.config import Config, load_config
from saas.db import Database, account_public, is_pro
from saas.envelope import EnvelopeError, envelope_byte_size, envelope_parts, parse_envelope
from tests.conftest import b64, fake_webhook_secret, make_pro
from tests.test_security_audit import _event, _send_event


def _env():
    return {"v": 1, "nonce": b64(12), "ct": b64(48),
            "kdf": {"alg": "PBKDF2-HMAC-SHA256", "iterations": 600000, "salt": b64(32)}}


def _stripe_cfg(**extra):
    # Runtime-built placeholders: never secret-shaped literals in the repo.
    return dict(
        stripe_secret="sk" + "_test_" + "x" * 8,
        stripe_webhook_secret=fake_webhook_secret(),
        stripe_price_monthly="price_month",
        stripe_price_yearly="price_year",
        **extra,
    )


_REAL_URLOPEN = urllib.request.urlopen


def _stripe_only(fake):
    """Patch urlopen for Stripe calls only; the test client shares the module."""

    def dispatch(req, timeout=None, *args, **kwargs):
        url = req.full_url if hasattr(req, "full_url") else str(req)
        if url.startswith(su.STRIPE_API):
            return fake(req, timeout)
        return _REAL_URLOPEN(req, *args, timeout=timeout, **kwargs)

    return dispatch


class _Resp(io.BytesIO):
    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


# ------------------------------------------------------------------ Stripe API


def test_checkout_creates_session_with_account_metadata(make_api, monkeypatch):
    api = make_api(**_stripe_cfg())
    _, created, *_ = api.register("buyer@example.com")
    seen = {}

    def fake_urlopen(req, timeout):
        seen["url"], seen["body"], seen["auth"] = req.full_url, req.data.decode(), req.get_header("Authorization")
        return _Resp(json.dumps({"id": "cs_1", "url": "https://checkout.stripe.com/c/cs_1"}).encode())

    monkeypatch.setattr(su.urllib.request, "urlopen", _stripe_only(fake_urlopen))
    status, body = api.request("POST", "/api/checkout", {"interval": "yearly"})
    assert status == 200 and body["url"].startswith("https://checkout.stripe.com/")
    assert seen["url"].endswith("/checkout/sessions")
    assert "price_year" in seen["body"] and created["account"]["id"] in seen["body"]
    assert "customer_email=buyer%40example.com" in seen["body"]
    assert seen["auth"].startswith("Bearer ")


def test_checkout_reuses_existing_customer_and_rejects_bad_interval(make_api, monkeypatch):
    api = make_api(**_stripe_cfg())
    _, created, *_ = api.register("again@example.com")
    api.db.set_stripe_customer(created["account"]["id"], "cus_existing")
    bodies = []
    monkeypatch.setattr(
        su.urllib.request, "urlopen",
        _stripe_only(lambda req, timeout: bodies.append(req.data.decode()) or _Resp(b'{"id":"cs","url":"https://x"}')),
    )
    assert api.request("POST", "/api/checkout", {"interval": "monthly"})[0] == 200
    assert "customer=cus_existing" in bodies[0] and "price_month" in bodies[0]
    status, body = api.request("POST", "/api/checkout", {"interval": "weekly"})
    assert status == 400 and body["error"] == "stripe_error"


@pytest.mark.parametrize(
    "failure,expected",
    [
        (urllib.error.HTTPError("u", 402, "Payment Required", {}, io.BytesIO(b'{"error":"card"}')), "Stripe API 402"),
        (urllib.error.URLError("dns down"), "Stripe unreachable"),
        (None, "non-JSON"),
    ],
)
def test_stripe_request_errors_become_502(monkeypatch, failure, expected):
    def fake(req, timeout):
        if failure is None:
            return _Resp(b"<html>")
        raise failure

    monkeypatch.setattr(su.urllib.request, "urlopen", fake)
    with pytest.raises(su.StripeError) as err:
        su.stripe_request(Config(**_stripe_cfg()), "GET", "/x")
    assert expected in str(err.value) and err.value.status == 502


def test_checkout_without_url_is_an_error(monkeypatch):
    monkeypatch.setattr(su.urllib.request, "urlopen", lambda req, timeout: _Resp(b'{"id":"cs"}'))
    with pytest.raises(su.StripeError, match="Checkout URL"):
        su.create_checkout_session(Config(**_stripe_cfg()), {"id": "a", "stripe_customer_id": None, "email": "e@x.io"}, "monthly")


def test_stripe_helpers():
    with pytest.raises(su.StripeError) as err:
        su.stripe_request(Config(), "GET", "/x")
    assert err.value.status == 503
    with pytest.raises(su.StripeError):
        su.create_checkout_session(Config(), {}, "monthly")
    flat = su._flatten({"a": {"b": [1, {"c": None, "d": True}], "e": None}, "f": [None], "g": False})
    assert flat == {"a[b][0]": "1", "a[b][1][d]": "true", "f[0]": "", "g": "false"}
    assert su._period_end_iso(None) is None and su._period_end_iso("x") is None
    assert su._period_end_iso(0) == "1970-01-01T00:00:00Z"
    assert su._event_created({"created": True}) is None and su._event_created({"created": "5"}) == 5
    assert su.parse_signature_header("t=1, v1=a, v1=b, v0=c") == ("1", ["a", "b"])
    assert su.verify_stripe_signature(b"x", "", "s") is False
    assert su.verify_stripe_signature(b"x", "t=abc,v1=00", "s") is False
    assert su.verify_stripe_signature(b"x", "v1=00", "s") is False
    with pytest.raises(su.StripeError):
        su.event_from_payload(b"\xff")
    with pytest.raises(su.StripeError):
        su.event_from_payload(b'{"id": "evt"}')


# ------------------------------------------------------------------ webhooks


@pytest.fixture
def hook(make_api):
    secret = fake_webhook_secret()
    api = make_api(stripe_webhook_secret=secret)
    _, created, *_ = api.register("hook@example.com")
    return api, secret, created["account"]["id"]


def test_subscription_lifecycle(hook):
    api, secret, acct = hook
    now = int(time.time())
    period = now + 30 * 86400
    _send_event(api, secret, _event("e1", "customer.subscription.created", acct, now, status="trialing", current_period_end=period))
    row = api.db.get_account_by_id(acct)
    assert (row["plan"], row["plan_status"]) == ("pro", "trialing") and row["plan_period_end"]
    _send_event(api, secret, _event("e2", "invoice.payment_failed", acct, now + 1))
    row = api.db.get_account_by_id(acct)
    assert (row["plan"], row["plan_status"]) == ("pro", "past_due") and row["plan_period_end"]
    _send_event(api, secret, _event("e3", "customer.subscription.updated", acct, now + 2, status="unpaid"))
    assert api.db.get_account_by_id(acct)["plan"] == "free"


def test_webhook_resolves_account_by_customer_and_ignores_unknowns(hook):
    api, secret, acct = hook
    api.db.set_stripe_customer(acct, "cus_lookup")
    now = int(time.time())
    event = {"id": "e_cust", "type": "customer.subscription.updated", "created": now,
             "data": {"object": {"customer": "cus_lookup", "status": "active"}}}
    status, body = _send_event(api, secret, event)
    assert body["account_id"] == acct and api.db.get_account_by_id(acct)["plan"] == "pro"

    status, body = _send_event(api, secret, _event("e_unknown", "customer.subscription.updated", "nope" * 8, now))
    assert body["reason"] == "unknown_account"
    status, body = _send_event(api, secret, _event("e_ping", "customer.created", acct, now))
    assert body["reason"] == "unhandled_type"
    status, body = _send_event(api, secret, {"id": "e_bad"})
    assert status == 400


def test_async_failure_does_not_downgrade_an_existing_pro(hook):
    api, secret, acct = hook
    make_pro(api, acct)
    _send_event(api, secret, _event("e_af", "checkout.session.async_payment_failed", acct, int(time.time())))
    assert api.db.get_account_by_id(acct)["plan"] == "pro"


def test_webhook_body_too_large(hook):
    api, secret, _ = hook
    status, _ = api.request("POST", "/api/stripe/webhook", b"x" * (600 * 1024),
                            headers={"Content-Type": "application/json"}, raw=True)
    assert status == 413


# ------------------------------------------------------------------ HTTP surface


def test_static_files_and_headers(make_api):
    api = make_api(secure_cookies=True)
    import urllib.request

    def get(path, method="GET"):
        req = urllib.request.Request(api.base + path, method=method)
        try:
            with urllib.request.urlopen(req, timeout=5) as resp:
                return resp.status, dict(resp.headers), resp.read()
        except urllib.error.HTTPError as exc:
            return exc.code, dict(exc.headers), exc.read()

    status, headers, body = get("/")
    assert status == 200 and headers["Content-Type"].startswith("text/html")
    assert "script-src 'self'" in headers["Content-Security-Policy"]
    assert "frame-ancestors 'none'" in headers["Content-Security-Policy"]
    assert headers["X-Frame-Options"] == "DENY" and headers["X-Content-Type-Options"] == "nosniff"
    assert "max-age" in headers["Strict-Transport-Security"]
    assert get("/saas/crypto.js")[1]["Content-Type"].startswith("text/javascript")
    assert get("/saas.css")[1]["Content-Type"].startswith("text/css")
    assert get("/favicon.svg")[1]["Content-Type"].startswith("image/svg+xml")
    assert get("/saas/")[0] == 404  # directory without index.html
    assert get("/vault.html", method="HEAD")[2] == b""
    for bad in ("/../saas/config.py", "/.git/config", "/nope.html", "/%2e%2e/saas/db.py"):
        assert get(bad)[0] == 404, bad
    status, _, body = get("/api/nope")
    assert status == 404 and json.loads(body)["error"] == "not_found"
    status, headers, _ = get("/api/health")
    assert headers["Content-Security-Policy"].startswith("default-src 'none'")
    assert headers["Cache-Control"] == "no-store"


def test_static_post_is_405_and_options_preflight(make_api):
    api = make_api(cors_origins=["https://app.example"])
    assert api.request("POST", "/index.html", {})[0] == 405
    import urllib.request

    def options(path, origin=None):
        headers = {"Origin": origin} if origin else {}
        req = urllib.request.Request(api.base + path, method="OPTIONS", headers=headers)
        try:
            with urllib.request.urlopen(req, timeout=5) as resp:
                return resp.status, dict(resp.headers)
        except urllib.error.HTTPError as exc:
            return exc.code, dict(exc.headers)

    status, headers = options("/api/vault", "https://app.example")
    assert status == 204 and headers["Access-Control-Allow-Origin"] == "https://app.example"
    assert headers["Access-Control-Allow-Credentials"] == "true"
    assert options("/api/vault", "https://evil.example")[0] == 403
    assert options("/index.html")[0] == 404
    assert options("/api/vault")[0] == 204
    # An allow-listed cross origin may make state-changing calls.
    status, _ = api.request("POST", "/api/prelogin", {"email": "a@example.com"}, headers={"Origin": "https://app.example"})
    assert status == 200


def test_register_validation(make_api, monkeypatch):
    api = make_api()
    monkeypatch.setattr(api.db, "limited", lambda *a, **k: False)
    req = lambda body: api.request("POST", "/api/register", body)  # noqa: E731
    assert req({"email": "bad", "auth_key": b64(32), "kdf_salt": b64(32)})[1]["error"] == "bad_email"
    assert req({"email": "a@example.com", "auth_key": b64(8), "kdf_salt": b64(32)})[0] == 400
    assert req({"email": "a@example.com", "auth_key": b64(32), "kdf_salt": b64(4)})[0] == 400
    status, body = req({"email": "a@example.com", "auth_key": b64(32), "kdf_salt": b64(32), "kdf_params": {"iterations": 1000}})
    assert body["error"] == "weak_kdf"
    assert req({"email": "a@example.com", "auth_key": b64(32), "kdf_salt": b64(32), "kdf_params": "x"})[1]["error"] == "bad_request"
    assert req({"email": "a@example.com", "auth_key": b64(32), "kdf_salt": b64(32), "kdf_params": {"alg": "scrypt"}})[0] == 400
    status, body = req({"email": "a@example.com", "auth_key": b64(32), "kdf_salt": b64(32)})
    assert status == 201 and body["account"]["kdf_params"]["iterations"] == 600000


def test_rate_limits_on_register_and_prelogin(make_api):
    api = make_api()
    statuses = [api.request("POST", "/api/register", {"email": "x"})[0] for _ in range(7)]
    assert statuses[-1] == 429
    statuses = [api.request("POST", "/api/prelogin", {"email": f"p{i}@example.com"})[0] for i in range(7)]
    assert statuses[-1] == 429
    statuses = [api.request("POST", "/api/login", {"email": f"l{i}@example.com"})[0] for i in range(2)]
    assert statuses[-1] == 429  # shares the prelogin bucket
    assert api.request("POST", "/api/prelogin", {"email": "bad"})[0] in {400, 429}


def test_login_edge_cases(make_api):
    api = make_api()
    assert api.request("POST", "/api/login", {"email": "nope"})[1]["error"] == "bad_email"
    assert api.request("POST", "/api/login", {"email": "a@example.com", "auth_key": "!!"})[0] == 400
    api.cookie = None
    assert api.request("POST", "/api/logout", {})[0] == 200  # no session is fine


def test_body_parsing_errors(make_api):
    api = make_api()
    headers = {"Content-Type": "application/json"}
    assert api.request("POST", "/api/prelogin", b"{bad", headers=headers, raw=True)[1]["error"] == "bad_json"
    assert api.request("POST", "/api/prelogin", b"[1]", headers=headers, raw=True)[1]["error"] == "bad_json"
    assert api.request("POST", "/api/prelogin", b"", headers=headers, raw=True)[1]["error"] == "bad_email"
    sock = socket.create_connection(("127.0.0.1", api.port), timeout=5)
    sock.sendall(b"POST /api/prelogin HTTP/1.1\r\nHost: x\r\nContent-Type: application/json\r\nContent-Length: nope\r\n\r\n")
    data = b""
    while chunk := sock.recv(4096):  # the server closes after this error
        data += chunk
    sock.close()
    assert b"bad_length" in data


def test_vault_revisions_export_and_errors(make_api, monkeypatch):
    api = make_api()
    _, created, auth_key, _ = api.register("rev@example.com")
    acct = created["account"]["id"]
    assert api.request("GET", "/api/vault/revisions")[1]["error"] == "pro_required"
    assert api.request("GET", "/api/vault")[1]["error"] == "no_vault"
    status, body = api.request("GET", "/api/account/export")
    assert status == 200 and body["vault"] is None
    make_pro(api, acct)
    for _ in range(3):
        assert api.request("PUT", "/api/vault", _env())[0] == 200
    status, body = api.request("GET", "/api/vault/revisions")
    assert status == 200 and len(body["revisions"]) == 3
    assert api.request("PUT", "/api/vault", {"v": 2})[1]["error"] == "bad_envelope"
    assert api.request("GET", "/api/me")[0] == 200
    assert api.request("POST", "/api/account/delete", {"confirm": "nah", "auth_key": auth_key})[1]["error"] == "confirm_required"

    def boom(*a, **k):
        raise RuntimeError("disk on fire")

    monkeypatch.setattr(api.db, "put_vault", boom)
    status, body = api.request("PUT", "/api/vault", _env())
    assert status == 500 and "disk" not in json.dumps(body)

    def too_big(*a, **k):
        raise ValueError("vault_too_large")

    monkeypatch.setattr(api.db, "put_vault", too_big)
    assert api.request("PUT", "/api/vault", _env())[1]["error"] == "vault_too_large"

    def other_value_error(*a, **k):
        raise ValueError("something else")

    monkeypatch.setattr(api.db, "put_vault", other_value_error)
    assert api.request("PUT", "/api/vault", _env())[1]["error"] == "bad_request"


def test_unauthenticated_routes(make_api):
    api = make_api()
    for method, path in [("GET", "/api/me"), ("GET", "/api/vault/revisions"), ("POST", "/api/checkout"),
                         ("POST", "/api/account/delete"), ("GET", "/api/account/export"), ("PUT", "/api/vault")]:
        body = {} if method != "GET" else None
        assert api.request(method, path, body)[0] == 401, path
    api.cookie = "pwmanager_session=forged"
    assert api.request("GET", "/api/me")[0] == 401
    assert api.request("GET", "/api/me", headers={"Authorization": "Bearer forged"})[0] == 401


def test_bearer_token_and_checkout_503(make_api):
    api = make_api()
    api.register("bearer@example.com")
    token = api.cookie.split("=", 1)[1]
    api.cookie = None
    assert api.request("GET", "/api/me", headers={"Authorization": "Bearer " + token})[0] == 200
    api.cookie = "pwmanager_session=" + token
    assert api.request("POST", "/api/checkout", {})[1]["error"] == "stripe_not_configured"


def test_server_main_prints_and_shuts_down(monkeypatch, capsys):
    class FakeHttpd:
        server_address = ("127.0.0.1", 1234)

        def serve_forever(self):
            raise KeyboardInterrupt

        def shutdown(self):
            self.stopped = True

    class FakeApp:
        cfg = Config(**_stripe_cfg())
        web_root = "web"

    monkeypatch.setattr(saas_server, "make_server", lambda cfg: (FakeHttpd(), FakeApp()))
    saas_server.main()
    out = capsys.readouterr().out
    assert "stripe:   configured" in out and "shutting down" in out
    FakeApp.cfg = Config()
    saas_server.main()
    assert "not configured" in capsys.readouterr().out


# ------------------------------------------------------------------ auth / config / db units


def test_pbkdf2_fallback_verifier(monkeypatch):
    monkeypatch.setattr(auth, "ARGON2_AVAILABLE", False)
    monkeypatch.setattr(auth, "_DUMMY_VERIFIER", None)
    key = b"k" * 32
    stored = auth.hash_auth_key(key)
    assert stored.startswith("pbkdf2-sha256$")
    assert auth.verify_auth_key(stored, key) is True
    assert auth.verify_auth_key(stored, b"x" * 32) is False
    assert auth.verify_auth_key("pbkdf2-sha256$bad", key) is False
    assert auth.verify_auth_key("$argon2id$v=19$whatever", key) is False
    assert auth.verify_auth_key("deleted", key) is False


def test_argon2_verifier_rejects_garbage():
    assert auth.verify_auth_key("$argon2id$garbage", b"k" * 32) is False
    assert auth.verify_auth_key("", b"k" * 32) is False


def test_auth_helpers():
    assert auth.valid_email("a@b.co") and not auth.valid_email("a@b") and not auth.valid_email("@b.co")
    assert not auth.valid_email("a@.b.co") and not auth.valid_email("a b@c.co") and not auth.valid_email("x" * 300)
    import base64

    assert auth.decode_auth_key(base64.urlsafe_b64encode(b"k" * 32).decode().rstrip("=")) == b"k" * 32

    std = base64.b64encode(b"\xfb" * 32).decode()  # contains "+" and "/"
    assert auth.decode_auth_key(std) == b"\xfb" * 32
    assert auth.decode_salt(std) == b"\xfb" * 32
    with pytest.raises(ValueError):
        auth.decode_auth_key("")
    with pytest.raises(ValueError):
        auth.decode_salt(base64.b64encode(b"s").decode())
    assert auth.parse_iso("2026-01-01T00:00:00Z").year == 2026
    with pytest.raises(ValueError):
        auth.canonical_kdf_params({"iterations": True})
    with pytest.raises(ValueError):
        auth.canonical_kdf_params({"iterations": "many"})
    with pytest.raises(ValueError, match="at most"):
        auth.canonical_kdf_params({"iterations": 10**9})
    assert auth.canonical_kdf_params(None)["iterations"] == 600000
    assert auth.canonical_kdf_params({"iterations": "700000"})["iterations"] == 700000


def test_load_config_from_environment(monkeypatch):
    monkeypatch.setenv("PWMANAGER_PUBLIC_URL", "https://vault.example/")
    monkeypatch.setenv("PWMANAGER_CORS_ORIGINS", "https://a.example/, ,https://b.example")
    monkeypatch.setenv("PWMANAGER_PORT", "9999")
    monkeypatch.setenv("PWMANAGER_TRUST_PROXY", "yes")
    cfg = load_config({"db_path": ":memory:"})
    assert cfg.public_url == "https://vault.example" and cfg.secure_cookies is True
    assert cfg.port == 9999 and cfg.trust_proxy is True and cfg.db_path == ":memory:"
    allow = cfg.cors_allowlist()
    assert allow[:3] == ["https://a.example", "https://b.example", "https://vault.example"]
    assert not cfg.stripe_configured


def test_db_sessions_and_plans(tmp_path):
    db = Database(str(tmp_path / "d.sqlite"))
    acct = db.create_account("s@example.com", b"k" * 32, b64(32), None)
    token = db.create_session(acct["id"], "ua")
    assert db.session_account(token)["id"] == acct["id"]
    assert db.session_account("") is None
    db.execute("UPDATE sessions SET expires_at = ?", (isoformat(utcnow() - timedelta(seconds=5)),))
    assert db.session_account(token) is None
    assert db.execute("SELECT COUNT(*) AS n FROM sessions").fetchone()["n"] == 0
    token = db.create_session(acct["id"], "ua")
    db.execute("UPDATE sessions SET expires_at = 'garbage'")
    assert db.session_account(token) is None
    sid = db.execute("SELECT id FROM sessions").fetchone()["id"]
    db.revoke_session_id(sid)
    assert db.get_account_by_stripe_customer("") is None
    db.set_plan("missing", "pro")  # silently ignored
    db.delete_account("missing")
    assert db.payment_event_seen("evt") is False
    db.record_payment_event("evt", "t", None, None)
    assert db.payment_event_seen("evt") is True

    row = dict(db.get_account_by_id(acct["id"]))
    assert is_pro(None) is False and is_pro(row) is False
    row.update(plan="pro", plan_status="canceled")
    assert is_pro(row) is False
    row.update(plan_status="active", plan_period_end="not a date")
    assert is_pro(row) is True
    row.update(plan_status="past_due", plan_period_end="2000-01-01T00:00:00Z")
    assert is_pro(row) is True
    row["kdf_params"] = "{bad"
    assert account_public(row)["kdf_params"]["iterations"] == 600000
    db.execute("UPDATE accounts SET kdf_params = '{bad'")
    assert db.prelogin("s@example.com")["kdf_params"]["iterations"] == 600000
    with pytest.raises(ValueError):
        db.put_vault(acct["id"], "c", "n", 1, 10**9, pro=False)
    db.close()


def test_db_migrates_old_schema(tmp_path):
    import sqlite3

    path = str(tmp_path / "old.sqlite")
    conn = sqlite3.connect(path)
    conn.execute(
        "CREATE TABLE accounts (id TEXT PRIMARY KEY, email TEXT NOT NULL UNIQUE, auth_verifier TEXT NOT NULL,"
        " kdf_salt TEXT NOT NULL, kdf_params TEXT NOT NULL, created_at TEXT NOT NULL, last_login_at TEXT,"
        " email_verified_at TEXT, stripe_customer_id TEXT, plan TEXT NOT NULL DEFAULT 'free', plan_status TEXT,"
        " plan_period_end TEXT, deleted_at TEXT)"
    )
    conn.commit()
    conn.close()
    db = Database(path)
    cols = {r["name"] for r in db.execute("PRAGMA table_info(accounts)")}
    assert "plan_event_at" in cols
    db.close()


def test_revision_cap(tmp_path, monkeypatch):
    import saas.db as sdb

    monkeypatch.setattr(sdb, "REVISION_CAP", 2)
    db = Database(str(tmp_path / "r.sqlite"))
    acct = db.create_account("r@example.com", b"k" * 32, b64(32), None)
    for i in range(5):
        db.put_vault(acct["id"], f"c{i}", "n", 1, 10, pro=True)
    assert len(db.list_revisions(acct["id"])) == 3  # current + 2
    db.close()


# ------------------------------------------------------------------ envelope units


def test_envelope_edge_cases():
    good = _env()
    assert parse_envelope(json.dumps(good))["v"] == 1
    assert parse_envelope(json.dumps(good).encode())["v"] == 1
    with_ts = parse_envelope({**good, "updated_at": "12"})
    assert with_ts["updated_at"] == 12
    ct, nonce, version = envelope_parts(with_ts)
    assert (ct, nonce, version) == (good["ct"], good["nonce"], 1)
    assert envelope_byte_size(with_ts) > 0
    bad_cases = [
        b"\xff", "{nope", "[]", {**good, "entries": []}, {k: v for k, v in good.items() if k != "ct"},
        {**good, "v": 2}, {**good, "nonce": ""}, {**good, "nonce": "!!!!"}, {**good, "nonce": b64(11)},
        {**good, "ct": b64(4)}, {**good, "kdf": "x"}, {**good, "kdf": {**good["kdf"], "alg": "scrypt"}},
        {**good, "kdf": {**good["kdf"], "iterations": None}}, {**good, "kdf": {**good["kdf"], "iterations": True}},
        {**good, "kdf": {**good["kdf"], "iterations": 5}}, {**good, "kdf": {**good["kdf"], "iterations": 10**9}},
        {**good, "kdf": {**good["kdf"], "salt": 5}}, {**good, "kdf": {**good["kdf"], "salt": b64(16)}},
        {**good, "updated_at": "soon"}, {**good, "ct": "A"},
    ]
    for case in bad_cases:
        with pytest.raises(EnvelopeError):
            parse_envelope(case)
    assert parse_envelope({**good, "nonce": b64(12).rstrip("=")})["v"] == 1
