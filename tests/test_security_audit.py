"""Regression tests for the 3.3 security audit. Each test reproduces one finding.

Finding ids (F1…) match the table in SECURITY.md.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import socket
import time

import pytest

from pwmanager.vault import Vault, VaultIntegrityError
from tests.conftest import b64, fake_webhook_secret, make_pro


def _signed(secret: str, event: dict):
    payload = json.dumps(event).encode("utf-8")
    ts = str(int(time.time()))
    sig = hmac.new(secret.encode(), ts.encode() + b"." + payload, hashlib.sha256).hexdigest()
    return payload, {"Content-Type": "application/json", "Stripe-Signature": f"t={ts},v1={sig}"}


def _send_event(api, secret, event):
    payload, headers = _signed(secret, event)
    return api.request("POST", "/api/stripe/webhook", payload, headers=headers, raw=True)


def _event(event_id, event_type, account_id, created, **obj):
    data = {"metadata": {"account_id": account_id}, "customer": "cus_" + account_id[:8]}
    data.update(obj)
    return {"id": event_id, "type": event_type, "created": created, "data": {"object": data}}


# ------------------------------------------------------------ F1 unpaid checkout


def test_f1_unpaid_async_checkout_does_not_grant_pro(make_api):
    """Async payment methods (e.g. BECS debit) complete Checkout before money moves."""
    secret = fake_webhook_secret()
    api = make_api(stripe_webhook_secret=secret)
    _, created, *_ = api.register("async@example.com")
    account_id = created["account"]["id"]
    now = int(time.time())

    status, _ = _send_event(
        api,
        secret,
        _event("evt_f1a", "checkout.session.completed", account_id, now,
               object="checkout.session", payment_status="unpaid"),
    )
    assert status == 200
    assert api.db.get_account_by_id(account_id)["plan"] == "free"

    status, _ = _send_event(
        api,
        secret,
        _event("evt_f1b", "checkout.session.async_payment_failed", account_id, now + 1,
               object="checkout.session", payment_status="unpaid"),
    )
    assert api.db.get_account_by_id(account_id)["plan"] == "free"

    _send_event(
        api,
        secret,
        _event("evt_f1c", "checkout.session.async_payment_succeeded", account_id, now + 2,
               object="checkout.session", payment_status="paid"),
    )
    assert api.db.get_account_by_id(account_id)["plan"] == "pro"


def test_f1_paid_checkout_still_grants_pro(make_api):
    secret = fake_webhook_secret()
    api = make_api(stripe_webhook_secret=secret)
    _, created, *_ = api.register("paid@example.com")
    account_id = created["account"]["id"]
    _send_event(
        api,
        secret,
        _event("evt_paid", "checkout.session.completed", account_id, int(time.time()),
               object="checkout.session", payment_status="paid"),
    )
    assert api.db.get_account_by_id(account_id)["plan"] == "pro"


# ------------------------------------------------------------ F2 out-of-order events


def test_f2_stale_webhook_cannot_resurrect_cancelled_plan(make_api):
    """Stripe does not guarantee delivery order; a late retry must not win."""
    secret = fake_webhook_secret()
    api = make_api(stripe_webhook_secret=secret)
    _, created, *_ = api.register("late@example.com")
    account_id = created["account"]["id"]
    now = int(time.time())

    _send_event(api, secret, _event("evt_new", "customer.subscription.deleted", account_id, now,
                                    object="subscription", status="canceled"))
    # An older "active" update, delivered late by Stripe's retry schedule.
    _send_event(api, secret, _event("evt_old", "customer.subscription.updated", account_id, now - 3600,
                                    object="subscription", status="active",
                                    current_period_end=now + 30 * 86400))
    row = api.db.get_account_by_id(account_id)
    assert row["plan"] == "free"
    assert row["plan_status"] == "canceled"


# ------------------------------------------------------------ F3/F4 rate limiting


def _wrong_login(api, email, xff=None):
    headers = {"X-Forwarded-For": xff} if xff else None
    return api.request("POST", "/api/login", {"email": email, "auth_key": b64(32)}, headers=headers)[0]


def test_f3_spoofed_forwarded_for_does_not_bypass_login_limit(make_api):
    """Behind a proxy the *last* hop is the one the proxy vouches for."""
    api = make_api(trust_proxy=True)
    api.register("victim@example.com")
    api.cookie = None
    statuses = [
        _wrong_login(api, "victim@example.com", xff=f"198.51.100.{i}, 203.0.113.7") for i in range(8)
    ]
    assert 429 in statuses, statuses


def test_f4_per_account_login_limit_across_many_ips(make_api):
    """A botnet with many real IPs still hits a per-account ceiling."""
    api = make_api(trust_proxy=True)
    api.register("target@example.com")
    api.cookie = None
    statuses = [_wrong_login(api, "target@example.com", xff=f"203.0.113.{i}") for i in range(25)]
    assert 429 in statuses, statuses


def test_f4_per_account_limit_does_not_block_other_accounts(make_api):
    api = make_api(trust_proxy=True)
    _, _, auth, _ = api.register("other@example.com")
    api.register("target2@example.com")
    api.cookie = None
    for i in range(25):
        _wrong_login(api, "target2@example.com", xff=f"203.0.113.{i}")
    status, _ = api.request(
        "POST", "/api/login", {"email": "other@example.com", "auth_key": auth},
        headers={"X-Forwarded-For": "192.0.2.50"},
    )
    assert status == 200


# ------------------------------------------------------------ F9 unbounded input


def test_f9_register_rejects_oversized_kdf_params(make_api):
    api = make_api()
    params = {"alg": "PBKDF2-HMAC-SHA256", "iterations": 600000, "junk": "A" * 200_000}
    status, body, *_ = api.register("big@example.com", kdf_params=params)
    assert status in {400, 413}, body
    assert api.db.get_account_by_email("big@example.com") is None


def test_f9_register_stores_only_canonical_kdf_params(make_api):
    api = make_api()
    params = {"alg": "PBKDF2-HMAC-SHA256", "iterations": 600000, "hash": "SHA-256", "note": "x"}
    status, body, *_ = api.register("canon@example.com", kdf_params=params)
    assert status == 201, body
    stored = json.loads(api.db.get_account_by_email("canon@example.com")["kdf_params"])
    assert "note" not in stored
    assert stored["iterations"] == 600000


def test_f9_register_rejects_absurd_iterations(make_api):
    api = make_api()
    params = {"alg": "PBKDF2-HMAC-SHA256", "iterations": 10**12}
    status, body, *_ = api.register("slow@example.com", kdf_params=params)
    assert status == 400, body


def test_f9_json_routes_cap_body_size(make_api):
    api = make_api()
    status, body = api.request("POST", "/api/login", {"email": "a@example.com", "pad": "A" * 1_000_000})
    assert status == 413, body


# ------------------------------------------------------------ F10 CSRF / re-auth


def test_f10_cross_origin_state_change_is_refused(make_api):
    api = make_api()
    _, created, auth, _ = api.register("csrf@example.com")
    status, body = api.request(
        "POST", "/api/account/delete", {"confirm": "DELETE", "auth_key": auth},
        headers={"Origin": "https://evil.example"},
    )
    assert status == 403, body
    assert api.db.get_account_by_id(created["account"]["id"]) is not None


def test_f10_state_change_requires_json_content_type(make_api):
    api = make_api()
    _, created, auth, _ = api.register("form@example.com")
    body = json.dumps({"confirm": "DELETE", "auth_key": auth}).encode()
    status, _ = api.request(
        "POST", "/api/account/delete", body, headers={"Content-Type": "text/plain"}, raw=True
    )
    assert status == 415
    assert api.db.get_account_by_id(created["account"]["id"]) is not None


def test_f10_account_delete_requires_reauthentication(make_api):
    api = make_api()
    _, created, auth, _ = api.register("reauth@example.com")
    account_id = created["account"]["id"]
    status, _ = api.request("POST", "/api/account/delete", {"confirm": "DELETE"})
    assert status == 401
    status, _ = api.request("POST", "/api/account/delete", {"confirm": "DELETE", "auth_key": b64(32)})
    assert status == 401
    assert api.db.get_account_by_id(account_id) is not None
    status, _ = api.request("POST", "/api/account/delete", {"confirm": "DELETE", "auth_key": auth})
    assert status == 200
    assert api.db.get_account_by_id(account_id) is None


def test_f10_same_origin_requests_still_work(make_api):
    api = make_api()
    _, created, _auth, _ = api.register("same@example.com")
    make_pro(api, created["account"]["id"])
    origin = f"http://127.0.0.1:{api.port}"
    env = {"v": 1, "nonce": b64(12), "ct": b64(48),
           "kdf": {"alg": "PBKDF2-HMAC-SHA256", "iterations": 600000, "salt": b64(32)}}
    status, body = api.request("PUT", "/api/vault", env, headers={"Origin": origin})
    assert status == 200, body


# ------------------------------------------------------------ F11 slow clients


def test_f11_stalled_request_body_is_timed_out(make_api):
    """A client that promises a body and never sends it must not pin a thread forever."""
    api = make_api(request_timeout=1)
    sock = socket.create_connection(("127.0.0.1", api.port), timeout=6)
    try:
        sock.sendall(
            b"POST /api/login HTTP/1.1\r\nHost: x\r\nContent-Type: application/json\r\n"
            b"Content-Length: 100\r\n\r\n{"
        )
        start = time.time()
        try:
            while sock.recv(4096):
                pass
        except socket.timeout:
            pytest.fail("server kept a stalled connection open")
        assert time.time() - start < 5
    finally:
        sock.close()


# ------------------------------------------------------------ F8 CLI integrity strip


def _vault(tmp_path):
    path = str(tmp_path / "v.json")
    v = Vault(path)
    v.create("correct horse battery staple", kdf="pbkdf2")
    return path


def test_f8_stripping_hmac_does_not_skip_integrity_check(tmp_path):
    path = _vault(tmp_path)
    with open(path) as f:
        payload = json.load(f)
    del payload["hmac"]
    payload["version"] = 1
    with open(path, "w") as f:
        json.dump(payload, f)
    with pytest.raises(VaultIntegrityError):
        Vault(path).unlock("correct horse battery staple")


def test_f8_import_without_hmac_is_rejected(tmp_path):
    src = Vault(str(tmp_path / "src.json"))
    src.create("correct horse battery staple", kdf="pbkdf2")
    out = str(tmp_path / "export.json")
    src.export_encrypted(out, "export password value")
    with open(out) as f:
        payload = json.load(f)
    del payload["hmac"]
    with open(out, "w") as f:
        json.dump(payload, f)
    dest = Vault(str(tmp_path / "dest.json"))
    dest.create("another master password", kdf="pbkdf2")
    with pytest.raises(ValueError):
        dest.import_encrypted(out, "export password value")
