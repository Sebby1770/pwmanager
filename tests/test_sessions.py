"""Signed-in devices (list / revoke / revoke others) and the security event log."""

from __future__ import annotations

import sqlite3

import pytest

from saas.auth import device_label
from saas.db import Database
from tests.cloud_helpers import register, v2
from tests.conftest import ApiClient

EMAIL = "devices@example.com"
FIREFOX = "Mozilla/5.0 (X11; Linux x86_64; rv:140.0) Gecko/20100101 Firefox/140.0"
IPHONE = "Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X) AppleWebKit/605.1.15 Version/18.0 Mobile/15E148 Safari/604.1"


@pytest.fixture
def three_devices(make_api):
    api = make_api()
    keys = v2(EMAIL)
    assert register(api, EMAIL, keys)[0] == 201
    devices = []
    for ua in (FIREFOX, IPHONE):
        client = ApiClient(api.base)
        status, _ = client.request("POST", "/api/login", {"email": EMAIL, "auth_key": keys.auth_b64},
                                   headers={"User-Agent": ua})
        assert status == 200
        devices.append(client)
    return api, keys, devices


@pytest.mark.parametrize(
    "ua,label",
    [
        (FIREFOX, "Firefox on Linux"),
        (IPHONE, "Safari on iOS"),
        ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/141.0 Safari/537.36 Edg/141.0", "Edge on Windows"),
        ("Mozilla/5.0 (Macintosh; Intel Mac OS X 14_5) AppleWebKit/537.36 Chrome/141.0 Safari/537.36", "Chrome on macOS"),
        ("pwmanager-cli/3.3", "pwmanager CLI"),
        ("", "Unknown browser"),
    ],
)
def test_device_labels_are_coarse(ua, label):
    assert device_label(ua) == label


def test_list_shows_every_device_and_marks_this_one(three_devices):
    api, _, (firefox, iphone) = three_devices
    status, body = firefox.request("GET", "/api/sessions")
    assert status == 200 and len(body["sessions"]) == 3
    current = [s for s in body["sessions"] if s["current"]]
    assert len(current) == 1 and current[0]["device"] == "Firefox on Linux"
    devices = {s["device"] for s in body["sessions"]}
    assert {"Firefox on Linux", "Safari on iOS"} <= devices
    for s in body["sessions"]:
        assert set(s) == {"id", "device", "created_at", "last_used_at", "expires_at", "current"}
    # Nothing identifying is stored or returned.
    row = api.db.execute("SELECT * FROM sessions LIMIT 1").fetchone()
    assert FIREFOX not in str(tuple(row)) and "127.0.0.1" not in str(tuple(row))


def test_revoke_one_device(three_devices):
    _, _, (firefox, iphone) = three_devices
    sessions = firefox.request("GET", "/api/sessions")[1]["sessions"]
    phone = next(s for s in sessions if s["device"] == "Safari on iOS")
    status, body = firefox.request("POST", "/api/sessions/revoke", {"id": phone["id"]})
    assert status == 200 and body["current"] is False
    assert iphone.request("GET", "/api/me")[0] == 401
    assert firefox.request("GET", "/api/me")[0] == 200


def test_revoking_the_current_session_signs_out(three_devices):
    _, _, (firefox, _) = three_devices
    me = next(s for s in firefox.request("GET", "/api/sessions")[1]["sessions"] if s["current"])
    status, body = firefox.request("POST", "/api/sessions/revoke", {"id": me["id"]})
    assert status == 200 and body["current"] is True and firefox.cookie is None
    assert firefox.request("GET", "/api/me")[0] == 401


def test_revoke_everywhere_else(three_devices):
    api, _, (firefox, iphone) = three_devices
    status, body = firefox.request("POST", "/api/sessions/revoke-others", {})
    assert status == 200 and body["revoked"] == 2
    assert iphone.request("GET", "/api/me")[0] == 401 and api.request("GET", "/api/me")[0] == 401
    assert firefox.request("GET", "/api/me")[0] == 200
    assert len(firefox.request("GET", "/api/sessions")[1]["sessions"]) == 1


def test_cannot_see_or_revoke_another_accounts_sessions(three_devices):
    api, _, (firefox, _) = three_devices
    victim_sessions = {s["id"] for s in firefox.request("GET", "/api/sessions")[1]["sessions"]}
    attacker = ApiClient(api.base)
    register(attacker, "attacker@example.com", v2("attacker@example.com"))
    listed = {s["id"] for s in attacker.request("GET", "/api/sessions")[1]["sessions"]}
    assert listed.isdisjoint(victim_sessions)
    for sid in victim_sessions:
        assert attacker.request("POST", "/api/sessions/revoke", {"id": sid})[0] == 404
    assert firefox.request("GET", "/api/me")[0] == 200


def test_session_routes_need_a_session(make_api):
    api = make_api()
    assert api.request("GET", "/api/sessions")[0] == 401
    assert api.request("POST", "/api/sessions/revoke", {"id": "x"})[0] == 401
    assert api.request("POST", "/api/sessions/revoke-others", {})[0] == 401
    assert api.request("GET", "/api/account/events")[0] == 401


def test_security_events_newest_first_without_noise(three_devices):
    api, keys, (firefox, _) = three_devices
    from tests.conftest import make_pro

    make_pro(api, api.db.get_account_by_email(EMAIL)["id"])
    firefox.request("PUT", "/api/vault", keys.seal({"version": 1, "entries": []}))
    firefox.request("POST", "/api/sessions/revoke-others", {})
    status, body = firefox.request("GET", "/api/account/events")
    names = [e["event"] for e in body["events"]]
    assert names[0] == "other_sessions_revoked"
    assert "register" in names and names.count("login") == 2
    assert "vault_put" not in names
    assert all(set(e) == {"event", "at"} for e in body["events"]), "no IP hashes in the response"


def test_last_used_is_tracked_but_rate_limited(three_devices):
    api, _, (firefox, _) = three_devices
    api.db.execute("UPDATE sessions SET last_used_at = '2000-01-01T00:00:00Z'")
    firefox.request("GET", "/api/me")
    rows = api.db.execute("SELECT last_used_at FROM sessions").fetchall()
    assert sum(r["last_used_at"] != "2000-01-01T00:00:00Z" for r in rows) == 1
    first = max(r["last_used_at"] for r in rows)
    firefox.request("GET", "/api/me")
    assert max(r["last_used_at"] for r in api.db.execute("SELECT last_used_at FROM sessions")) == first


def test_old_sessions_table_is_migrated(tmp_path):
    path = str(tmp_path / "old.sqlite")
    conn = sqlite3.connect(path)
    conn.execute("CREATE TABLE sessions (id TEXT PRIMARY KEY, account_id TEXT NOT NULL, token_hash TEXT NOT NULL,"
                 " expires_at TEXT NOT NULL, created_at TEXT NOT NULL, user_agent_hash TEXT)")
    conn.commit()
    conn.close()
    db = Database(path)
    cols = {r["name"] for r in db.execute("PRAGMA table_info(sessions)")}
    assert {"device_label", "last_used_at"} <= cols
    db.close()
