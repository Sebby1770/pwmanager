"""stdlib HTTP API + static file server for the pwmanager SaaS.

Run locally:

    python saas/server.py

The process never receives master passwords, vault keys, TOTP secrets, or
card numbers. Vault PUT bodies must be opaque AES-GCM envelopes.
"""

from __future__ import annotations

import json
import mimetypes
import os
import socket
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Dict, Optional, Tuple
from urllib.parse import urlparse

if __package__ is None:  # python saas/server.py
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from saas import __version__
from saas.auth import (
    canonical_kdf_params,
    decode_auth_key,
    decode_salt,
    hash_email,
    isoformat,
    normalize_email,
    valid_email,
    verify_auth_key,
)
from saas.config import (
    Config,
    FREE_VAULT_MAX_BYTES,
    HTTP_BODY_MAX_BYTES,
    JSON_BODY_MAX_BYTES,
    LOGIN_ACCOUNT_LIMIT,
    LOGIN_ACCOUNT_WINDOW,
    PRO_VAULT_MAX_BYTES,
    WEB_DIR,
    WEBHOOK_BODY_MAX_BYTES,
    load_config,
)
from saas.db import Database, account_public, blob_to_envelope, is_pro
from saas.envelope import EnvelopeError, envelope_byte_size, envelope_parts, parse_envelope
from saas.mfa import Mfa, MfaError, rp_for
from saas.stripeutil import (
    StripeError,
    apply_webhook_event,
    create_checkout_session,
    event_from_payload,
    not_configured_body,
    stripe_configured,
    verify_stripe_signature,
)

COOKIE_NAME = "pwmanager_session"

# Routes that change state on behalf of a signed-in browser. They get an Origin
# check and must be JSON, so a cross-site <form> cannot reach them even from a
# same-site origin (where SameSite=Strict does not help) or an older browser.
# The Stripe webhook is exempt: it is authenticated by its own HMAC.
CSRF_EXEMPT = frozenset({"/api/stripe/webhook"})

SECURITY_HEADERS = (
    ("X-Content-Type-Options", "nosniff"),
    ("X-Frame-Options", "DENY"),
    ("Referrer-Policy", "no-referrer"),
    ("Permissions-Policy", "camera=(), microphone=(), geolocation=(), payment=()"),
    ("X-Permitted-Cross-Domain-Policies", "none"),
    ("Cache-Control", "no-store"),
)

API_CSP = (
    "default-src 'none'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'"
)

STATIC_CSP = (
    "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; "
    "connect-src 'self' https://api.stripe.com https://api.pwnedpasswords.com; "
    "form-action 'self'; base-uri 'none'; frame-ancestors 'none'"
)


class App:
    def __init__(self, cfg: Optional[Config] = None, db: Optional[Database] = None):
        self.cfg = cfg or load_config()
        self.db = db or Database(self.cfg.db_path)
        self.web_root = Path(self.cfg.web_root).resolve()
        rp_id, origins = rp_for(self.cfg.public_url, self.cfg.webauthn_rp_id, self.cfg.cors_origins)
        self.mfa = Mfa(self.db, rp_id, origins)


class _ClientGone(Exception):
    """The client stopped sending mid-body; drop the connection silently."""


def make_handler(app: App):
    application = app

    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"
        app = application
        # Applied to the socket by StreamRequestHandler.setup(): a client that
        # stalls mid-headers or mid-body is dropped instead of pinning a thread.
        timeout = application.cfg.request_timeout

        def log_message(self, fmt: str, *args) -> None:
            sys.stderr.write("%s - %s\n" % (self.address_string(), fmt % args))

        def _client_ip(self) -> str:
            if self.app.cfg.trust_proxy:
                # The proxy appends the address it saw; everything to the left
                # of that came from the client and can be forged at will.
                forwarded = self.headers.get("X-Forwarded-For", "")
                hops = [hop.strip() for hop in forwarded.split(",") if hop.strip()]
                if hops:
                    return hops[-1]
            return self.client_address[0]

        def _origin_allowed(self) -> Optional[str]:
            origin = (self.headers.get("Origin") or "").rstrip("/")
            if not origin:
                return None
            host = self.headers.get("Host", "")
            if origin in {f"http://{host}", f"https://{host}"}:
                return origin
            allow = {item.rstrip("/") for item in self.app.cfg.cors_allowlist()}
            if origin in allow:
                return origin
            return None

        def _security_headers(self, content_type: str, extra: Optional[list] = None, csp: Optional[str] = None) -> None:
            self.send_header("Content-Type", content_type)
            for key, value in SECURITY_HEADERS:
                self.send_header(key, value)
            self.send_header("Content-Security-Policy", csp or API_CSP)
            origin = self._origin_allowed()
            if origin:
                self.send_header("Access-Control-Allow-Origin", origin)
                self.send_header("Access-Control-Allow-Credentials", "true")
                self.send_header("Vary", "Origin")
            if extra:
                for key, value in extra:
                    self.send_header(key, value)
            if self.app.cfg.secure_cookies:
                self.send_header(
                    "Strict-Transport-Security",
                    "max-age=63072000; includeSubDomains",
                )

        def _send(
            self,
            status: int,
            body: bytes,
            content_type: str,
            extra: Optional[list] = None,
            csp: Optional[str] = None,
        ) -> None:
            self.send_response(status)
            self._security_headers(content_type, extra=extra, csp=csp)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            if self.command != "HEAD":
                self.wfile.write(body)

        def _json(self, status: int, payload: dict, extra: Optional[list] = None) -> None:
            body = json.dumps(payload, separators=(",", ":")).encode("utf-8")
            self._send(status, body, "application/json; charset=utf-8", extra=extra)

        def _error(self, status: int, code: str, message: str, extra: Optional[dict] = None) -> None:
            payload = {"error": code, "message": message}
            if extra:
                payload.update(extra)
            self._json(status, payload)

        def handle_one_request(self) -> None:
            self._body_read = False
            super().handle_one_request()
            if getattr(self, "command", None) and not self._body_read and self._has_body():
                # A handler answered without consuming the body (401, 404,
                # 429, 503, …). Left on a keep-alive socket, those bytes would
                # be parsed as the *next* request, which is request smuggling
                # behind any proxy that reuses upstream connections. Close.
                self.close_connection = True

        def _has_body(self) -> bool:
            if self.headers is None:
                return False
            if self.headers.get("Transfer-Encoding"):
                return True  # chunked bodies are never read by this server
            return (self.headers.get("Content-Length") or "0").strip() not in {"", "0"}

        def do_OPTIONS(self) -> None:  # noqa: N802
            path = urlparse(self.path).path
            if not path.startswith("/api/"):
                self._error(404, "not_found", "Not found")
                return
            origin = self._origin_allowed()
            if self.headers.get("Origin") and origin is None:
                self._error(403, "origin_forbidden", "Origin is not allowed")
                return
            self.send_response(204)
            self._security_headers("text/plain")
            self.send_header("Access-Control-Allow-Methods", "GET, POST, PUT, OPTIONS")
            self.send_header(
                "Access-Control-Allow-Headers",
                "Authorization, Content-Type, Stripe-Signature",
            )
            self.send_header("Access-Control-Max-Age", "600")
            self.send_header("Content-Length", "0")
            self.end_headers()

        def do_HEAD(self) -> None:  # noqa: N802
            self._dispatch()

        def do_GET(self) -> None:  # noqa: N802
            self._dispatch()

        def do_POST(self) -> None:  # noqa: N802
            self._dispatch()

        def do_PUT(self) -> None:  # noqa: N802
            self._dispatch()

        def _dispatch(self) -> None:
            parsed = urlparse(self.path)
            path = parsed.path or "/"
            if path.startswith("/api/"):
                if not self._csrf_ok(path):
                    return
                try:
                    self._api(self.command, path)
                except _ClientGone:
                    return
                except MfaError as exc:
                    self._error(exc.status, exc.code, str(exc))
                except EnvelopeError as exc:
                    self._error(400, "bad_envelope", str(exc))
                except StripeError as exc:
                    if str(exc) == "stripe_not_configured" or exc.status == 503:
                        self._json(503, not_configured_body())
                    else:
                        self._error(exc.status, "stripe_error", str(exc))
                except ValueError as exc:
                    self._error(400, "bad_request", str(exc))
                except Exception:
                    self.log_message("internal error on %s", path)
                    self._error(500, "internal", "Internal server error")
                return
            if self.command not in {"GET", "HEAD"}:
                self._error(405, "method_not_allowed", "Method not allowed")
                return
            self._static(path)

        def _csrf_ok(self, path: str) -> bool:
            if self.command not in {"POST", "PUT"} or path in CSRF_EXEMPT:
                return True
            if self.headers.get("Origin") and self._origin_allowed() is None:
                self._error(403, "origin_forbidden", "Cross-origin requests are not allowed")
                self.close_connection = True
                return False
            has_body = self._has_body()
            ctype = (self.headers.get("Content-Type") or "").split(";", 1)[0].strip().lower()
            if has_body and ctype != "application/json":
                self._error(415, "unsupported_media_type", "Request body must be application/json")
                self.close_connection = True
                return False
            return True

        def _read_body(self, max_size: int = HTTP_BODY_MAX_BYTES) -> Optional[bytes]:
            raw_len = self.headers.get("Content-Length", "0") or "0"
            try:
                length = int(raw_len)
            except ValueError:
                self._error(400, "bad_length", "Invalid Content-Length")
                return None
            if length < 0 or length > max_size:
                self._error(413, "payload_too_large", f"Body exceeds {max_size} bytes")
                # The unread body is still on the socket; do not parse it as
                # the next request.
                self.close_connection = True
                return None
            self._body_read = True
            try:
                data = self.rfile.read(length)
            except (socket.timeout, TimeoutError, ConnectionError):
                self.close_connection = True
                raise _ClientGone()
            if len(data) != length:
                self.close_connection = True
                raise _ClientGone()
            return data

        def _json_body(self) -> Optional[dict]:
            raw = self._read_body(JSON_BODY_MAX_BYTES)
            if raw is None:
                return None
            if not raw:
                return {}
            try:
                data = json.loads(raw.decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError):
                self._error(400, "bad_json", "Body must be JSON")
                return None
            if not isinstance(data, dict):
                self._error(400, "bad_json", "JSON object required")
                return None
            return data

        def _session_token(self) -> Optional[str]:
            auth = self.headers.get("Authorization") or ""
            if auth.lower().startswith("bearer "):
                return auth[7:].strip() or None
            cookie = self.headers.get("Cookie") or ""
            for part in cookie.split(";"):
                key, _, value = part.strip().partition("=")
                if key == COOKIE_NAME:
                    return value or None
            return None

        def _current_account(self):
            token = self._session_token()
            if not token:
                return None, None
            account = self.app.db.session_account(token)
            return account, token

        def _require_account(self):
            account, token = self._current_account()
            if account is None:
                self._error(401, "unauthorized", "Sign in required")
                return None, None
            return account, token

        def _cookie(self, token: str, delete: bool = False) -> str:
            parts = [f"{COOKIE_NAME}={'' if delete else token}", "HttpOnly", "SameSite=Strict", "Path=/"]
            parts.append("Max-Age=0" if delete else "Max-Age=1209600")
            if self.app.cfg.secure_cookies:
                parts.append("Secure")
            return "; ".join(parts)

        def _rate_key(self, bucket: str) -> str:
            return f"{bucket}:{self.app.db.ip_hash(self._client_ip())}"

        def _api(self, method: str, path: str) -> None:
            if method == "GET" and path == "/api/health":
                self._json(
                    200,
                    {
                        "ok": True,
                        "service": "pwmanager",
                        "version": __version__,
                        "stripe_configured": stripe_configured(self.app.cfg),
                    },
                )
                return
            if method == "POST" and path == "/api/register":
                self._register()
                return
            if method == "POST" and path == "/api/prelogin":
                self._prelogin()
                return
            if method == "POST" and path == "/api/login":
                self._login()
                return
            if method == "POST" and path == "/api/login/webauthn":
                self._login_webauthn()
                return
            if method == "POST" and path == "/api/login/recovery":
                self._login_recovery()
                return
            if method == "POST" and path == "/api/webauthn/register/options":
                self._webauthn_register_options()
                return
            if method == "POST" and path == "/api/webauthn/register/verify":
                self._webauthn_register_verify()
                return
            if method == "GET" and path == "/api/webauthn/credentials":
                self._webauthn_list()
                return
            if method == "POST" and path == "/api/webauthn/credentials/delete":
                self._webauthn_delete()
                return
            if method == "POST" and path == "/api/webauthn/recovery-codes":
                self._webauthn_recovery_codes()
                return
            if method == "POST" and path == "/api/logout":
                self._logout()
                return
            if method == "GET" and path == "/api/me":
                self._me()
                return
            if method == "PUT" and path == "/api/vault":
                self._vault_put()
                return
            if method == "GET" and path == "/api/vault":
                self._vault_get()
                return
            if method == "GET" and path == "/api/vault/revisions":
                self._vault_revisions()
                return
            if method == "POST" and path == "/api/checkout":
                self._checkout()
                return
            if method == "POST" and path == "/api/stripe/webhook":
                self._webhook()
                return
            if method == "POST" and path == "/api/account/delete":
                self._account_delete()
                return
            if method == "GET" and path == "/api/account/export":
                self._account_export()
                return
            self._error(404, "not_found", "Unknown API route")

        def _register(self) -> None:
            if self.app.db.limited(self._rate_key("register")):
                self._error(429, "rate_limited", "Too many registration attempts. Try again in a minute.")
                return
            body = self._json_body()
            if body is None:
                return
            email = normalize_email(str(body.get("email") or ""))
            if not valid_email(email):
                self._error(400, "bad_email", "Enter a valid email address")
                return
            try:
                auth_key = decode_auth_key(str(body.get("auth_key") or ""))
                salt_b64 = str(body.get("kdf_salt") or "")
                decode_salt(salt_b64)
            except ValueError as exc:
                self._error(400, "bad_request", str(exc))
                return
            try:
                params = canonical_kdf_params(body.get("kdf_params"))
            except ValueError as exc:
                code = "weak_kdf" if "at least" in str(exc) else "bad_request"
                self._error(400, code, str(exc))
                return
            if self.app.db.get_account_by_email(email) is not None:
                self._error(409, "email_taken", "An account with that email already exists")
                return
            account = self.app.db.create_account(email, auth_key, salt_b64.strip(), params)
            token = self.app.db.create_session(account["id"], self.headers.get("User-Agent") or "")
            self.app.db.audit(account["id"], "register", self._client_ip())
            self._json(
                201,
                {"account": self._public(account)},
                extra=[("Set-Cookie", self._cookie(token))],
            )

        def _prelogin(self) -> None:
            if self.app.db.limited(self._rate_key("prelogin")):
                self._error(429, "rate_limited", "Too many attempts. Try again in a minute.")
                return
            body = self._json_body()
            if body is None:
                return
            email = normalize_email(str(body.get("email") or ""))
            if not valid_email(email):
                self._error(400, "bad_email", "Enter a valid email address")
                return
            self._json(200, self.app.db.prelogin(email))

        def _login(self) -> None:
            body = self._json_body()
            if body is None:
                return
            email = normalize_email(str(body.get("email") or ""))
            if not valid_email(email):
                self._error(400, "bad_email", "Enter a valid email address")
                return
            if not body.get("auth_key"):
                # Same handler can answer the salt lookup so clients that only
                # know POST /api/login still work.
                if self.app.db.limited(self._rate_key("prelogin")):
                    self._error(429, "rate_limited", "Too many attempts. Try again in a minute.")
                    return
                self._json(200, self.app.db.prelogin(email))
                return
            if self.app.db.limited(self._rate_key("login")):
                self._error(429, "rate_limited", "Too many sign-in attempts. Try again in a minute.")
                return
            # Per-account ceiling as well, so many IPs cannot share one target.
            # Keyed on the email whether or not the account exists, so the
            # limiter itself does not reveal which emails are registered.
            if self.app.db.limited(
                "login-account:" + hash_email(email, self.app.db.pepper),
                limit=LOGIN_ACCOUNT_LIMIT,
                window=LOGIN_ACCOUNT_WINDOW,
            ):
                self._error(429, "rate_limited", "Too many sign-in attempts for this account. Try again in a few minutes.")
                return
            try:
                auth_key = decode_auth_key(str(body.get("auth_key")))
            except ValueError as exc:
                self._error(400, "bad_request", str(exc))
                return
            account = self.app.db.verify_login(email, auth_key)
            if account is None:
                self._error(401, "invalid_credentials", "Email or master password is incorrect")
                return
            if self.app.mfa.enabled(account["id"]):
                # Correct authKey, but no session until the passkey step.
                self.app.db.audit(account["id"], "login_mfa_challenge", self._client_ip())
                self._json(200, self.app.mfa.login_options(account["id"]))
                return
            self._start_session(account["id"], "login")

        def _start_session(self, account_id: str, event: str) -> None:
            token = self.app.db.create_session(account_id, self.headers.get("User-Agent") or "")
            self.app.db.touch_login(account_id)
            self.app.db.audit(account_id, event, self._client_ip())
            account = self.app.db.get_account_by_id(account_id)
            self._json(
                200,
                {"account": self._public(account)},
                extra=[("Set-Cookie", self._cookie(token))],
            )

        def _public(self, account) -> Dict[str, Any]:
            pub = account_public(account)
            pub["mfa_enabled"] = self.app.mfa.enabled(account["id"])
            if pub["mfa_enabled"]:
                pub["recovery_codes_left"] = self.app.mfa.remaining_recovery_codes(account["id"])
            return pub

        def _mfa_limited(self) -> bool:
            if self.app.db.limited(self._rate_key("mfa"), limit=10, window=60):
                self._error(429, "rate_limited", "Too many sign-in attempts. Try again in a minute.")
                return True
            return False

        def _login_webauthn(self) -> None:
            if self._mfa_limited():
                return
            body = self._json_body()
            if body is None:
                return
            account_id = self.app.mfa.verify_login(str(body.get("ceremony") or ""), body.get("credential"))
            self._start_session(account_id, "login_passkey")

        def _login_recovery(self) -> None:
            if self._mfa_limited():
                return
            body = self._json_body()
            if body is None:
                return
            account_id = self.app.mfa.verify_recovery(str(body.get("ceremony") or ""), str(body.get("code") or ""))
            self._start_session(account_id, "login_recovery_code")

        def _reauth(self, account, body: dict) -> bool:
            """Destructive or factor-changing actions re-prove the master password."""
            # Own bucket, so managing passkeys does not use up sign-in attempts.
            if self.app.db.limited(self._rate_key("reauth"), limit=10, window=60):
                self._error(429, "rate_limited", "Too many attempts. Try again in a minute.")
                return False
            try:
                auth_key = decode_auth_key(str(body.get("auth_key") or ""))
            except ValueError:
                self._error(401, "reauth_required", "Re-enter your master password to continue")
                return False
            if not verify_auth_key(account["auth_verifier"], auth_key):
                self._error(401, "reauth_required", "Re-enter your master password to continue")
                return False
            return True

        def _webauthn_register_options(self) -> None:
            account, _token = self._require_account()
            if account is None:
                return
            if self._json_body() is None:
                return
            self._json(200, self.app.mfa.registration_options(account))

        def _webauthn_register_verify(self) -> None:
            account, _token = self._require_account()
            if account is None:
                return
            body = self._json_body()
            if body is None or not self._reauth(account, body):
                return
            result = self.app.mfa.register(
                account, str(body.get("ceremony") or ""), body.get("credential"), str(body.get("name") or "")
            )
            self.app.db.audit(account["id"], "passkey_added", self._client_ip())
            self._json(201, result)

        def _webauthn_list(self) -> None:
            account, _token = self._require_account()
            if account is None:
                return
            self._json(
                200,
                {
                    "credentials": self.app.mfa.public_credentials(account["id"]),
                    "recovery_codes_left": self.app.mfa.remaining_recovery_codes(account["id"]),
                },
            )

        def _webauthn_delete(self) -> None:
            account, _token = self._require_account()
            if account is None:
                return
            body = self._json_body()
            if body is None or not self._reauth(account, body):
                return
            if not self.app.mfa.delete_credential(account["id"], str(body.get("id") or "")):
                self._error(404, "not_found", "No such passkey on this account")
                return
            self.app.db.audit(account["id"], "passkey_removed", self._client_ip())
            self._json(200, {"ok": True, "mfa_enabled": self.app.mfa.enabled(account["id"])})

        def _webauthn_recovery_codes(self) -> None:
            account, _token = self._require_account()
            if account is None:
                return
            body = self._json_body()
            if body is None or not self._reauth(account, body):
                return
            if not self.app.mfa.enabled(account["id"]):
                self._error(400, "mfa_not_enabled", "Add a passkey before generating recovery codes")
                return
            self.app.db.audit(account["id"], "recovery_codes_regenerated", self._client_ip())
            self._json(200, {"recovery_codes": self.app.mfa.new_recovery_codes(account["id"])})

        def _logout(self) -> None:
            account, token = self._current_account()
            if token:
                self.app.db.revoke_session_token(token)
            if account is not None:
                self.app.db.audit(account["id"], "logout", self._client_ip())
            self._json(200, {"ok": True}, extra=[("Set-Cookie", self._cookie("", delete=True))])

        def _me(self) -> None:
            account, _token = self._require_account()
            if account is None:
                return
            self._json(200, {"account": self._public(account)})

        def _vault_put(self) -> None:
            account, _token = self._require_account()
            if account is None:
                return
            if not is_pro(account):
                self._error(
                    403,
                    "pro_required",
                    "Encrypted cloud sync is a Pro feature. The local vault still works on this device.",
                )
                return
            raw = self._read_body()
            if raw is None:
                return
            envelope = parse_envelope(raw)
            size = envelope_byte_size(envelope)
            if size > PRO_VAULT_MAX_BYTES:
                self._error(413, "vault_too_large", f"Vault exceeds the {PRO_VAULT_MAX_BYTES} byte Pro limit")
                return
            if not is_pro(account) and size > FREE_VAULT_MAX_BYTES:
                self._error(413, "vault_too_large", "Vault exceeds the Free size limit")
                return
            ct, nonce, version = envelope_parts(envelope)
            try:
                self.app.db.put_vault(account["id"], ct, nonce, version, size, pro=True)
            except ValueError as exc:
                if str(exc) == "vault_too_large":
                    self._error(413, "vault_too_large", "Vault exceeds the stored size limit")
                    return
                raise
            self.app.db.audit(account["id"], "vault_put", self._client_ip())
            stored = self.app.db.get_vault(account["id"])
            self._json(
                200,
                {
                    "ok": True,
                    "byte_size": stored["byte_size"] if stored else size,
                    "updated_at": stored["updated_at"] if stored else None,
                },
            )

        def _vault_get(self) -> None:
            account, _token = self._require_account()
            if account is None:
                return
            row = self.app.db.get_vault(account["id"])
            if row is None:
                self._error(404, "no_vault", "No cloud vault has been stored for this account")
                return
            pub = account_public(account)
            self._json(200, {"envelope": blob_to_envelope(row, pub["kdf_salt"], pub["kdf_params"])})

        def _vault_revisions(self) -> None:
            account, _token = self._require_account()
            if account is None:
                return
            if not is_pro(account):
                self._error(403, "pro_required", "Versioned cloud backups are a Pro feature")
                return
            pub = account_public(account)
            rows = self.app.db.list_revisions(account["id"])
            items = [blob_to_envelope(row, pub["kdf_salt"], pub["kdf_params"]) for row in rows]
            self._json(200, {"revisions": items})

        def _checkout(self) -> None:
            account, _token = self._require_account()
            if account is None:
                return
            if not stripe_configured(self.app.cfg):
                self._json(503, not_configured_body())
                return
            body = self._json_body()
            if body is None:
                return
            interval = str(body.get("interval") or body.get("price") or "monthly")
            result = create_checkout_session(self.app.cfg, account, interval)
            self._json(200, result)

        def _webhook(self) -> None:
            raw = self._read_body(WEBHOOK_BODY_MAX_BYTES)
            if raw is None:
                return
            if not self.app.cfg.stripe_webhook_secret:
                self._json(503, not_configured_body())
                return
            header = self.headers.get("Stripe-Signature") or ""
            if not verify_stripe_signature(raw, header, self.app.cfg.stripe_webhook_secret):
                self._error(400, "invalid_signature", "Stripe-Signature HMAC did not verify")
                return
            event = event_from_payload(raw)
            result = apply_webhook_event(self.app.db, event)
            self._json(200, result)

        def _account_delete(self) -> None:
            account, token = self._require_account()
            if account is None:
                return
            body = self._json_body()
            if body is None:
                return
            confirm = str(body.get("confirm") or "")
            if confirm.upper() not in {"DELETE", "YES", "DELETE MY ACCOUNT"}:
                self._error(400, "confirm_required", "Send confirm=DELETE to permanently delete this account")
                return
            # Deleting wipes every revision, so a session cookie alone is not
            # enough: the caller must prove they still hold the master password.
            if not self._reauth(account, body):
                return
            account_id = account["id"]
            self.app.db.audit(account_id, "delete_account", self._client_ip())
            self.app.mfa.delete_all(account_id)
            self.app.db.delete_account(account_id)
            extra = [("Set-Cookie", self._cookie(token or "", delete=True))] if token else None
            self._json(200, {"ok": True, "deleted": True}, extra=extra)

        def _account_export(self) -> None:
            account, _token = self._require_account()
            if account is None:
                return
            pub = account_public(account)
            row = self.app.db.get_vault(account["id"])
            envelope = blob_to_envelope(row, pub["kdf_salt"], pub["kdf_params"]) if row else None
            self.app.db.audit(account["id"], "export", self._client_ip())
            self._json(
                200,
                {
                    "exported_at": isoformat(),
                    "account": {
                        "id": pub["id"],
                        "email": pub["email"],
                        "plan": pub["plan"],
                        "plan_status": pub["plan_status"],
                        "created_at": pub["created_at"],
                    },
                    "vault": envelope,
                    "note": "The vault field is ciphertext. Decrypt it client-side with your master password.",
                },
            )

        def _static(self, path: str) -> None:
            if path == "/":
                path = "/index.html"
            rel = path.lstrip("/")
            if ".." in Path(rel).parts or path.startswith("/."):
                self._error(404, "not_found", "Not found")
                return
            target = (self.app.web_root / rel).resolve()
            try:
                target.relative_to(self.app.web_root)
            except ValueError:
                self._error(404, "not_found", "Not found")
                return
            if target.is_dir():
                target = target / "index.html"
            if not target.is_file():
                self._error(404, "not_found", "Not found")
                return
            data = target.read_bytes()
            mime, _enc = mimetypes.guess_type(str(target))
            content_type = mime or "application/octet-stream"
            if target.suffix == ".js":
                content_type = "text/javascript; charset=utf-8"
            elif target.suffix == ".css":
                content_type = "text/css; charset=utf-8"
            elif target.suffix in {".html", ".svg"}:
                content_type = f"{'text/html' if target.suffix == '.html' else 'image/svg+xml'}; charset=utf-8"
            extra = None
            if target.suffix in {".css", ".js", ".svg"}:
                extra = [("Cache-Control", "public, max-age=300")]
            self._send(200, data, content_type, extra=extra, csp=STATIC_CSP)

    return Handler


def make_server(cfg: Optional[Config] = None, db: Optional[Database] = None) -> Tuple[ThreadingHTTPServer, App]:
    app = App(cfg=cfg, db=db)
    handler = make_handler(app)
    httpd = ThreadingHTTPServer((app.cfg.host, app.cfg.port), handler)
    httpd.daemon_threads = True
    return httpd, app


def serve_in_thread(cfg: Optional[Config] = None, db: Optional[Database] = None) -> Tuple[ThreadingHTTPServer, App, threading.Thread]:
    httpd, app = make_server(cfg=cfg, db=db)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    return httpd, app, thread


def main() -> None:
    cfg = load_config()
    httpd, app = make_server(cfg)
    host, port = httpd.server_address[:2]
    print(f"pwmanager SaaS {__version__}  http://{host}:{port}")
    print(f"database: {app.cfg.db_path}")
    print(f"static:   {app.web_root}")
    if stripe_configured(app.cfg):
        print("stripe:   configured")
    else:
        print("stripe:   not configured (POST /api/checkout returns 503)")
    print("TLS is assumed in production. Do not expose this process on the public internet without HTTPS.")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nshutting down")
        httpd.shutdown()


if __name__ == "__main__":
    main()
