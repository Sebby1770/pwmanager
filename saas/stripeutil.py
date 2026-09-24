"""Stripe Checkout + webhook helpers. Card numbers never touch this process."""

from __future__ import annotations

import hashlib
import hmac
import json
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Dict, Optional, Tuple

from saas.config import Config
from saas.db import Database, is_pro

STRIPE_API = "https://api.stripe.com/v1"
SIGN_TOLERANCE = 300

PAID_STATUSES = frozenset({"paid", "no_payment_required"})
PLAN_EVENTS = frozenset(
    {
        "checkout.session.completed",
        "checkout.session.async_payment_succeeded",
        "checkout.session.async_payment_failed",
        "customer.subscription.created",
        "customer.subscription.updated",
        "customer.subscription.deleted",
        "customer.subscription.canceled",
        "invoice.payment_failed",
    }
)


class StripeError(RuntimeError):
    def __init__(self, message: str, status: int = 502):
        super().__init__(message)
        self.status = status


def stripe_configured(cfg: Config) -> bool:
    return cfg.stripe_configured


def not_configured_body() -> Dict[str, str]:
    return {
        "error": "stripe_not_configured",
        "message": (
            "Checkout is unavailable until Stripe test (or live) keys are set. "
            "Export PWMANAGER_STRIPE_SECRET, PWMANAGER_STRIPE_WEBHOOK_SECRET, "
            "PWMANAGER_STRIPE_PRICE_MONTHLY, and PWMANAGER_STRIPE_PRICE_YEARLY. "
            "Use Stripe Checkout — pwmanager never collects card numbers."
        ),
    }


def parse_signature_header(header: str) -> Tuple[str, list]:
    timestamp = ""
    signatures = []
    for item in (header or "").split(","):
        key, _, value = item.strip().partition("=")
        if key == "t":
            timestamp = value
        elif key == "v1":
            signatures.append(value)
    return timestamp, signatures


def verify_stripe_signature(payload: bytes, header: str, secret: str, now: Optional[float] = None) -> bool:
    if not secret or not header or payload is None:
        return False
    timestamp, signatures = parse_signature_header(header)
    if not timestamp or not signatures:
        return False
    try:
        ts = int(timestamp)
    except ValueError:
        return False
    clock = time.time() if now is None else now
    if abs(clock - ts) > SIGN_TOLERANCE:
        return False
    signed = timestamp.encode("ascii") + b"." + payload
    expected = hmac.new(secret.encode("utf-8"), signed, hashlib.sha256).hexdigest()
    ok = False
    for item in signatures:
        ok = hmac.compare_digest(expected, item) or ok
    return ok


def stripe_request(cfg: Config, method: str, path: str, data: Optional[dict] = None) -> dict:
    if not cfg.stripe_secret:
        raise StripeError("Stripe secret key is not configured", status=503)
    url = STRIPE_API + path
    body = None
    headers = {"Authorization": "Bearer " + cfg.stripe_secret}
    if data is not None:
        body = urllib.parse.urlencode(_flatten(data)).encode("utf-8")
        headers["Content-Type"] = "application/x-www-form-urlencoded"
    req = urllib.request.Request(url, data=body, method=method.upper(), headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=20) as resp:
            raw = resp.read().decode("utf-8")
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="replace")
        raise StripeError(f"Stripe API {exc.code}: {detail[:300]}", status=502) from exc
    except urllib.error.URLError as exc:
        raise StripeError(f"Stripe unreachable: {exc.reason}", status=502) from exc
    try:
        return json.loads(raw)
    except json.JSONDecodeError as exc:
        raise StripeError("Stripe returned non-JSON") from exc


def _flatten(data: dict, prefix: str = "") -> Dict[str, str]:
    out: Dict[str, str] = {}
    for key, value in data.items():
        name = f"{prefix}[{key}]" if prefix else str(key)
        if isinstance(value, dict):
            out.update(_flatten(value, name))
        elif isinstance(value, (list, tuple)):
            for index, item in enumerate(value):
                if isinstance(item, dict):
                    out.update(_flatten(item, f"{name}[{index}]"))
                else:
                    out[f"{name}[{index}]"] = "" if item is None else str(item)
        elif value is None:
            continue
        elif isinstance(value, bool):
            out[name] = "true" if value else "false"
        else:
            out[name] = str(value)
    return out


def create_checkout_session(cfg: Config, account, interval: str) -> dict:
    if not stripe_configured(cfg):
        raise StripeError("stripe_not_configured", status=503)
    if interval not in {"month", "monthly", "year", "yearly"}:
        raise StripeError("interval must be monthly or yearly", status=400)
    yearly = interval in {"year", "yearly"}
    price_id = cfg.stripe_price_yearly if yearly else cfg.stripe_price_monthly
    success = cfg.public_url.rstrip("/") + "/vault.html?checkout=success"
    cancel = cfg.public_url.rstrip("/") + "/pricing.html?checkout=cancel"
    payload: Dict[str, Any] = {
        "mode": "subscription",
        "success_url": success,
        "cancel_url": cancel,
        "client_reference_id": account["id"],
        "line_items": [{"price": price_id, "quantity": 1}],
        "metadata": {"account_id": account["id"]},
        "subscription_data": {"metadata": {"account_id": account["id"]}},
    }
    if account["stripe_customer_id"]:
        payload["customer"] = account["stripe_customer_id"]
    else:
        payload["customer_email"] = account["email"]
    session = stripe_request(cfg, "POST", "/checkout/sessions", payload)
    url = session.get("url")
    if not url:
        raise StripeError("Stripe did not return a Checkout URL", status=502)
    return {"id": session.get("id"), "url": url}


def _period_end_iso(value: Any) -> Optional[str]:
    if value is None or value == "":
        return None
    try:
        ts = int(value)
    except (TypeError, ValueError):
        return None
    from datetime import datetime, timezone

    return datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def apply_webhook_event(db: Database, event: dict) -> Dict[str, Any]:
    """Apply a verified Stripe event. Stores the event id only, never PAN."""
    event_id = event.get("id") or ""
    event_type = event.get("type") or ""
    data = (event.get("data") or {}).get("object") or {}
    payload_type = data.get("object")
    account_id = None
    metadata = data.get("metadata") or {}
    if isinstance(metadata, dict):
        account_id = metadata.get("account_id")
    if not account_id:
        account_id = data.get("client_reference_id")
    customer = data.get("customer")
    account = None
    if account_id:
        account = db.get_account_by_id(str(account_id))
    if account is None and customer:
        account = db.get_account_by_stripe_customer(str(customer))
    resolved_id = account["id"] if account is not None else account_id

    inserted = db.record_payment_event(event_id, event_type, resolved_id, payload_type)
    if not inserted:
        return {"ok": True, "duplicate": True}

    if account is None:
        return {"ok": True, "ignored": True, "reason": "unknown_account"}

    if event_type not in PLAN_EVENTS:
        return {"ok": True, "ignored": True, "reason": "unhandled_type"}

    # Stripe does not deliver events in order and retries for days. Only an
    # event at least as new as the last one applied may change the plan, or a
    # late "active" update could undo a cancellation.
    created = _event_created(event)
    last = account["plan_event_at"]
    if created is not None and last is not None and created < int(last):
        return {"ok": True, "ignored": True, "reason": "stale_event"}

    customer_id = str(data.get("customer")) if data.get("customer") else None
    if event_type == "checkout.session.completed":
        # With async payment methods (BECS/SEPA debit) the session completes
        # before any money moves; payment_status is "unpaid" until the
        # async_payment_succeeded event arrives.
        if str(data.get("payment_status") or "") in PAID_STATUSES:
            db.set_plan(account["id"], "pro", status="active", stripe_customer_id=customer_id, event_at=created)
        elif customer_id:
            db.set_stripe_customer(account["id"], customer_id)
    elif event_type == "checkout.session.async_payment_succeeded":
        db.set_plan(account["id"], "pro", status="active", stripe_customer_id=customer_id, event_at=created)
    elif event_type == "checkout.session.async_payment_failed":
        if account["plan"] != "pro":
            db.set_plan(account["id"], "free", status="payment_failed", stripe_customer_id=customer_id, event_at=created)
    elif event_type in {"customer.subscription.created", "customer.subscription.updated"}:
        status = str(data.get("status") or "active")
        period_end = _period_end_iso(data.get("current_period_end"))
        plan = "pro" if status in {"active", "trialing", "past_due"} else "free"
        db.set_plan(
            account["id"],
            plan,
            status=status,
            period_end=period_end,
            stripe_customer_id=customer_id,
            event_at=created,
        )
    elif event_type in {"customer.subscription.deleted", "customer.subscription.canceled"}:
        db.set_plan(account["id"], "free", status="canceled", event_at=created)
    elif event_type == "invoice.payment_failed":
        db.set_plan(
            account["id"],
            "pro" if is_pro(account) else account["plan"],
            status="past_due",
            period_end=account["plan_period_end"],
            event_at=created,
        )

    return {"ok": True, "applied": event_type, "account_id": account["id"]}


def _event_created(event: dict) -> Optional[int]:
    value = event.get("created")
    if isinstance(value, bool):
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def event_from_payload(payload: bytes) -> dict:
    try:
        event = json.loads(payload.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise StripeError("webhook body is not JSON", status=400) from exc
    if not isinstance(event, dict) or not event.get("id") or not event.get("type"):
        raise StripeError("webhook event missing id or type", status=400)
    return event
