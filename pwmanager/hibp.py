"""Have I Been Pwned k-anonymity password breach check (optional network).

Only the first 5 hex characters of the SHA-1 hash are sent to the API.
The full password and full hash never leave the machine.
"""

from __future__ import annotations

import hashlib
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from typing import Dict, List, Optional, TYPE_CHECKING

if TYPE_CHECKING:
    from pwmanager.vault import Vault

HIBP_RANGE_URL = "https://api.pwnedpasswords.com/range/{prefix}"
DEFAULT_TIMEOUT = 5.0
USER_AGENT = "pwmanager-local-hibp-check/2.2"


@dataclass
class HibpResult:
    """Result of checking a single password (never stores the password)."""

    breached: bool
    count: int = 0  # times seen in breaches (0 if clean or skipped)
    skipped: bool = False
    skip_reason: str = ""


@dataclass
class HibpVaultReport:
    """Vault-level HIBP findings (entry names only)."""

    breached_names: List[str] = field(default_factory=list)
    clean_count: int = 0
    skipped: bool = False
    skip_reason: str = ""
    checked: int = 0  # passwords actually checked (non-empty, non-note-only)


def sha1_hex(password: str) -> str:
    """Return uppercase SHA-1 hex digest of the password."""
    return hashlib.sha1(password.encode("utf-8")).hexdigest().upper()


def check_password_hibp(
    password: str,
    timeout: float = DEFAULT_TIMEOUT,
    opener: Optional[object] = None,
) -> HibpResult:
    """Check one password via HIBP range API (k-anonymity).

    Sends only the first 5 hex chars of SHA-1(password). Compares the
    remaining hash suffix locally against the returned list.

    ``opener`` may be a callable(url, timeout) -> response body str, for tests.
    """
    if not password:
        return HibpResult(breached=False, count=0)

    digest = sha1_hex(password)
    prefix, suffix = digest[:5], digest[5:]

    try:
        if opener is not None:
            body = opener(HIBP_RANGE_URL.format(prefix=prefix), timeout)
        else:
            body = _fetch_range(prefix, timeout=timeout)
    except (urllib.error.URLError, TimeoutError, OSError) as e:
        return HibpResult(
            breached=False,
            skipped=True,
            skip_reason=f"network unavailable: {e.__class__.__name__}",
        )
    except Exception as e:  # pragma: no cover — defensive
        return HibpResult(
            breached=False,
            skipped=True,
            skip_reason=f"network unavailable: {e.__class__.__name__}",
        )

    # Response lines: SUFFIX:COUNT
    counts: Dict[str, int] = {}
    for line in body.splitlines():
        line = line.strip()
        if not line or ":" not in line:
            continue
        suf, _, cnt = line.partition(":")
        try:
            counts[suf.upper()] = int(cnt.strip())
        except ValueError:
            continue

    hit = counts.get(suffix, 0)
    return HibpResult(breached=hit > 0, count=hit)


def _fetch_range(prefix: str, timeout: float = DEFAULT_TIMEOUT) -> str:
    """HTTP GET range endpoint; returns response body as text."""
    url = HIBP_RANGE_URL.format(prefix=prefix.upper())
    req = urllib.request.Request(
        url,
        headers={
            "User-Agent": USER_AGENT,
            "Add-Padding": "true",
        },
        method="GET",
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.read().decode("utf-8", errors="replace")


def check_vault_hibp(
    vault: "Vault",
    timeout: float = DEFAULT_TIMEOUT,
    opener: Optional[object] = None,
) -> HibpVaultReport:
    """Check all login entries with passwords against HIBP.

    Reports entry **names** only. Never prints or returns passwords.
    If the network is unavailable on the first attempt, remaining checks
    are skipped with a clear reason.
    """
    report = HibpVaultReport()
    # Cache by password hash so reused passwords only hit the API once
    cache: Dict[str, HibpResult] = {}

    for name, entry in sorted(vault.entries.items()):
        # Skip note-only entries without passwords
        if getattr(entry, "kind", "login") == "note" and not entry.password:
            continue
        if not entry.password:
            continue

        report.checked += 1
        digest = sha1_hex(entry.password)
        if digest in cache:
            result = cache[digest]
        else:
            result = check_password_hibp(
                entry.password, timeout=timeout, opener=opener
            )
            cache[digest] = result

        if result.skipped:
            report.skipped = True
            report.skip_reason = result.skip_reason or "network unavailable"
            # Mark remaining as skipped too — offline
            return report

        if result.breached:
            report.breached_names.append(name)
        else:
            report.clean_count += 1

    report.breached_names.sort()
    return report
