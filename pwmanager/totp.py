"""RFC 6238 TOTP helpers, progress bar, and otpauth URI display."""

from __future__ import annotations

import base64
import hashlib
import hmac
import sys
import time
from typing import Callable, Optional, TextIO
from urllib.parse import quote


def totp_at(secret_b32: str, timestamp: float, digits: int = 6, period: int = 30) -> str:
    """Generate a TOTP code for a specific Unix timestamp."""
    try:
        key = base64.b32decode(secret_b32.upper().replace(" ", ""), casefold=True)
    except Exception as e:
        raise ValueError(f"Invalid TOTP secret: {e}") from e
    counter = int(timestamp // period)
    msg = counter.to_bytes(8, "big")
    h = hmac.new(key, msg, hashlib.sha1).digest()
    offset = h[-1] & 0x0F
    code = (
        (h[offset] & 0x7F) << 24
        | (h[offset + 1] & 0xFF) << 16
        | (h[offset + 2] & 0xFF) << 8
        | (h[offset + 3] & 0xFF)
    )
    return str(code % (10**digits)).zfill(digits)


def totp_now(secret_b32: str, digits: int = 6, period: int = 30) -> str:
    """Generate the current TOTP code from a base32 secret."""
    return totp_at(secret_b32, time.time(), digits=digits, period=period)


def totp_seconds_remaining(period: int = 30, now: Optional[float] = None) -> int:
    """Seconds remaining in the current TOTP period.

    ``now`` may be injected for unit tests.
    """
    t = time.time() if now is None else now
    rem = period - int(t % period)
    # When t % period == 0, remaining is ``period`` (full window just started)
    return rem if rem > 0 else period


def format_totp_code_spaced(code: str) -> str:
    """Format a 6-digit code as '123 456' for readability."""
    code = code.strip()
    if len(code) == 6 and code.isdigit():
        return f"{code[:3]} {code[3:]}"
    return code


def progress_bar(remaining: int, period: int = 30, width: int = 20) -> str:
    """ASCII progress bar for time left in the TOTP window."""
    if period <= 0:
        period = 30
    remaining = max(0, min(period, remaining))
    filled = int(round((remaining / period) * width))
    filled = max(0, min(width, filled))
    return "[" + ("#" * filled) + ("-" * (width - filled)) + "]"


def format_totp_line(
    code: str,
    remaining: int,
    period: int = 30,
    width: int = 20,
) -> str:
    """One-line display: spaced code + seconds + progress bar."""
    spaced = format_totp_code_spaced(code)
    bar = progress_bar(remaining, period=period, width=width)
    return f"{spaced}  {remaining:2d}s  {bar}"


def totp_uri(
    secret: str,
    name: str,
    issuer: str = "pwmanager",
    digits: int = 6,
    period: int = 30,
) -> str:
    """Build an otpauth://totp URI suitable for authenticator QR apps.

    Format: otpauth://totp/Issuer:Name?secret=SECRET&issuer=Issuer&digits=6&period=30
    """
    secret_clean = secret.upper().replace(" ", "").strip()
    if not secret_clean:
        raise ValueError("TOTP secret is empty")
    label = f"{issuer}:{name}" if issuer else name
    # Path segment: encode but keep colon between issuer and account
    path = quote(label, safe=":")
    params = [
        f"secret={quote(secret_clean, safe='')}",
        f"digits={digits}",
        f"period={period}",
    ]
    if issuer:
        params.append(f"issuer={quote(issuer, safe='')}")
    return f"otpauth://totp/{path}?{'&'.join(params)}"


def format_otpauth_box(uri: str, title: str = "otpauth URI") -> str:
    """Pretty box around an otpauth URI for terminal display.

    Suggests external QR tools; optional ``qrcode`` package if installed.
    """
    lines = [
        f"┌─ {title} ",
        f"│ {uri}",
        "│",
        "│ Scan with an authenticator app, or:",
        "│   qrencode -t ANSIUTF8  '<uri>'   # if qrencode is installed",
        "│   python -c \"import qrcode; qrcode.make('<uri>').print_ascii()\"",
        "└─",
    ]
    # Fit top border
    inner = max(len(uri) + 2, 48)
    lines[0] = "┌─ " + title + " " + "─" * max(1, inner - len(title) - 2)
    lines[-1] = "└" + "─" * (len(lines[0]) - 1)
    return "\n".join(lines)


def try_print_qr(uri: str, out: Optional[TextIO] = None) -> bool:
    """If the optional ``qrcode`` package is installed, print ASCII QR.

    Returns True if printed, False if unavailable.
    """
    out = out or sys.stdout
    try:
        import qrcode  # type: ignore
    except ImportError:
        return False
    try:
        qr = qrcode.QRCode(border=1)
        qr.add_data(uri)
        qr.make(fit=True)
        qr.print_ascii(out=out, invert=True)
        return True
    except Exception:
        return False


def watch_totp(
    secret_b32: str,
    period: int = 30,
    digits: int = 6,
    iterations: Optional[int] = None,
    sleep_fn: Callable[[float], None] = time.sleep,
    now_fn: Callable[[], float] = time.time,
    write_fn: Optional[Callable[[str], None]] = None,
    stop_check: Optional[Callable[[], bool]] = None,
) -> None:
    """Live TOTP display that refreshes until Ctrl+C or iteration limit.

    Unit-testable via injected ``sleep_fn``, ``now_fn``, ``write_fn``,
    and ``iterations`` / ``stop_check``.
    """
    if write_fn is None:

        def write_fn(s: str) -> None:
            sys.stdout.write(s)
            sys.stdout.flush()

    count = 0
    try:
        while True:
            if stop_check is not None and stop_check():
                break
            if iterations is not None and count >= iterations:
                break
            t = now_fn()
            code = totp_at(secret_b32, t, digits=digits, period=period)
            rem = totp_seconds_remaining(period=period, now=t)
            line = format_totp_line(code, rem, period=period)
            write_fn(f"\r{line}  ")
            count += 1
            sleep_fn(1.0)
    except KeyboardInterrupt:
        write_fn("\n")
        return
    write_fn("\n")

