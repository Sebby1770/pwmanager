"""Password / passphrase generation and strength estimation."""

from __future__ import annotations

import math
import secrets
import string
from functools import lru_cache
from importlib import resources
from pathlib import Path
from typing import Dict, List

from pwmanager.colors import C
from pwmanager.constants import SYMBOLS

# Compact fallback if package data is missing (should rarely be used).
_FALLBACK_WORDLIST = """\
abandon ability able about above absent absorb abstract absurd abuse access accident
account accuse achieve acid acoustic acquire across action actor actress actual adapt
add addict address adjust admit adult advance advice aerobic affair afford afraid again
age agent agree ahead aim air airport aisle alarm album alcohol alert alien all alley
allow almost alone alpha already also alter always amateur amazing among amount amused
analyst anchor ancient anger angle angry animal ankle announce annual another answer
antenna antique anxiety any apart apology appear apple approve april arch arctic area
arena argue arm armed armor army around arrange arrest arrive arrow art artist artwork
ask aspect assault asset assist assume asthma athlete atom attack attend attitude attract
auction audit august aunt author auto autumn average avocado avoid awake aware away
awesome awful awkward axis baby bachelor bacon badge bag balance balcony ball bamboo
banana banner bargain barrel basic basket battle beach bean beauty because become beef
before begin behave behind believe below belt bench benefit best betray better between
beyond bicycle bid bike bind biology bird birth bitter black blade blame blanket blast
bleak bless blind blood blossom blouse blue blur blush board boat body boil bomb bone
bonus book boost border boring borrow boss bottom bounce box boy bracket brain brand
brass brave bread breeze brick bridge brief bright bring brisk broccoli broken bronze
broom brother brown brush bubble buddy budget buffalo build bulb bulk bullet bundle
""".split()

# Named generator policies (length + character classes)
GENERATOR_PRESETS: Dict[str, Dict] = {
    "pin": {
        "length": 6,
        "use_upper": False,
        "use_digits": True,
        "use_symbols": False,
        "use_lower": False,
        "avoid_ambiguous": False,
        "digits_only": True,
    },
    "wifi": {
        # 16 chars, easy to type on devices, no ambiguous glyphs
        "length": 16,
        "use_upper": True,
        "use_digits": True,
        "use_symbols": False,
        "use_lower": True,
        "avoid_ambiguous": True,
        "digits_only": False,
    },
    "apple": {
        # Apple-style strong password length with mixed classes, no ambiguous
        "length": 20,
        "use_upper": True,
        "use_digits": True,
        "use_symbols": True,
        "use_lower": True,
        "avoid_ambiguous": True,
        "digits_only": False,
    },
    "max": {
        "length": 64,
        "use_upper": True,
        "use_digits": True,
        "use_symbols": True,
        "use_lower": True,
        "avoid_ambiguous": False,
        "digits_only": False,
    },
}


@lru_cache(maxsize=1)
def _load_wordlist() -> List[str]:
    """Load passphrase wordlist from package data (1000+ words)."""
    # 1) importlib.resources (installed package)
    try:
        ref = resources.files("pwmanager").joinpath("data/eff_short.txt")
        text = ref.read_text(encoding="utf-8")
        words = [w.strip().lower() for w in text.splitlines() if w.strip() and not w.startswith("#")]
        if len(words) >= 100:
            return words
    except (FileNotFoundError, OSError, TypeError, AttributeError, ModuleNotFoundError):
        pass

    # 2) adjacent file next to this module (editable / source tree)
    try:
        path = Path(__file__).resolve().parent / "data" / "eff_short.txt"
        if path.is_file():
            text = path.read_text(encoding="utf-8")
            words = [
                w.strip().lower()
                for w in text.splitlines()
                if w.strip() and not w.startswith("#")
            ]
            if len(words) >= 100:
                return words
    except OSError:
        pass

    return list(_FALLBACK_WORDLIST)


def get_wordlist() -> List[str]:
    """Return the active passphrase wordlist (copy not needed; treat as read-only)."""
    return _load_wordlist()


def generate_password(
    length: int = 16,
    use_upper: bool = True,
    use_digits: bool = True,
    use_symbols: bool = True,
    avoid_ambiguous: bool = False,
    use_lower: bool = True,
    digits_only: bool = False,
) -> str:
    if length < 4:
        raise ValueError("Length must be at least 4.")

    if digits_only:
        return "".join(secrets.choice(string.digits) for _ in range(length))

    lower = string.ascii_lowercase
    upper = string.ascii_uppercase
    digits = string.digits
    syms = SYMBOLS

    if avoid_ambiguous:
        ambiguous = set("Il1O0o`'\"|")
        lower = "".join(c for c in lower if c not in ambiguous)
        upper = "".join(c for c in upper if c not in ambiguous)
        digits = "".join(c for c in digits if c not in ambiguous)
        syms = "".join(c for c in syms if c not in ambiguous)

    pools: List[str] = []
    required: List[str] = []
    if use_lower:
        pools.append(lower)
        required.append(secrets.choice(lower))
    if use_upper:
        pools.append(upper)
        required.append(secrets.choice(upper))
    if use_digits:
        pools.append(digits)
        required.append(secrets.choice(digits))
    if use_symbols:
        pools.append(syms)
        required.append(secrets.choice(syms))

    if not pools:
        raise ValueError("At least one character class must be enabled.")

    if length < len(required):
        raise ValueError(f"Length must be at least {len(required)} for selected classes.")

    all_chars = "".join(pools)
    chars = required + [secrets.choice(all_chars) for _ in range(length - len(required))]
    # Fisher-Yates with secrets
    for i in range(len(chars) - 1, 0, -1):
        j = secrets.randbelow(i + 1)
        chars[i], chars[j] = chars[j], chars[i]
    return "".join(chars)


def generate_from_preset(preset: str) -> str:
    """Generate a password using a named policy (pin, wifi, apple, max)."""
    key = (preset or "").strip().lower()
    if key not in GENERATOR_PRESETS:
        raise ValueError(
            f"Unknown preset '{preset}'. Choose: {', '.join(sorted(GENERATOR_PRESETS))}."
        )
    opts = GENERATOR_PRESETS[key]
    return generate_password(
        length=int(opts["length"]),
        use_upper=bool(opts.get("use_upper", True)),
        use_digits=bool(opts.get("use_digits", True)),
        use_symbols=bool(opts.get("use_symbols", True)),
        avoid_ambiguous=bool(opts.get("avoid_ambiguous", False)),
        use_lower=bool(opts.get("use_lower", True)),
        digits_only=bool(opts.get("digits_only", False)),
    )


def generate_passphrase(words: int = 5, separator: str = "-", capitalize: bool = False) -> str:
    if words < 3:
        raise ValueError("Use at least 3 words.")
    wordlist = get_wordlist()
    chosen = [secrets.choice(wordlist) for _ in range(words)]
    if capitalize:
        chosen = [w.capitalize() for w in chosen]
    return separator.join(chosen)


def password_entropy_bits(password: str) -> float:
    """Estimate Shannon entropy of a password based on the character pool used."""
    if not password:
        return 0.0
    pool = 0
    if any(c.islower() for c in password):
        pool += 26
    if any(c.isupper() for c in password):
        pool += 26
    if any(c.isdigit() for c in password):
        pool += 10
    if any(c in SYMBOLS for c in password):
        pool += len(SYMBOLS)
    if any(c not in string.ascii_letters + string.digits + SYMBOLS for c in password):
        pool += 32  # rough other-chars allowance
    if pool == 0:
        return 0.0
    return len(password) * math.log2(pool)


def strength_label(bits: float) -> str:
    if bits < 28:
        return C.red("Very weak")
    if bits < 50:
        return C.yellow("Weak")
    if bits < 70:
        return C.yellow("Reasonable")
    if bits < 90:
        return C.green("Strong")
    return C.green(C.bold("Very strong"))
