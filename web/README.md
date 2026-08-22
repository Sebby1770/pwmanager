# pwmanager web generator

A static password and passphrase generator that runs entirely in the browser.
No build step, no dependencies, no server — five files that can be opened
straight from disk or served from any static host.

**Live:** https://sebby1770.github.io/pwmanager/

## Files

| File | What it is |
| --- | --- |
| `index.html` | The page. Declares the Content-Security-Policy. |
| `styles.css` | All styling. Light and dark, no external fonts. |
| `generator.js` | Pure generator logic. Shared with `tests/js/run.mjs`. |
| `app.js` | DOM wiring only. Never calls out except for the HIBP check. |
| `wordlist.js` | The EFF wordlist, generated from `pwmanager/data/eff_short.txt`. |

## Design rules

1. **Randomness is CSPRNG-only.** `crypto.getRandomValues` with rejection
   sampling — no `Math.random` fallback, and no modulo bias. If the browser has
   no CSPRNG the generator raises rather than emitting a weak password.
2. **Secrets never persist.** `localStorage` holds interface preferences under
   one key and nothing else. Nothing is written to the URL, and there is no
   analytics or telemetry of any kind.
3. **One outbound destination.** The CSP allows `connect-src
   https://api.pwnedpasswords.com` and nothing else, so the page cannot exfiltrate
   even if a script were somehow injected. That request only fires on a click,
   and carries five hex characters of a SHA-1 hash.
4. **Parity with the CLI.** Same symbol set, same lookalike set, same presets,
   same wordlist, same entropy thresholds. `tests/test_web_parity.py` fails if
   either side drifts.

## Running locally

```sh
python3 -m http.server 8137 --directory web
```

Then open http://localhost:8137. A `file://` open works too, though the
clipboard and SHA-1 hashing need a secure context (https or localhost).

## Tests

```sh
node tests/js/run.mjs          # generator core: bias, policy, entropy, HIBP parsing
python -m pytest tests/test_web_parity.py -q   # web <-> CLI parity
```

## Regenerating the wordlist

`web/wordlist.js` is generated. After editing `pwmanager/data/eff_short.txt`:

```sh
python3 scripts/build_web_wordlist.py
```

CI fails if the checked-in file does not match its source.
