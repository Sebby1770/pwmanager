# pwmanager web

Zero-knowledge vault UI, marketing pages, and the original static generator.
No npm build step — ES modules and a few classic scripts.

**Generator (unchanged logic):** `generator.html` + `styles.css` + `app.js` +
`generator.js` + `wordlist.js`. Randomness is `crypto.getRandomValues` with
rejection sampling. CSP on that page allows a single outbound host: the HIBP
range API.

**Product:** `index.html` (landing), `vault.html`, `pricing.html`, legal pages,
`saas.css`, and `saas/*.js`. Landing/vault CSP allows `'self'`, Stripe, and HIBP.

## Design rules

1. **Secrets stay in the tab.** The master password and `vaultKey` are never
   written to URLs, cookies, or the network. IndexedDB holds ciphertext.
2. **Two keys.** PBKDF2-HMAC-SHA256, 600,000 iterations, 32-byte salt mixed
   with the email. `vaultKey` encrypts; `authKey` authenticates.
3. **No inline script.** Pages declare a restrictive Content-Security-Policy.
4. **Generator parity.** `generator.js` / `wordlist.js` stay in lock-step with
   the CLI; `tests/test_web_parity.py` and `tests/js/run.mjs` enforce that.

## Running locally

Preferred (API + static):

```sh
python saas/server.py
```

Static only:

```sh
python3 -m http.server 8137 --directory web
```

## Tests

```sh
node tests/js/run.mjs                 # generator core
node tests/js/saas_crypto.mjs         # AES-GCM envelope roundtrip
python -m pytest tests/test_web_parity.py tests/test_saas_crypto_envelope.py -q
```

Regenerate `wordlist.js` after editing `pwmanager/data/eff_short.txt`:

```sh
python3 scripts/build_web_wordlist.py
```
