# Vendored third-party code

Everything here is loaded from this origin only: no CDN. `tests/test_vendor_integrity.py`
fails if a file changes without this table and the page's `integrity` attribute
being updated with it.

| File | Source | Version | License | sha256 of file |
|------|--------|---------|---------|----------------|
| `hash-wasm-argon2-4.13.0.umd.min.js` | npm `hash-wasm`, `dist/argon2.umd.min.js` | 4.13.0 | MIT (`hash-wasm.LICENSE`) | `acfe11b015852f593aaddc51116f71dc7850e4551e6b34d42c1f88cf39635f03` |

The npm tarball (`hash-wasm-4.13.0.tgz`) matched the registry's published
integrity `sha512-GrWl7wsV46fKIXQZB5ebskLZLAmKL6d9RS0fspCxDeQyjoNu1AfTJTMLPOJyfzaQm0ldFiwFN21/w+sE/kgEFQ==`
when it was vendored. The build contains the Argon2/Blake2b WebAssembly module
inline; it makes no network requests and uses no `eval`. Its output is checked
against Python's `argon2-cffi` (the reference C implementation) in
`tests/test_kdf_v2.py`.

To update: `npm pack hash-wasm@<version>`, compare the tarball's sha512 with
`npm view hash-wasm@<version> dist.integrity`, copy `dist/argon2.umd.min.js`, then
update this table, the `integrity` attribute in `web/vault.html`, and the pinned
hash in the test.
