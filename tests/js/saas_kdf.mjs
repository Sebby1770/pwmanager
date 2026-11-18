/**
 * Client-side KDF policy: v2 (Argon2id) by default, floors and ceilings
 * enforced no matter what a server or a stored record claims.
 *   node tests/js/saas_kdf.mjs
 */
import assert from "node:assert/strict";
import "./argon2_node.mjs";
import {
  ARGON2_LIMITS,
  bytesToB64,
  decryptVault,
  defaultKdfParams,
  deriveKeys,
  encryptVault,
  kdfRank,
  legacyKdfParams,
  normalizeKdfParams,
  parseEnvelope,
  sameKdf
} from "../../web/saas/crypto.js";

const email = "kdf@example.com";
const password = "a long enough master password";
const salt = new Uint8Array(32).fill(9);

assert.equal(defaultKdfParams().alg, "argon2id");
assert.equal(kdfRank(defaultKdfParams()), 2);
assert.equal(kdfRank(legacyKdfParams()), 1);
assert.equal(kdfRank({ alg: "PBKDF2" }), 1);

const v2 = defaultKdfParams();
for (const bad of [
  { ...v2, m: ARGON2_LIMITS.mMin - 1 },
  { ...v2, m: ARGON2_LIMITS.mMax + 1 },
  { ...v2, t: 2 },
  { ...v2, t: 21 },
  { ...v2, p: 0 },
  { ...v2, m: 65536.5 },
  { ...v2, m: "lots" },
  { alg: "scrypt" },
  { alg: "PBKDF2-HMAC-SHA256", iterations: 1000 },
  null
]) {
  assert.throws(() => normalizeKdfParams(bad), undefined, JSON.stringify(bad));
}
// Extra keys never survive normalisation.
assert.equal(normalizeKdfParams({ ...v2, evil: 1 }).evil, undefined);
assert.ok(sameKdf(v2, { ...v2, junk: true }));
assert.ok(!sameKdf(v2, { ...v2, m: 131072 }));

// v1 ignores any iteration count a server supplies: always 600k, as before 3.3.
const a = await deriveKeys(password, email, salt, legacyKdfParams());
const b = await deriveKeys(password, email, salt, { alg: "PBKDF2-HMAC-SHA256", iterations: 9_000_000 });
assert.equal(bytesToB64(a.authKeyBytes), bytesToB64(b.authKeyBytes));

// v1 and v2 produce unrelated keys; v2 auth and vault keys differ from each other.
const k2 = await deriveKeys(password, email, salt, v2);
assert.notEqual(bytesToB64(k2.authKeyBytes), bytesToB64(a.authKeyBytes));
assert.equal(k2.vaultKeyBytes, undefined, "raw vault key bytes are never exposed");

// Envelopes record their scheme; a v1 key cannot open a v2 envelope.
const env = await encryptVault(k2.vaultKey, { version: 1, entries: [] }, k2.saltB64, k2.kdfParams);
assert.equal(parseEnvelope(env).kdfParams.alg, "argon2id");
await assert.rejects(decryptVault(a.vaultKey, env));
assert.deepEqual(await decryptVault(k2.vaultKey, env), { version: 1, entries: [] });
await assert.rejects(encryptVault(k2.vaultKey, {}, k2.saltB64), /KDF params/);
assert.throws(() => parseEnvelope({ ...env, kdf: { ...env.kdf, m: 1024 } }));

if (process.argv[2] === "--print") {
  const [pw, em, saltB64, params] = process.argv.slice(3);
  const { b64ToBytes } = await import("../../web/saas/crypto.js");
  const keys = await deriveKeys(pw, em, b64ToBytes(saltB64), JSON.parse(params));
  console.log(bytesToB64(keys.authKeyBytes));
} else {
  console.log("saas kdf policy ok");
}
