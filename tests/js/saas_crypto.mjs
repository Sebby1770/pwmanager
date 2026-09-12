/**
 * AES-GCM envelope roundtrip for the SaaS client crypto module.
 *   node tests/js/saas_crypto.mjs
 */
import {
  deriveKeys,
  encryptVault,
  decryptVault,
  parseEnvelope,
  randomBytes,
  SALT_BYTES,
  bytesToB64
} from "../../web/saas/crypto.js";

const email = "roundtrip@example.com";
const password = "correct horse battery example";
const salt = randomBytes(SALT_BYTES);
const keys = await deriveKeys(password, email, salt);
const vault = {
  version: 1,
  entries: [{ id: "1", name: "demo", password: "not-uploaded-in-plaintext", totp_secret: "MFRGGZDF" }]
};
const envelope = await encryptVault(keys.vaultKey, vault, keys.saltB64);
parseEnvelope(envelope);
if (envelope.password || envelope.entries) {
  throw new Error("plaintext leaked into envelope");
}
const opened = await decryptVault(keys.vaultKey, envelope);
if (opened.entries[0].password !== vault.entries[0].password) {
  throw new Error("roundtrip mismatch");
}
const other = await deriveKeys("definitely-wrong-password-value", email, salt);
let failed = false;
try {
  await decryptVault(other.vaultKey, envelope);
} catch (err) {
  failed = true;
}
if (!failed) {
  throw new Error("wrong password should not decrypt");
}
if (bytesToB64(salt) !== keys.saltB64) {
  throw new Error("salt encoding drifted");
}
console.log("saas crypto roundtrip ok");
