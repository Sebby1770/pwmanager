/**
 * Browser / Node WebCrypto helpers for the zero-knowledge vault.
 * Derives two keys from master password + email; the server never sees vaultKey.
 *
 * KDF v2 (default since 3.3): masterKey = Argon2id(password, SHA-256(salt || email))
 * then vaultKey / authKey = HKDF-SHA256(masterKey) with distinct info strings.
 * KDF v1 (legacy): PBKDF2-SHA256, 600k iterations, 64 bytes split in two. v1
 * vaults still open and are migrated to v2 on the next unlock.
 */

export const KDF_ITERATIONS = 600000;
export const KDF_V1 = "PBKDF2-HMAC-SHA256";
export const KDF_V2 = "argon2id";
export const ARGON2_DEFAULTS = Object.freeze({ m: 65536, t: 3, p: 4 });
// Floors stop a server (or a tampered local record) from weakening derivation;
// ceilings stop it from freezing the browser with an absurd work factor.
export const ARGON2_LIMITS = Object.freeze({ mMin: 65536, mMax: 262144, tMin: 3, tMax: 20, pMin: 1, pMax: 16 });
const HKDF_INFO_VAULT = "pwmanager/v2/vault-key";
const HKDF_INFO_AUTH = "pwmanager/v2/auth-key";
export const SALT_BYTES = 32;
export const AUTH_KEY_BYTES = 32;
export const VAULT_KEY_BYTES = 32;
export const NONCE_BYTES = 12;
export const AAD = "pwmanager-vault-v1";
export const MIN_MASTER_LENGTH = 12;

const FORBIDDEN_TOP = [
  "password",
  "passwords",
  "password_plain",
  "master_password",
  "masterPassword",
  "totp_secret",
  "totp",
  "entries",
  "username",
  "card_number",
  "cardNumber",
  "pan",
  "cvv",
  "cvc",
  "plaintext",
  "secret",
  "secrets",
  "notes",
  "history"
];

export function normalizeEmail(email) {
  return String(email || "").trim().toLowerCase();
}

export function legacyKdfParams() {
  return {
    alg: KDF_V1,
    hash: "SHA-256",
    iterations: KDF_ITERATIONS,
    dk_len: 64,
    salt_bytes: SALT_BYTES,
    email_mix: "sha256(salt||email)"
  };
}

export function defaultKdfParams() {
  return {
    alg: KDF_V2,
    version: 2,
    m: ARGON2_DEFAULTS.m,
    t: ARGON2_DEFAULTS.t,
    p: ARGON2_DEFAULTS.p,
    salt_bytes: SALT_BYTES,
    email_mix: "sha256(salt||email)",
    key_split: "hkdf-sha256"
  };
}

function boundedInt(value, lo, hi, label) {
  const n = typeof value === "string" && /^[0-9]+$/.test(value) ? Number(value) : value;
  if (!Number.isInteger(n) || n < lo || n > hi) {
    throw new Error(label + " must be an integer between " + lo + " and " + hi);
  }
  return n;
}

/**
 * Canonical KDF parameters, or an Error. Accepts only the two schemes this
 * client implements. v1 always runs at 600k iterations, exactly as before, so
 * a server cannot change an existing v1 account's derivation either way.
 */
export function normalizeKdfParams(params) {
  if (!params || typeof params !== "object") {
    throw new Error("kdf params must be an object");
  }
  const alg = String(params.alg || params.name || "").toLowerCase();
  if (alg === KDF_V2) {
    const out = defaultKdfParams();
    out.m = boundedInt(params.m, ARGON2_LIMITS.mMin, ARGON2_LIMITS.mMax, "argon2 memory (KiB)");
    out.t = boundedInt(params.t, ARGON2_LIMITS.tMin, ARGON2_LIMITS.tMax, "argon2 iterations");
    out.p = boundedInt(params.p, ARGON2_LIMITS.pMin, ARGON2_LIMITS.pMax, "argon2 parallelism");
    return out;
  }
  if (alg === "pbkdf2" || alg === KDF_V1.toLowerCase()) {
    if (params.iterations !== undefined && Number(params.iterations) < KDF_ITERATIONS) {
      throw new Error("kdf.iterations must be at least 600000");
    }
    return legacyKdfParams();
  }
  throw new Error("unsupported key derivation scheme");
}

/** 1 = PBKDF2 (legacy), 2 = Argon2id. Higher is stronger; never step down. */
export function kdfRank(params) {
  return normalizeKdfParams(params).alg === KDF_V2 ? 2 : 1;
}

export function sameKdf(a, b) {
  const x = normalizeKdfParams(a);
  const y = normalizeKdfParams(b);
  return x.alg === y.alg && x.m === y.m && x.t === y.t && x.p === y.p;
}

function argon2Module() {
  const hw = globalThis.hashwasm;
  if (!hw || typeof hw.argon2id !== "function") {
    throw new Error("The Argon2 module did not load. Reload the page.");
  }
  return hw;
}

export function bytesToB64(bytes) {
  const arr = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
  let bin = "";
  const chunk = 0x8000;
  for (let i = 0; i < arr.length; i += chunk) {
    bin += String.fromCharCode.apply(null, arr.subarray(i, i + chunk));
  }
  return btoa(bin);
}

export function b64ToBytes(value) {
  const raw = String(value || "").trim().replace(/-/g, "+").replace(/_/g, "/");
  const bin = atob(raw);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i += 1) {
    out[i] = bin.charCodeAt(i);
  }
  return out;
}

export function randomBytes(n) {
  if (!globalThis.crypto || !globalThis.crypto.getRandomValues) {
    throw new Error("No CSPRNG available (needs a secure context).");
  }
  const out = new Uint8Array(n);
  globalThis.crypto.getRandomValues(out);
  return out;
}

export function concatBytes(a, b) {
  const out = new Uint8Array(a.length + b.length);
  out.set(a, 0);
  out.set(b, a.length);
  return out;
}

export async function sha256(bytes) {
  const digest = await globalThis.crypto.subtle.digest("SHA-256", bytes);
  return new Uint8Array(digest);
}

export async function mixSalt(salt, email) {
  const enc = new TextEncoder();
  return sha256(concatBytes(salt, enc.encode(normalizeEmail(email))));
}

async function importVaultKey(bytes) {
  return globalThis.crypto.subtle.importKey("raw", bytes, { name: "AES-GCM" }, false, ["encrypt", "decrypt"]);
}

async function deriveV1(masterPassword, mixed) {
  const enc = new TextEncoder();
  const baseKey = await globalThis.crypto.subtle.importKey(
    "raw",
    enc.encode(masterPassword),
    "PBKDF2",
    false,
    ["deriveBits"]
  );
  const bits = await globalThis.crypto.subtle.deriveBits(
    { name: "PBKDF2", hash: "SHA-256", iterations: KDF_ITERATIONS, salt: mixed },
    baseKey,
    512
  );
  const material = new Uint8Array(bits);
  const vaultKeyBytes = material.slice(0, VAULT_KEY_BYTES);
  const authKeyBytes = material.slice(VAULT_KEY_BYTES, VAULT_KEY_BYTES + AUTH_KEY_BYTES);
  material.fill(0);
  return { vaultKeyBytes, authKeyBytes };
}

async function hkdf(masterKey, info) {
  const base = await globalThis.crypto.subtle.importKey("raw", masterKey, "HKDF", false, ["deriveBits"]);
  const bits = await globalThis.crypto.subtle.deriveBits(
    { name: "HKDF", hash: "SHA-256", salt: new Uint8Array(0), info: new TextEncoder().encode(info) },
    base,
    256
  );
  return new Uint8Array(bits);
}

async function deriveV2(masterPassword, mixed, p) {
  const masterKey = await argon2Module().argon2id({
    password: masterPassword,
    salt: mixed,
    parallelism: p.p,
    iterations: p.t,
    memorySize: p.m,
    hashLength: 32,
    outputType: "binary"
  });
  try {
    // One expensive derivation, two independent keys: unlike v1, an attacker
    // holding authKey gains no shortcut to vaultKey and pays the full Argon2
    // cost per password guess, same as the user does once.
    return {
      vaultKeyBytes: await hkdf(masterKey, HKDF_INFO_VAULT),
      authKeyBytes: await hkdf(masterKey, HKDF_INFO_AUTH)
    };
  } finally {
    masterKey.fill(0);
  }
}

export async function deriveKeys(masterPassword, email, salt, params) {
  if (!masterPassword || masterPassword.length < MIN_MASTER_LENGTH) {
    throw new Error("Master password must be at least 12 characters.");
  }
  if (!globalThis.crypto || !globalThis.crypto.subtle) {
    throw new Error("WebCrypto is unavailable. Use https:// or localhost.");
  }
  const kdfParams = normalizeKdfParams(params || defaultKdfParams());
  const saltBytes = salt instanceof Uint8Array ? salt : b64ToBytes(salt);
  if (saltBytes.length !== SALT_BYTES) {
    throw new Error("KDF salt must be 32 bytes.");
  }
  const mixed = await mixSalt(saltBytes, email);
  const material =
    kdfParams.alg === KDF_V2 ? await deriveV2(masterPassword, mixed, kdfParams) : await deriveV1(masterPassword, mixed);
  const vaultKey = await importVaultKey(material.vaultKeyBytes);
  material.vaultKeyBytes.fill(0);
  return {
    vaultKey,
    authKeyBytes: material.authKeyBytes,
    salt: saltBytes,
    saltB64: bytesToB64(saltBytes),
    kdfParams: kdfParams
  };
}

export function parseEnvelope(obj) {
  if (!obj || typeof obj !== "object") {
    throw new Error("envelope must be an object");
  }
  for (let i = 0; i < FORBIDDEN_TOP.length; i += 1) {
    if (Object.prototype.hasOwnProperty.call(obj, FORBIDDEN_TOP[i])) {
      throw new Error("envelope contains plaintext fields the server refuses to store");
    }
  }
  if (obj.v !== 1 && obj.v !== "1") {
    throw new Error("unsupported envelope version");
  }
  if (typeof obj.nonce !== "string" || typeof obj.ct !== "string") {
    throw new Error("nonce and ct must be base64 strings");
  }
  const nonce = b64ToBytes(obj.nonce);
  const ct = b64ToBytes(obj.ct);
  if (nonce.length !== NONCE_BYTES) {
    throw new Error("nonce must be 12 bytes");
  }
  if (ct.length < 16) {
    throw new Error("ciphertext is too short");
  }
  if (!obj.kdf || typeof obj.kdf !== "object") {
    throw new Error("kdf must be an object");
  }
  const kdfParams = normalizeKdfParams(obj.kdf);
  if (typeof obj.kdf.salt !== "string") {
    throw new Error("kdf.salt must be a base64 string");
  }
  const salt = b64ToBytes(obj.kdf.salt);
  if (salt.length !== SALT_BYTES) {
    throw new Error("kdf.salt must be 32 bytes");
  }
  return {
    v: 1,
    nonce: obj.nonce,
    ct: obj.ct,
    kdf: Object.assign({}, kdfParams, { salt: obj.kdf.salt }),
    kdfParams: kdfParams,
    updated_at: obj.updated_at,
    nonceBytes: nonce,
    ctBytes: ct,
    saltBytes: salt
  };
}

export async function encryptVault(vaultKey, data, saltB64, kdfParams) {
  if (!kdfParams) {
    // Required: the envelope records which scheme unlocks it, and guessing
    // wrong would lock the user out of a v1 vault.
    throw new Error("encryptVault needs the vault's KDF params");
  }
  const canonical = normalizeKdfParams(kdfParams);
  const nonce = randomBytes(NONCE_BYTES);
  const aad = new TextEncoder().encode(AAD);
  const plaintext = new TextEncoder().encode(JSON.stringify(data));
  const ct = new Uint8Array(
    await globalThis.crypto.subtle.encrypt(
      { name: "AES-GCM", iv: nonce, additionalData: aad, tagLength: 128 },
      vaultKey,
      plaintext
    )
  );
  return {
    v: 1,
    nonce: bytesToB64(nonce),
    ct: bytesToB64(ct),
    kdf: Object.assign({}, canonical, { salt: saltB64 }),
    updated_at: Date.now()
  };
}

export async function decryptVault(vaultKey, envelope) {
  const parsed = parseEnvelope(envelope);
  const aad = new TextEncoder().encode(AAD);
  const pt = await globalThis.crypto.subtle.decrypt(
    {
      name: "AES-GCM",
      iv: parsed.nonceBytes,
      additionalData: aad,
      tagLength: 128
    },
    vaultKey,
    parsed.ctBytes
  );
  return JSON.parse(new TextDecoder().decode(pt));
}

export function scoreMasterPassword(password, email) {
  const pw = String(password || "");
  let score = 0;
  if (pw.length >= 12) score += 1;
  if (pw.length >= 16) score += 1;
  if (/[a-z]/.test(pw) && /[A-Z]/.test(pw)) score += 1;
  if (/\d/.test(pw) && /[^A-Za-z0-9]/.test(pw)) score += 1;
  const local = normalizeEmail(email).split("@")[0] || "";
  if (local && pw.toLowerCase().includes(local)) {
    score = Math.max(0, score - 2);
  }
  const labels = ["Too short", "Weak", "Fair", "Strong", "Excellent"];
  return { score, label: labels[Math.max(0, Math.min(score, 4))], length: pw.length };
}

const LOWER = "abcdefghijklmnopqrstuvwxyz";
const UPPER = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
const DIGITS = "0123456789";
const SYMBOLS = "!@#$%^&*()-_=+[]{};:,.?/";

function randomInt(bound) {
  if (!Number.isInteger(bound) || bound <= 0) {
    throw new Error("invalid bound");
  }
  const maxUnbiased = Math.floor(256 / bound) * bound;
  const buf = new Uint8Array(1);
  while (true) {
    globalThis.crypto.getRandomValues(buf);
    if (buf[0] < maxUnbiased) {
      return buf[0] % bound;
    }
  }
}

export function generatePassphrase(wordCount, separator) {
  const list = globalThis.PW_WORDLIST;
  if (!Array.isArray(list) || list.length < 64) {
    throw new Error("Passphrase wordlist is not loaded.");
  }
  const count = wordCount || 5;
  if (count < 4 || count > 12) {
    throw new Error("Passphrase must use 4 to 12 words.");
  }
  const words = [];
  for (let i = 0; i < count; i += 1) {
    words.push(list[randomInt(list.length)]);
  }
  return words.join(separator == null ? "-" : separator);
}

export function generateSecret(length) {
  const len = length || 20;
  const alphabet = LOWER + UPPER + DIGITS + SYMBOLS;
  const required = [
    LOWER[randomInt(LOWER.length)],
    UPPER[randomInt(UPPER.length)],
    DIGITS[randomInt(DIGITS.length)],
    SYMBOLS[randomInt(SYMBOLS.length)]
  ];
  const chars = required.slice();
  for (let i = required.length; i < len; i += 1) {
    chars.push(alphabet[randomInt(alphabet.length)]);
  }
  for (let i = chars.length - 1; i > 0; i -= 1) {
    const j = randomInt(i + 1);
    const tmp = chars[i];
    chars[i] = chars[j];
    chars[j] = tmp;
  }
  return chars.join("");
}

export function estimateBits(secret) {
  const text = String(secret || "");
  if (!text) return 0;
  let pool = 0;
  if (/[a-z]/.test(text)) pool += 26;
  if (/[A-Z]/.test(text)) pool += 26;
  if (/\d/.test(text)) pool += 10;
  if (/[^A-Za-z0-9]/.test(text)) pool += 24;
  if (pool < 2) pool = 2;
  return text.length * Math.log2(pool);
}
