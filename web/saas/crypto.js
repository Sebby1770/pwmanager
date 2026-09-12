/**
 * Browser / Node WebCrypto helpers for the zero-knowledge vault.
 * Derives two keys from master password + email; the server never sees vaultKey.
 */

export const KDF_ITERATIONS = 600000;
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

export function defaultKdfParams() {
  return {
    alg: "PBKDF2-HMAC-SHA256",
    hash: "SHA-256",
    iterations: KDF_ITERATIONS,
    dk_len: 64,
    salt_bytes: SALT_BYTES,
    email_mix: "sha256(salt||email)"
  };
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

export async function deriveKeys(masterPassword, email, salt) {
  if (!masterPassword || masterPassword.length < MIN_MASTER_LENGTH) {
    throw new Error("Master password must be at least 12 characters.");
  }
  if (!globalThis.crypto || !globalThis.crypto.subtle) {
    throw new Error("WebCrypto is unavailable. Use https:// or localhost.");
  }
  const saltBytes = salt instanceof Uint8Array ? salt : b64ToBytes(salt);
  if (saltBytes.length !== SALT_BYTES) {
    throw new Error("KDF salt must be 32 bytes.");
  }
  const enc = new TextEncoder();
  const baseKey = await globalThis.crypto.subtle.importKey(
    "raw",
    enc.encode(masterPassword),
    "PBKDF2",
    false,
    ["deriveBits"]
  );
  const mixed = await mixSalt(saltBytes, email);
  const bits = await globalThis.crypto.subtle.deriveBits(
    {
      name: "PBKDF2",
      hash: "SHA-256",
      iterations: KDF_ITERATIONS,
      salt: mixed
    },
    baseKey,
    512
  );
  const material = new Uint8Array(bits);
  const vaultKeyBytes = material.slice(0, VAULT_KEY_BYTES);
  const authKeyBytes = material.slice(VAULT_KEY_BYTES, VAULT_KEY_BYTES + AUTH_KEY_BYTES);
  const vaultKey = await globalThis.crypto.subtle.importKey(
    "raw",
    vaultKeyBytes,
    { name: "AES-GCM" },
    false,
    ["encrypt", "decrypt"]
  );
  return {
    vaultKey,
    vaultKeyBytes,
    authKeyBytes,
    salt: saltBytes,
    saltB64: bytesToB64(saltBytes),
    kdfParams: defaultKdfParams()
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
  const iterations = Number(obj.kdf.iterations);
  if (!Number.isFinite(iterations) || iterations < KDF_ITERATIONS) {
    throw new Error("kdf.iterations must be at least 600000");
  }
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
    kdf: obj.kdf,
    updated_at: obj.updated_at,
    nonceBytes: nonce,
    ctBytes: ct,
    saltBytes: salt
  };
}

export async function encryptVault(vaultKey, data, saltB64) {
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
    kdf: Object.assign({}, defaultKdfParams(), { salt: saltB64 }),
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
