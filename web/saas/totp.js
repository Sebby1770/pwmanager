/** RFC 6238 TOTP using WebCrypto HMAC-SHA1. Secrets never leave the device. */

function base32Decode(secret) {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  const cleaned = String(secret || "")
    .toUpperCase()
    .replace(/\s+/g, "")
    .replace(/=+$/g, "");
  if (!cleaned) {
    throw new Error("TOTP secret is empty");
  }
  let bits = "";
  for (let i = 0; i < cleaned.length; i += 1) {
    const idx = alphabet.indexOf(cleaned[i]);
    if (idx < 0) {
      throw new Error("Invalid TOTP secret");
    }
    bits += idx.toString(2).padStart(5, "0");
  }
  const bytes = [];
  for (let i = 0; i + 8 <= bits.length; i += 8) {
    bytes.push(parseInt(bits.slice(i, i + 8), 2));
  }
  return new Uint8Array(bytes);
}

export async function totpAt(secretB32, timestamp, digits, period) {
  const d = digits || 6;
  const p = period || 30;
  const keyBytes = base32Decode(secretB32);
  const counter = Math.floor(timestamp / p);
  const msg = new Uint8Array(8);
  let n = counter;
  for (let i = 7; i >= 0; i -= 1) {
    msg[i] = n & 0xff;
    n = Math.floor(n / 256);
  }
  const key = await crypto.subtle.importKey("raw", keyBytes, { name: "HMAC", hash: "SHA-1" }, false, [
    "sign"
  ]);
  const sig = new Uint8Array(await crypto.subtle.sign("HMAC", key, msg));
  const offset = sig[sig.length - 1] & 0x0f;
  const code =
    ((sig[offset] & 0x7f) << 24) |
    ((sig[offset + 1] & 0xff) << 16) |
    ((sig[offset + 2] & 0xff) << 8) |
    (sig[offset + 3] & 0xff);
  const mod = code % Math.pow(10, d);
  return String(mod).padStart(d, "0");
}

export function totpRemaining(period, now) {
  const p = period || 30;
  const t = now === undefined ? Date.now() / 1000 : now;
  const rem = p - (Math.floor(t) % p);
  return rem === 0 ? p : rem;
}

export function formatCode(code) {
  const text = String(code || "");
  if (text.length === 6) {
    return text.slice(0, 3) + " " + text.slice(3);
  }
  return text;
}
