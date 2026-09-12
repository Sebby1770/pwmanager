/** IndexedDB ciphertext store and in-memory vault document helpers. */

const DB_NAME = "pwmanager.saas.v1";
const STORE = "envelopes";

function openDb() {
  return new Promise(function (resolve, reject) {
    const req = indexedDB.open(DB_NAME, 1);
    req.onupgradeneeded = function () {
      const db = req.result;
      if (!db.objectStoreNames.contains(STORE)) {
        db.createObjectStore(STORE, { keyPath: "email" });
      }
    };
    req.onsuccess = function () {
      resolve(req.result);
    };
    req.onerror = function () {
      reject(req.error || new Error("IndexedDB unavailable"));
    };
  });
}

export function emptyVault() {
  return { version: 1, entries: [] };
}

export function newId() {
  if (globalThis.crypto && globalThis.crypto.randomUUID) {
    return globalThis.crypto.randomUUID();
  }
  const bytes = new Uint8Array(16);
  globalThis.crypto.getRandomValues(bytes);
  bytes[6] = (bytes[6] & 0x0f) | 0x40;
  bytes[8] = (bytes[8] & 0x3f) | 0x80;
  const hex = [...bytes].map(function (b) {
    return b.toString(16).padStart(2, "0");
  }).join("");
  return (
    hex.slice(0, 8) +
    "-" +
    hex.slice(8, 12) +
    "-" +
    hex.slice(12, 16) +
    "-" +
    hex.slice(16, 20) +
    "-" +
    hex.slice(20)
  );
}

export function newEntry(partial) {
  const now = Date.now() / 1000;
  const base = {
    id: newId(),
    name: "",
    username: "",
    password: "",
    url: "",
    notes: "",
    tags: [],
    totp_secret: "",
    favorite: false,
    kind: "login",
    created_at: now,
    updated_at: now,
    last_accessed: 0,
    rotate_after_days: null,
    history: []
  };
  return Object.assign(base, partial || {});
}

export function sortEntries(entries) {
  return entries.slice().sort(function (a, b) {
    if (Boolean(a.favorite) !== Boolean(b.favorite)) {
      return a.favorite ? -1 : 1;
    }
    return String(a.name || "").localeCompare(String(b.name || ""), undefined, {
      sensitivity: "base"
    });
  });
}

export function filterEntries(entries, query, favoritesOnly) {
  const q = String(query || "").trim().toLowerCase();
  return entries.filter(function (entry) {
    if (favoritesOnly && !entry.favorite) {
      return false;
    }
    if (!q) {
      return true;
    }
    const tags = Array.isArray(entry.tags) ? entry.tags.join(" ") : "";
    const hay = [entry.name, entry.username, entry.url, tags, entry.kind]
      .join(" ")
      .toLowerCase();
    return hay.indexOf(q) !== -1;
  });
}

export async function idbGet(email) {
  const key = String(email || "").trim().toLowerCase();
  if (!key || !globalThis.indexedDB) {
    return null;
  }
  const db = await openDb();
  return new Promise(function (resolve, reject) {
    const tx = db.transaction(STORE, "readonly");
    const req = tx.objectStore(STORE).get(key);
    req.onsuccess = function () {
      resolve(req.result || null);
    };
    req.onerror = function () {
      reject(req.error);
    };
  });
}

export async function idbPut(email, envelope) {
  const key = String(email || "").trim().toLowerCase();
  if (!key) {
    throw new Error("email required");
  }
  if (!globalThis.indexedDB) {
    throw new Error("IndexedDB is unavailable in this browser.");
  }
  const db = await openDb();
  return new Promise(function (resolve, reject) {
    const tx = db.transaction(STORE, "readwrite");
    tx.objectStore(STORE).put({
      email: key,
      envelope: envelope,
      saved_at: Date.now()
    });
    tx.oncomplete = function () {
      resolve();
    };
    tx.onerror = function () {
      reject(tx.error);
    };
  });
}

export async function idbDelete(email) {
  const key = String(email || "").trim().toLowerCase();
  if (!key || !globalThis.indexedDB) {
    return;
  }
  const db = await openDb();
  return new Promise(function (resolve, reject) {
    const tx = db.transaction(STORE, "readwrite");
    tx.objectStore(STORE).delete(key);
    tx.oncomplete = function () {
      resolve();
    };
    tx.onerror = function () {
      reject(tx.error);
    };
  });
}

export function applyPasswordChange(entry, nextPassword) {
  const current = entry.password || "";
  if (current && current !== nextPassword) {
    const history = Array.isArray(entry.history) ? entry.history.slice() : [];
    history.unshift({ password: current, changed_at: Date.now() / 1000 });
    entry.history = history.slice(0, 10);
  }
  entry.password = nextPassword;
  entry.updated_at = Date.now() / 1000;
  return entry;
}
