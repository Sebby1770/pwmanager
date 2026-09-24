import * as api from "./api.js";
import { auditVault } from "./audit.js";
import * as crypto from "./crypto.js";
import { totpAt, totpRemaining, formatCode } from "./totp.js";
import * as ui from "./ui.js";
import * as vault from "./vault.js";
import * as passkey from "./webauthn.js";

const IDLE_MS = 5 * 60 * 1000;
const CLIP_MS = 20000;
const REVEAL_MS = 15000;
const TOTP_TICK_MS = 1000;

const state = {
  email: "",
  vaultKey: null,
  authKeyB64: "",
  saltB64: "",
  kdfParams: null,
  data: null,
  account: null,
  selectedId: null,
  dirty: false,
  idleTimer: null,
  idleClockTimer: null,
  idleUntil: 0,
  totpTimer: null,
  revealTimer: null,
  clipTimer: null,
  clipValue: "",
  revealed: false,
  health: null
};

const el = {};

function bind() {
  [
    "view-lock",
    "view-app",
    "tab-unlock",
    "tab-create",
    "panel-unlock",
    "panel-create",
    "unlock-email",
    "unlock-password",
    "unlock-form",
    "create-email",
    "create-password",
    "create-password2",
    "create-age",
    "create-warning",
    "create-cloud",
    "create-form",
    "create-meter",
    "create-meter-label",
    "lock-status",
    "search",
    "filter-fav",
    "btn-add",
    "idle-clock",
    "btn-lock",
    "btn-export",
    "btn-kit",
    "btn-import",
    "import-file",
    "btn-sync",
    "btn-audit",
    "btn-account",
    "btn-help",
    "entry-list",
    "pane-empty",
    "pane-detail",
    "entry-form",
    "entry-id",
    "entry-kind",
    "entry-name",
    "entry-username",
    "entry-password",
    "entry-url",
    "entry-notes",
    "entry-tags",
    "entry-totp",
    "entry-favorite",
    "entry-generate",
    "entry-passphrase",
    "entry-reveal",
    "entry-copy-password",
    "entry-copy-username",
    "entry-copy-totp",
    "entry-delete",
    "entry-save",
    "entry-cancel",
    "totp-display",
    "totp-bar",
    "totp-wrap",
    "audit-panel",
    "account-dialog",
    "account-body",
    "plan-badge",
    "sync-status",
    "btn-checkout-month",
    "btn-checkout-year",
    "btn-delete-account",
    "btn-logout",
    "btn-hibp",
    "hibp-result",
    "account-close",
    "help-dialog",
    "help-close",
    "passkey-section",
    "passkey-list",
    "btn-passkey-add",
    "btn-recovery-regen",
    "recovery-box",
    "recovery-codes",
    "passkey-status"
  ].forEach(function (id) {
    el[id] = document.getElementById(id);
  });
}

function setLockStatus(message, kind) {
  if (!el["lock-status"]) return;
  el["lock-status"].textContent = message || "";
  el["lock-status"].dataset.kind = kind || "";
}

function showLock() {
  el["view-lock"].hidden = false;
  el["view-app"].hidden = true;
  stopTimers();
}

function showApp() {
  el["view-lock"].hidden = true;
  el["view-app"].hidden = false;
  bumpIdle();
}

function stopTimers() {
  window.clearTimeout(state.idleTimer);
  window.clearInterval(state.idleClockTimer);
  window.clearInterval(state.totpTimer);
  window.clearTimeout(state.revealTimer);
  window.clearTimeout(state.clipTimer);
}

function flushClipboard() {
  // stopTimers() cancels the pending auto-clear, so a lock inside the 20 s
  // window used to leave the secret on the clipboard indefinitely.
  const pending = state.clipValue;
  state.clipValue = "";
  window.clearTimeout(state.clipTimer);
  if (pending) {
    ui.clearClipboardIfUnchanged(pending).catch(function () {});
  }
}

function wipeDecryptedDom() {
  // Hidden is not gone: every decrypted value written into the DOM stays
  // readable (devtools, extensions, a later XSS) until it is overwritten.
  if (el["entry-form"]) el["entry-form"].reset();
  ["entry-id", "entry-name", "entry-username", "entry-password", "entry-url", "entry-notes", "entry-tags", "entry-totp", "search"].forEach(
    function (id) {
      if (el[id]) el[id].value = "";
    }
  );
  if (el["entry-list"]) el["entry-list"].textContent = "";
  if (el["audit-panel"]) {
    el["audit-panel"].replaceChildren();
    el["audit-panel"].hidden = true;
  }
  if (el["hibp-result"]) el["hibp-result"].textContent = "";
  if (el["totp-display"]) el["totp-display"].textContent = "";
  hideRecoveryCodes();
  if (el["passkey-list"]) el["passkey-list"].textContent = "";
  if (el["totp-wrap"]) el["totp-wrap"].hidden = true;
  if (el["pane-detail"]) el["pane-detail"].hidden = true;
  if (el["pane-empty"]) el["pane-empty"].hidden = false;
  if (el["view-app"]) el["view-app"].dataset.ready = "false";
}

function lockVault(reason) {
  flushClipboard();
  state.vaultKey = null;
  state.authKeyB64 = "";
  state.data = null;
  state.selectedId = null;
  state.revealed = false;
  wipeDecryptedDom();
  if (el["unlock-password"]) el["unlock-password"].value = "";
  if (el["create-password"]) el["create-password"].value = "";
  if (el["create-password2"]) el["create-password2"].value = "";
  showLock();
  if (reason) setLockStatus(reason, "warn");
}

function formatIdle(ms) {
  const total = Math.max(0, Math.ceil(ms / 1000));
  const minutes = Math.floor(total / 60);
  const seconds = String(total % 60).padStart(2, "0");
  return minutes + ":" + seconds;
}

function tickIdleClock() {
  if (!el["idle-clock"]) return;
  if (!state.vaultKey || !state.idleUntil) {
    el["idle-clock"].textContent = "Locked";
    return;
  }
  const left = state.idleUntil - Date.now();
  el["idle-clock"].textContent = left <= 0 ? "Locking…" : "Idle lock " + formatIdle(left);
}

function bumpIdle() {
  window.clearTimeout(state.idleTimer);
  state.idleUntil = Date.now() + IDLE_MS;
  tickIdleClock();
  state.idleTimer = window.setTimeout(function () {
    lockVault("Locked after 5 minutes idle.");
  }, IDLE_MS);
}

function setMode(mode) {
  const create = mode === "create";
  el["tab-unlock"].setAttribute("aria-selected", create ? "false" : "true");
  el["tab-create"].setAttribute("aria-selected", create ? "true" : "false");
  el["panel-unlock"].hidden = create;
  el["panel-create"].hidden = !create;
}

async function persist() {
  if (!state.vaultKey || !state.data || !state.email) return;
  // Inside the ciphertext, so the server cannot forge or reorder it.
  state.data.saved_at = Date.now();
  const envelope = await crypto.encryptVault(state.vaultKey, state.data, state.saltB64);
  await vault.idbPut(state.email, envelope);
  state.dirty = false;
  if (state.account && state.account.pro) {
    try {
      await api.putVault(envelope);
      el["sync-status"].textContent = "Cloud copy updated";
    } catch (err) {
      el["sync-status"].textContent = err.message || "Cloud sync failed";
    }
  }
  return envelope;
}

function renderList() {
  const favOnly = el["filter-fav"].getAttribute("aria-pressed") === "true";
  const items = vault.filterEntries(state.data.entries, el.search.value, favOnly);
  const sorted = vault.sortEntries(items);
  el["entry-list"].textContent = "";
  if (!sorted.length) {
    const empty = document.createElement("li");
    empty.className = "entry-empty";
    empty.textContent = state.data.entries.length ? "No matches." : "No entries yet.";
    el["entry-list"].appendChild(empty);
    return;
  }
  sorted.forEach(function (entry) {
    const li = document.createElement("li");
    const btn = document.createElement("button");
    btn.type = "button";
    btn.className = "entry-row" + (entry.id === state.selectedId ? " is-active" : "");
    btn.setAttribute("aria-current", entry.id === state.selectedId ? "true" : "false");
    const title = document.createElement("span");
    title.className = "entry-title";
    title.textContent = entry.name || "(unnamed)";
    const meta = document.createElement("span");
    meta.className = "entry-meta";
    meta.textContent = entry.kind === "note" ? "Note" : entry.username || entry.url || "Login";
    btn.appendChild(title);
    btn.appendChild(meta);
    if (entry.favorite) {
      const star = document.createElement("span");
      star.className = "entry-star";
      star.textContent = "Pinned";
      btn.appendChild(star);
    }
    btn.addEventListener("click", function () {
      openEntry(entry.id);
    });
    li.appendChild(btn);
    el["entry-list"].appendChild(li);
  });
}

function hidePasswordSoon() {
  window.clearTimeout(state.revealTimer);
  state.revealTimer = window.setTimeout(function () {
    state.revealed = false;
    applyReveal();
  }, REVEAL_MS);
}

function applyReveal() {
  el["entry-password"].type = state.revealed ? "text" : "password";
  el["entry-reveal"].textContent = state.revealed ? "Hide" : "Reveal";
  el["entry-reveal"].setAttribute("aria-pressed", state.revealed ? "true" : "false");
  if (state.revealed) hidePasswordSoon();
}

function formToEntry() {
  const id = el["entry-id"].value;
  const existing = state.data.entries.find(function (item) {
    return item.id === id;
  });
  const entry = existing ? Object.assign({}, existing) : vault.newEntry({ id: id });
  entry.kind = el["entry-kind"].value === "note" ? "note" : "login";
  entry.name = el["entry-name"].value.trim();
  entry.username = el["entry-username"].value.trim();
  entry.url = el["entry-url"].value.trim();
  entry.notes = el["entry-notes"].value;
  entry.tags = el["entry-tags"].value
    .split(",")
    .map(function (t) {
      return t.trim();
    })
    .filter(Boolean);
  entry.totp_secret = el["entry-totp"].value.replace(/\s+/g, "").toUpperCase();
  entry.favorite = el["entry-favorite"].checked;
  vault.applyPasswordChange(entry, el["entry-password"].value);
  return entry;
}

function fillForm(entry) {
  el["entry-id"].value = entry.id;
  el["entry-kind"].value = entry.kind === "note" ? "note" : "login";
  el["entry-name"].value = entry.name || "";
  el["entry-username"].value = entry.username || "";
  el["entry-password"].value = entry.password || "";
  el["entry-url"].value = entry.url || "";
  el["entry-notes"].value = entry.notes || "";
  el["entry-tags"].value = Array.isArray(entry.tags) ? entry.tags.join(", ") : "";
  el["entry-totp"].value = entry.totp_secret || "";
  el["entry-favorite"].checked = Boolean(entry.favorite);
  state.revealed = false;
  applyReveal();
  toggleKind();
  tickTotp();
}

function toggleKind() {
  const note = el["entry-kind"].value === "note";
  document.querySelectorAll("[data-login-only]").forEach(function (node) {
    node.hidden = note;
  });
}

function openEntry(id) {
  const entry = state.data.entries.find(function (item) {
    return item.id === id;
  });
  if (!entry) return;
  entry.last_accessed = Date.now() / 1000;
  state.selectedId = id;
  el["pane-empty"].hidden = true;
  el["pane-detail"].hidden = false;
  fillForm(entry);
  renderList();
}

function openNew() {
  const entry = vault.newEntry({ name: "" });
  state.data.entries.push(entry);
  state.selectedId = entry.id;
  el["pane-empty"].hidden = true;
  el["pane-detail"].hidden = false;
  fillForm(entry);
  renderList();
  el["entry-name"].focus();
}

async function saveEntry(event) {
  event.preventDefault();
  const next = formToEntry();
  if (!next.name) {
    ui.toast("Name this entry before saving.", "warn");
    el["entry-name"].focus();
    return;
  }
  const idx = state.data.entries.findIndex(function (item) {
    return item.id === next.id;
  });
  if (idx === -1) state.data.entries.push(next);
  else state.data.entries[idx] = next;
  await persist();
  ui.toast("Saved on this device.");
  renderList();
  renderAudit(false);
}

async function deleteEntry() {
  const id = el["entry-id"].value;
  if (!id) return;
  if (!window.confirm("Delete this entry from the vault? This cannot be undone.")) return;
  state.data.entries = state.data.entries.filter(function (item) {
    return item.id !== id;
  });
  state.selectedId = null;
  el["pane-detail"].hidden = true;
  el["pane-empty"].hidden = false;
  await persist();
  renderList();
  ui.toast("Entry deleted.");
}

async function copyField(value, label) {
  if (!value) {
    ui.toast("Nothing to copy.", "warn");
    return;
  }
  await ui.copyText(value);
  ui.toast(label + " copied — clipboard clears in 20 seconds (or when the vault locks).");
  window.clearTimeout(state.clipTimer);
  state.clipValue = value;
  state.clipTimer = window.setTimeout(function () {
    state.clipValue = "";
    ui.clearClipboardIfUnchanged(value).then(function () {
      ui.toast("Clipboard cleared.");
    });
  }, CLIP_MS);
}

async function tickTotp() {
  const secret = el["entry-totp"].value.trim();
  if (!secret) {
    el["totp-wrap"].hidden = true;
    return;
  }
  el["totp-wrap"].hidden = false;
  try {
    const now = Date.now() / 1000;
    const code = await totpAt(secret, now);
    const rem = totpRemaining(30, now);
    el["totp-display"].textContent = formatCode(code);
    el["totp-bar"].style.width = (rem / 30) * 100 + "%";
  } catch (err) {
    el["totp-display"].textContent = "Invalid secret";
  }
}

function renderAudit(show) {
  const report = auditVault(state.data.entries);
  const panel = el["audit-panel"];
  if (!show && panel.hidden) return;
  panel.hidden = !show ? panel.hidden : false;
  if (panel.hidden) return;
  const lines = [];
  lines.push(report.issueCount ? report.issueCount + " issues in " + report.total + " entries." : "No issues found.");
  if (report.weak.length) lines.push("Weak: " + report.weak.join(", "));
  if (report.reused.length) {
    report.reused.forEach(function (group) {
      lines.push("Reused: " + group.join(", "));
    });
  }
  if (report.old.length) lines.push("Due for rotation: " + report.old.join(", "));
  if (report.emptyUser.length) lines.push("Empty username: " + report.emptyUser.join(", "));
  if (report.missingTotp.length) lines.push("URL without TOTP: " + report.missingTotp.join(", "));
  panel.replaceChildren();
  const h = document.createElement("h2");
  h.textContent = "Audit";
  panel.appendChild(h);
  lines.forEach(function (line) {
    const p = document.createElement("p");
    p.textContent = line;
    panel.appendChild(p);
  });
}

function renderAccount() {
  const account = state.account;
  const badge = el["plan-badge"];
  if (!account) {
    badge.textContent = "Local";
    el["account-body"].textContent =
      "This vault lives in this browser. Create a cloud account from the lock screen to enable Pro sync.";
    return;
  }
  badge.textContent = account.pro ? "Pro" : "Free";
  el["account-body"].textContent =
    account.email +
    " · plan " +
    account.plan +
    (account.plan_status ? " (" + account.plan_status + ")" : "") +
    ". Cloud sync stores ciphertext only.";
  renderPasskeys();
}

/* ---------------------------------------------------------------- passkeys */

function setPasskeyStatus(message, kind) {
  if (!el["passkey-status"]) return;
  el["passkey-status"].textContent = message || "";
  el["passkey-status"].dataset.kind = kind || "";
}

function hideRecoveryCodes() {
  if (el["recovery-codes"]) el["recovery-codes"].textContent = "";
  if (el["recovery-box"]) el["recovery-box"].hidden = true;
}

function showRecoveryCodes(codes) {
  el["recovery-codes"].textContent = codes.join("\n");
  el["recovery-box"].hidden = false;
}

async function renderPasskeys() {
  const section = el["passkey-section"];
  if (!section) return;
  section.hidden = !state.account;
  if (!state.account) return;
  el["btn-passkey-add"].disabled = !passkey.supported();
  if (!passkey.supported()) setPasskeyStatus("This browser does not support passkeys.", "warn");
  let listing;
  try {
    listing = await api.passkeys();
  } catch (err) {
    setPasskeyStatus(err.message || "Could not load passkeys.", "error");
    return;
  }
  const list = el["passkey-list"];
  list.textContent = "";
  listing.credentials.forEach(function (cred) {
    const li = document.createElement("li");
    const label = document.createElement("span");
    label.textContent = cred.name + (cred.last_used_at ? " · last used " + ui.formatWhen(Date.parse(cred.last_used_at)) : "");
    const remove = document.createElement("button");
    remove.type = "button";
    remove.className = "btn btn-ghost";
    remove.textContent = "Remove";
    remove.addEventListener("click", function () {
      removePasskey(cred);
    });
    li.appendChild(label);
    li.appendChild(remove);
    list.appendChild(li);
  });
  const on = listing.credentials.length > 0;
  el["btn-recovery-regen"].hidden = !on;
  if (on) {
    setPasskeyStatus(listing.recovery_codes_left + " recovery codes left.", listing.recovery_codes_left < 3 ? "warn" : "");
  } else if (passkey.supported()) {
    setPasskeyStatus("No passkeys yet: the master password alone signs in to the cloud.", "");
  }
}

async function addPasskey() {
  hideRecoveryCodes();
  try {
    const opts = await api.passkeyOptions();
    const credential = await passkey.createPasskey(opts.publicKey);
    const name = (navigator.platform || "Passkey").slice(0, 40);
    const result = await api.passkeyRegister(opts.ceremony, credential, name, state.authKeyB64);
    if (result.recovery_codes) showRecoveryCodes(result.recovery_codes);
    ui.toast("Passkey added. Cloud sign-in now needs it.");
    state.account.mfa_enabled = true;
  } catch (err) {
    setPasskeyStatus(err.name === "NotAllowedError" ? "Passkey creation was cancelled." : err.message || "Could not add passkey.", "error");
    return;
  }
  await renderPasskeys();
}

async function removePasskey(cred) {
  if (!window.confirm("Remove passkey \u201c" + cred.name + "\u201d? If it is the last one, the master password alone will sign in again.")) {
    return;
  }
  try {
    const result = await api.deletePasskey(cred.id, state.authKeyB64);
    state.account.mfa_enabled = result.mfa_enabled;
    if (!result.mfa_enabled) hideRecoveryCodes();
    ui.toast("Passkey removed.");
  } catch (err) {
    setPasskeyStatus(err.message || "Could not remove passkey.", "error");
  }
  await renderPasskeys();
}

async function regenerateRecovery() {
  if (!window.confirm("Replace all recovery codes? The old ones stop working immediately.")) return;
  try {
    const result = await api.regenerateRecoveryCodes(state.authKeyB64);
    showRecoveryCodes(result.recovery_codes);
  } catch (err) {
    setPasskeyStatus(err.message || "Could not create recovery codes.", "error");
  }
  await renderPasskeys();
}

/**
 * Second sign-in step. Returns the account, or null to continue local-only.
 * Never blocks unlocking the local vault: that needs only the master password.
 */
async function completeSecondFactor(challenge) {
  try {
    if (!passkey.supported()) throw new Error("no passkeys in this browser");
    const assertion = await passkey.getPasskey(challenge.publicKey);
    const session = await api.loginWebauthn(challenge.ceremony, assertion);
    return session.account;
  } catch (err) {
    const code = window.prompt(
      "Cloud sign-in needs your passkey. Enter a recovery code instead, or cancel to keep working on this device only."
    );
    if (!code) return null;
    try {
      // The passkey attempt consumed the ceremony; ask for a fresh one.
      const again = await api.login(state.email, state.authKeyB64);
      if (!again.mfa_required) return again.account;
      const session = await api.loginRecovery(again.ceremony, code);
      ui.toast("Signed in with a recovery code. " + session.account.recovery_codes_left + " left.", "warn");
      return session.account;
    } catch (inner) {
      ui.toast(inner.message || "Recovery code rejected.", "error");
      return null;
    }
  }
}

async function afterUnlock() {
  el["view-app"].dataset.ready = "false";
  showApp();
  renderList();
  renderAccount();
  el["pane-detail"].hidden = true;
  el["pane-empty"].hidden = false;
  window.clearInterval(state.totpTimer);
  state.totpTimer = window.setInterval(tickTotp, TOTP_TICK_MS);
  window.clearInterval(state.idleClockTimer);
  state.idleClockTimer = window.setInterval(tickIdleClock, 1000);
  bumpIdle();
  if (state.account && state.account.pro) {
    try {
      const remote = await api.getVault();
      if (remote.envelope) {
        const decrypted = await crypto.decryptVault(state.vaultKey, remote.envelope);
        // Compare the timestamps sealed inside each ciphertext. The envelope's
        // own updated_at is server-supplied (and was an ISO string, so the old
        // Number() comparison was always NaN → 0 and the cloud copy never won).
        if (vault.pickNewer(state.data, decrypted) === "remote") {
          state.data = decrypted;
          await vault.idbPut(state.email, remote.envelope);
          el["sync-status"].textContent = "Loaded cloud copy";
          renderList();
        } else if (vault.savedAt(state.data) > vault.savedAt(decrypted)) {
          // The cloud copy is older than this device's (or was rolled back):
          // keep local and push it so the cloud catches up.
          await persist();
        }
      }
    } catch (err) {
      if (err.status !== 404) {
        el["sync-status"].textContent = "Cloud vault unavailable";
      }
    }
  }
  // Lets tests (and anything else) know the initial cloud pull has settled.
  el["view-app"].dataset.ready = "true";
}

function setBusy(busy) {
  const forms = [el["unlock-form"], el["create-form"]];
  forms.forEach(function (form) {
    if (!form) return;
    form.querySelectorAll("button[type='submit']").forEach(function (btn) {
      btn.disabled = busy;
    });
  });
}

function typingTarget(target) {
  return target instanceof Element && target.closest("input, textarea, select, [contenteditable='true']");
}

function openDialog(node) {
  if (!node) return;
  if (typeof node.showModal === "function") node.showModal();
  else node.hidden = false;
}

function closeDialog(node) {
  if (!node) return;
  if (typeof node.close === "function" && node.open) node.close();
  else node.hidden = true;
}

async function unlock(event) {
  event.preventDefault();
  const email = crypto.normalizeEmail(el["unlock-email"].value);
  const password = el["unlock-password"].value;
  setBusy(true);
  setLockStatus("Deriving keys… this can take a second on a slow device.");
  try {
    let record = await vault.idbGet(email);
    let saltB64 = record && record.envelope && record.envelope.kdf ? record.envelope.kdf.salt : "";
    if (!saltB64) {
      try {
        const pre = await api.prelogin(email);
        saltB64 = pre.kdf_salt;
        state.kdfParams = pre.kdf_params;
      } catch (err) {
        setLockStatus("No local vault for that email, and the API is unreachable.", "error");
        return;
      }
    }
    const keys = await crypto.deriveKeys(password, email, saltB64);
    let data = vault.emptyVault();
    if (record && record.envelope) {
      try {
        data = await crypto.decryptVault(keys.vaultKey, record.envelope);
      } catch (err) {
        setLockStatus("Could not decrypt the local vault. Check the master password.", "error");
        return;
      }
    }
    state.email = email;
    state.vaultKey = keys.vaultKey;
    state.authKeyB64 = crypto.bytesToB64(keys.authKeyBytes);
    state.saltB64 = keys.saltB64;
    state.kdfParams = keys.kdfParams;
    state.data = data;
    state.account = null;
    try {
      const session = await api.login(email, state.authKeyB64);
      state.account = session.mfa_required ? await completeSecondFactor(session) : session.account;
    } catch (err) {
      /* local-only is fine */
    }
    el["unlock-password"].value = "";
    setLockStatus("");
    await afterUnlock();
  } catch (err) {
    setLockStatus(err.message || "Unlock failed.", "error");
  } finally {
    setBusy(false);
  }
}

async function createVault(event) {
  event.preventDefault();
  const email = crypto.normalizeEmail(el["create-email"].value);
  const password = el["create-password"].value;
  const confirm = el["create-password2"].value;
  if (!email) {
    setLockStatus("Enter an email address to bind this vault.", "error");
    return;
  }
  if (password.length < crypto.MIN_MASTER_LENGTH) {
    setLockStatus("Master password must be at least 12 characters.", "error");
    return;
  }
  if (password !== confirm) {
    setLockStatus("Master passwords do not match.", "error");
    return;
  }
  if (!el["create-age"].checked) {
    setLockStatus("You must be 16 or older.", "error");
    return;
  }
  if (!el["create-warning"].checked) {
    setLockStatus("Please confirm that a forgotten master password cannot be recovered.", "error");
    return;
  }
  setBusy(true);
  setLockStatus("Deriving keys… this can take a second on a slow device.");
  try {
    const salt = crypto.randomBytes(crypto.SALT_BYTES);
    const keys = await crypto.deriveKeys(password, email, salt);
    state.email = email;
    state.vaultKey = keys.vaultKey;
    state.authKeyB64 = crypto.bytesToB64(keys.authKeyBytes);
    state.saltB64 = keys.saltB64;
    state.kdfParams = keys.kdfParams;
    state.data = vault.emptyVault();
    state.account = null;
    await persist();
    if (el["create-cloud"].checked) {
      try {
        const created = await api.register(email, state.authKeyB64, state.saltB64, state.kdfParams);
        state.account = created.account;
      } catch (err) {
        if (err.status === 409) {
          try {
            const session = await api.login(email, state.authKeyB64);
            state.account = session.mfa_required ? await completeSecondFactor(session) : session.account;
          } catch (loginErr) {
            setLockStatus(
              "Local vault created, but that email already has a cloud account with a different master password.",
              "warn"
            );
          }
        } else {
          setLockStatus("Local vault created. Cloud account skipped: " + err.message, "warn");
        }
      }
    }
    el["create-password"].value = "";
    el["create-password2"].value = "";
    await afterUnlock();
    ui.toast("Vault created. If you forget the master password, the contents are gone.");
  } catch (err) {
    setLockStatus(err.message || "Could not create the vault.", "error");
  } finally {
    setBusy(false);
  }
}

function updateMeter() {
  const result = crypto.scoreMasterPassword(el["create-password"].value, el["create-email"].value);
  el["create-meter"].style.width = (result.score / 4) * 100 + "%";
  el["create-meter"].dataset.level = String(result.score);
  el["create-meter-label"].textContent = result.label;
}

async function exportBackup() {
  const envelope = await persist();
  const blob = new Blob([JSON.stringify(envelope, null, 2)], { type: "application/json" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = "pwmanager-vault-backup.json";
  a.click();
  URL.revokeObjectURL(url);
  ui.toast("Encrypted backup downloaded. Keep the master password somewhere safe.");
}

async function exportRecoveryKit() {
  const envelope = await persist();
  const kit = {
    kind: "pwmanager-recovery-kit",
    warning:
      "This file is ciphertext only. The master password is not inside it. If you lose the password, nobody can recover the vault.",
    downloaded_at: new Date().toISOString(),
    email: state.email,
    envelope: envelope
  };
  const blob = new Blob([JSON.stringify(kit, null, 2)], { type: "application/json" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = "pwmanager-recovery-kit.json";
  a.click();
  URL.revokeObjectURL(url);
  ui.toast("Recovery kit downloaded. Store it offline, separately from the master password.");
}

async function importBackup(file) {
  const text = await file.text();
  let envelope;
  try {
    const parsed = JSON.parse(text);
    envelope = parsed && parsed.kind === "pwmanager-recovery-kit" ? parsed.envelope : parsed;
    crypto.parseEnvelope(envelope);
  } catch (err) {
    ui.toast("That file is not a pwmanager envelope.", "error");
    return;
  }
  try {
    const data = await crypto.decryptVault(state.vaultKey, envelope);
    state.data = data;
    await vault.idbPut(state.email, envelope);
    renderList();
    ui.toast("Imported encrypted backup.");
  } catch (err) {
    ui.toast("Could not decrypt that backup with the current master password.", "error");
  }
}

async function startCheckout(interval) {
  try {
    const result = await api.checkout(interval);
    if (result.url) {
      window.location.href = result.url;
      return;
    }
  } catch (err) {
    ui.toast(err.message || "Checkout unavailable.", "warn");
  }
}

async function hibpCheck() {
  const password = el["entry-password"].value;
  if (!password) {
    el["hibp-result"].textContent = "Reveal or enter a password first.";
    return;
  }
  el["hibp-result"].textContent = "Checking…";
  try {
    const digestBuf = await globalThis.crypto.subtle.digest("SHA-1", new TextEncoder().encode(password));
    const hex = [...new Uint8Array(digestBuf)]
      .map(function (b) {
        return b.toString(16).padStart(2, "0");
      })
      .join("")
      .toUpperCase();
    const prefix = hex.slice(0, 5);
    const suffix = hex.slice(5);
    const response = await fetch("https://api.pwnedpasswords.com/range/" + prefix, {
      headers: { "Add-Padding": "true" },
      referrerPolicy: "no-referrer"
    });
    if (!response.ok) throw new Error("HIBP " + response.status);
    const body = await response.text();
    let count = 0;
    body.split(/\r?\n/).forEach(function (line) {
      const parts = line.split(":");
      if (parts[0] && parts[0].toUpperCase() === suffix) {
        count = parseInt(parts[1], 10) || 1;
      }
    });
    el["hibp-result"].textContent =
      count > 0
        ? "Seen in known breaches " + count.toLocaleString() + " times. Change it."
        : "Not found in the HIBP range. That is not proof it is strong.";
  } catch (err) {
    el["hibp-result"].textContent = "Could not check: " + (err.message || "network");
  }
}

function wire() {
  el["tab-unlock"].addEventListener("click", function () {
    setMode("unlock");
  });
  el["tab-create"].addEventListener("click", function () {
    setMode("create");
  });
  el["unlock-form"].addEventListener("submit", unlock);
  el["create-form"].addEventListener("submit", createVault);
  el["create-password"].addEventListener("input", updateMeter);
  el["create-email"].addEventListener("input", updateMeter);
  el.search.addEventListener("input", renderList);
  el["filter-fav"].addEventListener("click", function () {
    const pressed = el["filter-fav"].getAttribute("aria-pressed") === "true";
    el["filter-fav"].setAttribute("aria-pressed", pressed ? "false" : "true");
    renderList();
  });
  el["btn-add"].addEventListener("click", openNew);
  el["btn-lock"].addEventListener("click", function () {
    lockVault("Vault locked.");
  });
  el["btn-export"].addEventListener("click", exportBackup);
  el["btn-kit"].addEventListener("click", exportRecoveryKit);
  el["btn-import"].addEventListener("click", function () {
    el["import-file"].click();
  });
  el["import-file"].addEventListener("change", function () {
    const file = el["import-file"].files && el["import-file"].files[0];
    if (file) importBackup(file);
    el["import-file"].value = "";
  });
  el["btn-sync"].addEventListener("click", persist);
  el["btn-audit"].addEventListener("click", function () {
    el["audit-panel"].hidden = !el["audit-panel"].hidden;
    renderAudit(true);
  });
  el["btn-account"].addEventListener("click", function () {
    if (typeof el["account-dialog"].showModal === "function") {
      el["account-dialog"].showModal();
    } else {
      el["account-dialog"].hidden = !el["account-dialog"].hidden;
    }
  });
  el["entry-form"].addEventListener("submit", saveEntry);
  el["entry-kind"].addEventListener("change", toggleKind);
  el["entry-generate"].addEventListener("click", function () {
    el["entry-password"].value = crypto.generateSecret(20);
    state.revealed = true;
    applyReveal();
  });
  el["entry-passphrase"].addEventListener("click", function () {
    try {
      el["entry-password"].value = crypto.generatePassphrase(5, "-");
      state.revealed = true;
      applyReveal();
    } catch (err) {
      ui.toast(err.message || "Could not generate a passphrase.", "error");
    }
  });
  el["entry-reveal"].addEventListener("click", function () {
    state.revealed = !state.revealed;
    applyReveal();
  });
  el["entry-copy-password"].addEventListener("click", function () {
    copyField(el["entry-password"].value, "Password");
  });
  el["entry-copy-username"].addEventListener("click", function () {
    copyField(el["entry-username"].value, "Username");
  });
  el["entry-copy-totp"].addEventListener("click", async function () {
    const secret = el["entry-totp"].value.trim();
    if (!secret) return;
    const code = await totpAt(secret, Date.now() / 1000);
    copyField(code, "TOTP code");
  });
  el["entry-delete"].addEventListener("click", deleteEntry);
  el["entry-cancel"].addEventListener("click", function () {
    el["pane-detail"].hidden = true;
    el["pane-empty"].hidden = false;
    state.selectedId = null;
    renderList();
  });
  el["btn-checkout-month"].addEventListener("click", function () {
    startCheckout("monthly");
  });
  el["btn-checkout-year"].addEventListener("click", function () {
    startCheckout("yearly");
  });
  el["btn-logout"].addEventListener("click", async function () {
    await api.logout();
    lockVault("Signed out. Local ciphertext remains on this device.");
  });
  el["btn-delete-account"].addEventListener("click", async function () {
    if (!window.confirm("Delete the cloud account and wipe server-side ciphertext? Local copy remains until you clear this browser.")) {
      return;
    }
    try {
      await api.deleteAccount(state.authKeyB64);
      ui.toast("Cloud account deleted.");
      state.account = null;
      renderAccount();
    } catch (err) {
      ui.toast(err.message, "error");
    }
  });
  el["btn-hibp"].addEventListener("click", hibpCheck);
  el["btn-passkey-add"].addEventListener("click", addPasskey);
  el["btn-recovery-regen"].addEventListener("click", regenerateRecovery);
  el["account-close"].addEventListener("click", function () {
    closeDialog(el["account-dialog"]);
  });
  el["btn-help"].addEventListener("click", function () {
    openDialog(el["help-dialog"]);
  });
  el["help-close"].addEventListener("click", function () {
    closeDialog(el["help-dialog"]);
  });
  document.addEventListener("keydown", function (event) {
    if (event.key === "Escape") {
      closeDialog(el["help-dialog"]);
      closeDialog(el["account-dialog"]);
      return;
    }
    if (event.metaKey || event.ctrlKey || event.altKey) return;
    if (typingTarget(event.target)) {
      if (event.key === "Escape" && event.target && event.target.blur) event.target.blur();
      return;
    }
    if (!state.vaultKey) return;
    if (event.key === "/") {
      event.preventDefault();
      el.search.focus();
    } else if (event.key === "n" || event.key === "N") {
      event.preventDefault();
      openNew();
    } else if (event.key === "l" || event.key === "L") {
      event.preventDefault();
      lockVault("Vault locked.");
    } else if (event.key === "?") {
      event.preventDefault();
      openDialog(el["help-dialog"]);
    }
  });
  ["mousemove", "keydown", "click", "touchstart"].forEach(function (name) {
    document.addEventListener(name, function () {
      if (state.vaultKey) bumpIdle();
    }, { passive: true });
  });
  document.addEventListener("visibilitychange", function () {
    if (document.visibilityState === "hidden" && state.vaultKey) {
      bumpIdle();
    }
  });
}

async function boot() {
  ui.initShell();
  bind();
  wire();
  setMode("unlock");
  try {
    state.health = await api.health();
  } catch (err) {
    state.health = null;
  }
  const params = new URLSearchParams(window.location.search);
  if (params.get("checkout") === "success") {
    setLockStatus("If payment succeeded, unlock to refresh your plan. Stripe never sends us the card number.", "ok");
  }
}

if (document.readyState === "loading") {
  document.addEventListener("DOMContentLoaded", boot);
} else {
  boot();
}
