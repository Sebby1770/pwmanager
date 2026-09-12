/** Local vault audit. Findings list names only — never the secrets themselves. */

import { estimateBits } from "./crypto.js";

const WEAK_BITS = 50;
const ROTATE_DAYS = 90;

export function auditVault(entries) {
  const list = Array.isArray(entries) ? entries : [];
  const now = Date.now() / 1000;
  const byPassword = new Map();
  const weak = [];
  const old = [];
  const missingTotp = [];
  const emptyUser = [];
  const reused = [];

  list.forEach(function (entry) {
    if (!entry || entry.kind === "note") {
      return;
    }
    const name = entry.name || "(unnamed)";
    if (!entry.username) {
      emptyUser.push(name);
    }
    if (entry.url && !entry.totp_secret) {
      missingTotp.push(name);
    }
    const password = entry.password || "";
    if (password) {
      if (estimateBits(password) < WEAK_BITS) {
        weak.push(name);
      }
      const group = byPassword.get(password) || [];
      group.push(name);
      byPassword.set(password, group);
    }
    const windowDays = entry.rotate_after_days == null ? ROTATE_DAYS : Number(entry.rotate_after_days);
    const updated = Number(entry.updated_at) || 0;
    if (windowDays > 0 && updated && now - updated > windowDays * 86400) {
      old.push(name);
    }
  });

  byPassword.forEach(function (names) {
    if (names.length > 1) {
      reused.push(names);
    }
  });

  const issueCount =
    weak.length +
    old.length +
    missingTotp.length +
    emptyUser.length +
    reused.reduce(function (n, g) {
      return n + g.length;
    }, 0);

  return {
    total: list.length,
    weak: weak,
    old: old,
    missingTotp: missingTotp,
    emptyUser: emptyUser,
    reused: reused,
    issueCount: issueCount
  };
}
