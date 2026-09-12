/** Shared shell: theme, mobile nav, toasts, lock mark. No secrets here. */

const THEME_KEY = "pwmanager.saas.theme";

export function $(id) {
  return document.getElementById(id);
}

export function preferredTheme() {
  try {
    const stored = window.localStorage.getItem(THEME_KEY);
    if (stored === "light" || stored === "dark") {
      return stored;
    }
  } catch (err) {
    /* private mode */
  }
  if (window.matchMedia && window.matchMedia("(prefers-color-scheme: light)").matches) {
    return "light";
  }
  return "dark";
}

export function setTheme(theme) {
  const next = theme === "light" ? "light" : "dark";
  document.documentElement.setAttribute("data-theme", next);
  try {
    window.localStorage.setItem(THEME_KEY, next);
  } catch (err) {
    /* ignore */
  }
  document.querySelectorAll("[data-theme-toggle]").forEach(function (btn) {
    btn.setAttribute("aria-pressed", next === "dark" ? "true" : "false");
    btn.textContent = next === "dark" ? "Light" : "Dark";
  });
}

export function initTheme() {
  setTheme(preferredTheme());
  document.querySelectorAll("[data-theme-toggle]").forEach(function (btn) {
    btn.addEventListener("click", function () {
      const current = document.documentElement.getAttribute("data-theme") === "light" ? "light" : "dark";
      setTheme(current === "dark" ? "light" : "dark");
    });
  });
}

export function initNav() {
  const toggle = document.getElementById("nav-toggle");
  const links = document.getElementById("nav-links");
  if (!toggle || !links) {
    return;
  }
  toggle.addEventListener("click", function () {
    const open = toggle.getAttribute("aria-expanded") === "true";
    toggle.setAttribute("aria-expanded", open ? "false" : "true");
    links.classList.toggle("is-open", !open);
  });
}

export function initShell() {
  initTheme();
  initNav();
  const year = document.getElementById("year");
  if (year) {
    year.textContent = String(new Date().getFullYear());
  }
}

export function toast(message, kind) {
  let node = document.getElementById("toast");
  if (!node) {
    node = document.createElement("div");
    node.id = "toast";
    node.className = "toast";
    node.setAttribute("role", "status");
    document.body.appendChild(node);
  }
  node.textContent = message;
  node.dataset.kind = kind || "info";
  node.classList.add("is-visible");
  window.clearTimeout(toast._timer);
  toast._timer = window.setTimeout(function () {
    node.classList.remove("is-visible");
  }, 4200);
}

export async function copyText(text) {
  if (!navigator.clipboard || !navigator.clipboard.writeText) {
    throw new Error("Clipboard unavailable");
  }
  await navigator.clipboard.writeText(text);
}

export async function clearClipboardIfUnchanged(text) {
  const wipe = function () {
    return navigator.clipboard.writeText("");
  };
  if (navigator.clipboard.readText) {
    try {
      const current = await navigator.clipboard.readText();
      if (current === text) {
        await wipe();
      }
      return;
    } catch (err) {
      await wipe().catch(function () {});
      return;
    }
  }
  await wipe().catch(function () {});
}

export function formatWhen(ts) {
  if (!ts) {
    return "Never";
  }
  const date = new Date(ts < 1e12 ? ts * 1000 : ts);
  if (Number.isNaN(date.getTime())) {
    return "—";
  }
  return date.toLocaleString();
}
