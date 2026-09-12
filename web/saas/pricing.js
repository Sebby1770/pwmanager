import * as api from "./api.js";
import { initShell, toast } from "./ui.js";

initShell();

const status = document.getElementById("pricing-status");
const setup = document.getElementById("stripe-setup");
const payMonth = document.getElementById("pay-month");
const payYear = document.getElementById("pay-year");

function setStatus(text, kind) {
  if (!status) return;
  status.textContent = text;
  status.dataset.kind = kind || "";
}

async function pay(interval) {
  try {
    const result = await api.checkout(interval);
    if (result.url) {
      window.location.href = result.url;
      return;
    }
    setStatus("Checkout did not return a URL.", "error");
  } catch (err) {
    if (err.code === "stripe_not_configured" || err.status === 503) {
      if (setup) setup.hidden = false;
      setStatus(err.message, "warn");
      return;
    }
    if (err.status === 401) {
      setStatus("Sign in from the vault first, then return here to subscribe.", "warn");
      toast("Open the vault and create a cloud account before checkout.");
      return;
    }
    setStatus(err.message || "Checkout failed.", "error");
  }
}

payMonth.addEventListener("click", function () {
  pay("monthly");
});
payYear.addEventListener("click", function () {
  pay("yearly");
});

(async function boot() {
  try {
    const health = await api.health();
    if (!health.stripe_configured && setup) {
      setup.hidden = false;
    }
  } catch (err) {
    setStatus("API not reachable. Local vault still works without Pro sync.", "warn");
  }
  try {
    const me = await api.me();
    if (me.account && me.account.pro) {
      setStatus("This account is already on Pro.", "ok");
    } else if (me.account) {
      setStatus("Signed in as " + me.account.email + " (Free). Choose a plan to open Stripe Checkout.", "ok");
    }
  } catch (err) {
    /* not signed in */
  }
  const params = new URLSearchParams(window.location.search);
  if (params.get("checkout") === "cancel") {
    setStatus("Checkout canceled. No charge was made.", "warn");
  }
})();
