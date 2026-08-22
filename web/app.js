/*
 * pwmanager web generator — UI layer.
 *
 * All generation logic lives in generator.js (shared with the Node tests).
 * This file only wires DOM events to it. Two rules it never breaks:
 *   1. a generated secret is never written to localStorage, the URL, or the
 *      network;
 *   2. the only fetch in this file is the HIBP range request, and only from a
 *      direct click on "Check breaches".
 */
(function () {
  "use strict";

  var PwGen = window.PwGen;
  var WORDLIST = window.PW_WORDLIST || [];
  var WORD_SET = WORDLIST.length ? PwGen.buildWordSet(WORDLIST) : null;

  var PREFS_KEY = "pwmanager.web.prefs.v1";
  var CLIPBOARD_CLEAR_MS = 20000; // matches CLIPBOARD_CLEAR_SECONDS in the CLI

  var $ = function (id) {
    return document.getElementById(id);
  };

  var el = {
    secret: $("secret"),
    regenerate: $("regenerate"),
    copy: $("copy"),
    reveal: $("reveal"),
    copyStatus: $("copy-status"),
    meterFill: $("meter-fill"),
    strengthText: $("strength-text"),
    factEntropy: $("fact-entropy"),
    factAlphabet: $("fact-alphabet"),
    factCrack: $("fact-crack"),
    modelNote: $("model-note"),
    tabPassword: $("tab-password"),
    tabPassphrase: $("tab-passphrase"),
    panelPassword: $("panel-password"),
    panelPassphrase: $("panel-passphrase"),
    length: $("length"),
    lengthValue: $("length-value"),
    useLower: $("use-lower"),
    useUpper: $("use-upper"),
    useDigits: $("use-digits"),
    useSymbols: $("use-symbols"),
    avoidAmbiguous: $("avoid-ambiguous"),
    exclude: $("exclude"),
    symbolSample: $("symbol-sample"),
    presetHint: $("preset-hint"),
    words: $("words"),
    wordsValue: $("words-value"),
    separator: $("separator"),
    capitalize: $("capitalize"),
    addNumber: $("add-number"),
    addSymbol: $("add-symbol"),
    wordlistSize: $("wordlist-size"),
    cliCommand: $("cli-command"),
    copyCli: $("copy-cli"),
    batchCount: $("batch-count"),
    batchGenerate: $("batch-generate"),
    batchCopy: $("batch-copy"),
    batchClear: $("batch-clear"),
    batchList: $("batch-list"),
    breachInput: $("breach-input"),
    breachCheck: $("breach-check"),
    breachUseCurrent: $("breach-use-current"),
    breachResult: $("breach-result"),
    themeToggle: $("theme-toggle")
  };

  var state = {
    mode: "password",
    current: "",
    revealed: true,
    batch: [],
    copyTimer: null,
    statusTimer: null
  };

  /* ----------------------------------------------------------- preferences */

  // Only interface settings are persisted. Never a secret.
  function loadPrefs() {
    try {
      var raw = window.localStorage.getItem(PREFS_KEY);
      return raw ? JSON.parse(raw) : null;
    } catch (err) {
      return null;
    }
  }

  function savePrefs() {
    var prefs = {
      mode: state.mode,
      theme: document.documentElement.getAttribute("data-theme") || "",
      length: Number(el.length.value),
      useLower: el.useLower.checked,
      useUpper: el.useUpper.checked,
      useDigits: el.useDigits.checked,
      useSymbols: el.useSymbols.checked,
      avoidAmbiguous: el.avoidAmbiguous.checked,
      exclude: el.exclude.value,
      words: Number(el.words.value),
      separator: el.separator.value,
      capitalize: el.capitalize.checked,
      addNumber: el.addNumber.checked,
      addSymbol: el.addSymbol.checked
    };
    try {
      window.localStorage.setItem(PREFS_KEY, JSON.stringify(prefs));
    } catch (err) {
      /* private browsing or storage disabled — preferences just won't persist */
    }
  }

  function applyPrefs(prefs) {
    if (!prefs) {
      return;
    }
    if (prefs.theme === "dark" || prefs.theme === "light") {
      setTheme(prefs.theme);
    }
    if (Number.isFinite(prefs.length)) {
      el.length.value = String(clamp(prefs.length, Number(el.length.min), Number(el.length.max)));
    }
    if (Number.isFinite(prefs.words)) {
      el.words.value = String(clamp(prefs.words, Number(el.words.min), Number(el.words.max)));
    }
    setChecked(el.useLower, prefs.useLower, true);
    setChecked(el.useUpper, prefs.useUpper, true);
    setChecked(el.useDigits, prefs.useDigits, true);
    setChecked(el.useSymbols, prefs.useSymbols, true);
    setChecked(el.avoidAmbiguous, prefs.avoidAmbiguous, false);
    setChecked(el.capitalize, prefs.capitalize, false);
    setChecked(el.addNumber, prefs.addNumber, false);
    setChecked(el.addSymbol, prefs.addSymbol, false);
    if (typeof prefs.exclude === "string") {
      el.exclude.value = prefs.exclude;
    }
    if (typeof prefs.separator === "string") {
      el.separator.value = prefs.separator;
    }
    if (prefs.mode === "passphrase") {
      setMode("passphrase", { focus: false });
    }
  }

  function setChecked(node, value, fallback) {
    node.checked = typeof value === "boolean" ? value : fallback;
  }

  function clamp(value, min, max) {
    return Math.min(max, Math.max(min, value));
  }

  /* ----------------------------------------------------------------- theme */

  function setTheme(theme) {
    document.documentElement.setAttribute("data-theme", theme);
    var dark = theme === "dark";
    el.themeToggle.textContent = dark ? "Light" : "Dark";
    el.themeToggle.setAttribute("aria-pressed", dark ? "true" : "false");
  }

  function initTheme() {
    var prefersDark = window.matchMedia && window.matchMedia("(prefers-color-scheme: dark)").matches;
    setTheme(prefersDark ? "dark" : "light");
  }

  /* ------------------------------------------------------------- gathering */

  function passwordOptions() {
    return {
      length: Number(el.length.value),
      useLower: el.useLower.checked,
      useUpper: el.useUpper.checked,
      useDigits: el.useDigits.checked,
      useSymbols: el.useSymbols.checked,
      avoidAmbiguous: el.avoidAmbiguous.checked,
      exclude: el.exclude.value
    };
  }

  function passphraseOptions() {
    return {
      words: Number(el.words.value),
      separator: el.separator.value,
      capitalize: el.capitalize.checked,
      addNumber: el.addNumber.checked,
      addSymbol: el.addSymbol.checked,
      wordlist: WORDLIST
    };
  }

  function generateOne() {
    return state.mode === "passphrase"
      ? PwGen.generatePassphrase(passphraseOptions())
      : PwGen.generatePassword(passwordOptions());
  }

  /* --------------------------------------------------------------- display */

  function renderSecret() {
    try {
      state.current = generateOne();
      el.secret.classList.remove("error");
      el.secret.textContent = state.current;
      applyReveal();
      renderStrength(state.current);
    } catch (err) {
      state.current = "";
      el.secret.classList.add("error");
      el.secret.classList.remove("hidden-secret");
      el.secret.textContent = err.message;
      clearStrength();
    }
    renderCli();
  }

  function applyReveal() {
    var hide = !state.revealed && state.current;
    el.secret.classList.toggle("hidden-secret", hide);
    el.reveal.textContent = state.revealed ? "Hide" : "Show";
    el.reveal.setAttribute("aria-pressed", state.revealed ? "true" : "false");
  }

  function renderStrength(secret) {
    var estimate = PwGen.estimateEntropyBits(secret, { wordlist: WORDLIST, wordSet: WORD_SET });
    var bits = estimate.bits;
    var strength = PwGen.strengthLabel(bits);

    el.meterFill.style.width = Math.min(100, (bits / 128) * 100) + "%";
    el.meterFill.setAttribute("data-level", String(strength.level));
    el.strengthText.textContent = strength.label;
    el.factEntropy.textContent = bits.toFixed(1) + " bits";
    el.factCrack.textContent = PwGen.humaniseSeconds(PwGen.crackTimeSeconds(bits));

    if (state.mode === "passphrase") {
      el.factAlphabet.textContent = WORDLIST.length + " words";
    } else {
      el.factAlphabet.textContent = PwGen.poolsFor(passwordOptions()).alphabet.length + " chars";
    }

    el.modelNote.textContent =
      estimate.model === "passphrase"
        ? "Scored as a passphrase: " +
          estimate.words +
          " words from a known " +
          WORDLIST.length +
          "-word list. An attacker guesses whole words, not letters, so this is lower than a naive per-character estimate."
        : "Assumes an attacker knows the exact policy and guesses offline at 100 billion attempts per second.";
  }

  function clearStrength() {
    el.meterFill.style.width = "0";
    el.meterFill.setAttribute("data-level", "0");
    el.strengthText.textContent = "—";
    el.factEntropy.textContent = "—";
    el.factAlphabet.textContent = "—";
    el.factCrack.textContent = "—";
    el.modelNote.textContent = "";
  }

  function renderCli() {
    el.cliCommand.textContent =
      state.mode === "passphrase"
        ? PwGen.cliCommand("passphrase", passphraseOptions())
        : PwGen.cliCommand("password", passwordOptions());
  }

  function status(message, kind) {
    el.copyStatus.textContent = message;
    el.copyStatus.style.color = kind === "error" ? "var(--weak)" : "var(--good)";
    window.clearTimeout(state.statusTimer);
    if (message) {
      state.statusTimer = window.setTimeout(function () {
        el.copyStatus.textContent = "";
      }, 4000);
    }
  }

  /* ------------------------------------------------------------- clipboard */

  function writeClipboard(text) {
    if (navigator.clipboard && navigator.clipboard.writeText) {
      return navigator.clipboard.writeText(text);
    }
    return Promise.reject(new Error("Clipboard unavailable — select the text and copy manually."));
  }

  /**
   * Copy, then blank the clipboard after 20 seconds — the same guard rail as
   * `pwmanager get --copy`. Best effort: if the user copies something else in
   * the meantime we would overwrite it, so we only clear when the clipboard
   * still holds what we put there (where the browser lets us read it back).
   */
  function copySecret(text, label) {
    writeClipboard(text)
      .then(function () {
        status(label + " copied — clipboard clears in 20 seconds.");
        window.clearTimeout(state.copyTimer);
        state.copyTimer = window.setTimeout(function () {
          clearClipboardIfUnchanged(text);
        }, CLIPBOARD_CLEAR_MS);
      })
      .catch(function (err) {
        status(err.message || "Could not copy.", "error");
      });
  }

  function clearClipboardIfUnchanged(text) {
    var finish = function () {
      writeClipboard("").catch(function () {});
      status("Clipboard cleared.");
    };
    if (navigator.clipboard && navigator.clipboard.readText) {
      navigator.clipboard
        .readText()
        .then(function (current) {
          if (current === text) {
            finish();
          }
        })
        .catch(function () {
          finish(); // no read permission: clear anyway, ours is the likelier content
        });
    } else {
      finish();
    }
  }

  /* ------------------------------------------------------------------ tabs */

  function setMode(mode, options) {
    var opts = options || {};
    state.mode = mode;
    var isPhrase = mode === "passphrase";

    el.tabPassword.setAttribute("aria-selected", isPhrase ? "false" : "true");
    el.tabPassphrase.setAttribute("aria-selected", isPhrase ? "true" : "false");
    el.tabPassword.tabIndex = isPhrase ? -1 : 0;
    el.tabPassphrase.tabIndex = isPhrase ? 0 : -1;
    el.panelPassword.hidden = isPhrase;
    el.panelPassphrase.hidden = !isPhrase;

    if (opts.focus !== false) {
      (isPhrase ? el.tabPassphrase : el.tabPassword).focus();
    }
    if (opts.regenerate !== false) {
      renderSecret();
      savePrefs();
    }
  }

  /* --------------------------------------------------------------- presets */

  function applyPreset(name) {
    var preset = PwGen.PRESETS[name];
    if (!preset) {
      return;
    }
    setMode("password", { focus: false, regenerate: false });
    el.length.value = String(preset.length);
    el.useLower.checked = preset.useLower;
    el.useUpper.checked = preset.useUpper;
    el.useDigits.checked = preset.useDigits;
    el.useSymbols.checked = preset.useSymbols;
    el.avoidAmbiguous.checked = preset.avoidAmbiguous;
    el.exclude.value = "";

    // The PIN preset is digits-only; express that as "digits only" checkboxes
    // so the visible controls always describe what was actually generated.
    if (preset.digitsOnly) {
      el.useLower.checked = false;
      el.useUpper.checked = false;
      el.useSymbols.checked = false;
      el.useDigits.checked = true;
    }

    el.presetHint.textContent = preset.label + ": " + preset.hint;
    Object.keys(PwGen.PRESETS).forEach(function (key) {
      var chip = document.querySelector('[data-preset="' + key + '"]');
      if (chip) {
        chip.setAttribute("aria-pressed", key === name ? "true" : "false");
      }
    });

    syncRangeLabels();
    renderSecret();
    savePrefs();
  }

  function clearPresetSelection() {
    Object.keys(PwGen.PRESETS).forEach(function (key) {
      var chip = document.querySelector('[data-preset="' + key + '"]');
      if (chip) {
        chip.setAttribute("aria-pressed", "false");
      }
    });
  }

  /* ----------------------------------------------------------------- batch */

  function renderBatch() {
    el.batchList.textContent = "";
    state.batch.forEach(function (item) {
      var li = document.createElement("li");
      li.textContent = item;
      el.batchList.appendChild(li);
    });
    var empty = state.batch.length === 0;
    el.batchCopy.disabled = empty;
    el.batchClear.disabled = empty;
  }

  function generateBatch() {
    var count = clamp(Math.round(Number(el.batchCount.value) || 0), 1, 100);
    el.batchCount.value = String(count);
    var items = [];
    try {
      for (var i = 0; i < count; i += 1) {
        items.push(generateOne());
      }
    } catch (err) {
      status(err.message, "error");
      return;
    }
    state.batch = items;
    renderBatch();
    status(count + " generated.");
  }

  /* ---------------------------------------------------------------- breach */

  function sha1Hex(text) {
    if (!window.crypto || !window.crypto.subtle) {
      return Promise.reject(
        new Error("This browser cannot hash locally (needs https:// or localhost).")
      );
    }
    var bytes = new TextEncoder().encode(text);
    return window.crypto.subtle.digest("SHA-1", bytes).then(function (buffer) {
      var view = new Uint8Array(buffer);
      var out = "";
      for (var i = 0; i < view.length; i += 1) {
        out += view[i].toString(16).padStart(2, "0");
      }
      return out.toUpperCase();
    });
  }

  function setBreachResult(message, kind) {
    el.breachResult.textContent = message;
    el.breachResult.className = "breach-result" + (kind ? " " + kind : "");
  }

  function checkBreach() {
    var password = el.breachInput.value;
    if (!password) {
      setBreachResult("Enter a password first.", "warn");
      return;
    }

    el.breachCheck.disabled = true;
    setBreachResult("Checking…");

    sha1Hex(password)
      .then(function (digest) {
        var parts = PwGen.splitHibpDigest(digest);
        // Add-Padding asks the API to pad the response so its size does not
        // leak how many suffixes share our prefix.
        return fetch("https://api.pwnedpasswords.com/range/" + parts.prefix, {
          headers: { "Add-Padding": "true" },
          referrerPolicy: "no-referrer"
        })
          .then(function (response) {
            if (!response.ok) {
              throw new Error("HIBP responded with " + response.status);
            }
            return response.text();
          })
          .then(function (body) {
            return PwGen.countInRangeResponse(body, parts.suffix);
          });
      })
      .then(function (count) {
        if (count > 0) {
          setBreachResult(
            "Found in breach corpora " + count.toLocaleString() + " times. Do not use this password.",
            "bad"
          );
        } else {
          setBreachResult("Not found in any known breach. That is not proof it is strong.", "ok");
        }
      })
      .catch(function (err) {
        setBreachResult("Could not check: " + (err.message || "network unavailable") + ".", "warn");
      })
      .then(function () {
        el.breachCheck.disabled = false;
      });
  }

  /* ----------------------------------------------------------------- wiring */

  function syncRangeLabels() {
    el.lengthValue.textContent = el.length.value;
    el.wordsValue.textContent = el.words.value;
  }

  function onPolicyChange() {
    syncRangeLabels();
    clearPresetSelection();
    renderSecret();
    savePrefs();
  }

  function init() {
    if (!PwGen) {
      el.secret.textContent = "Generator failed to load.";
      return;
    }

    el.symbolSample.textContent = PwGen.SYMBOLS;
    el.wordlistSize.textContent = String(WORDLIST.length);
    el.length.max = String(PwGen.MAX_LENGTH > 128 ? 128 : PwGen.MAX_LENGTH);
    el.words.min = String(PwGen.MIN_WORDS);

    initTheme();
    applyPrefs(loadPrefs());
    syncRangeLabels();

    el.regenerate.addEventListener("click", function () {
      renderSecret();
    });
    el.copy.addEventListener("click", function () {
      if (state.current) {
        copySecret(state.current, state.mode === "passphrase" ? "Passphrase" : "Password");
      }
    });
    el.reveal.addEventListener("click", function () {
      state.revealed = !state.revealed;
      applyReveal();
    });
    el.copyCli.addEventListener("click", function () {
      writeClipboard(el.cliCommand.textContent).then(
        function () {
          status("Command copied.");
        },
        function () {
          status("Could not copy.", "error");
        }
      );
    });

    el.tabPassword.addEventListener("click", function () {
      setMode("password");
    });
    el.tabPassphrase.addEventListener("click", function () {
      setMode("passphrase");
    });
    [el.tabPassword, el.tabPassphrase].forEach(function (tab) {
      tab.addEventListener("keydown", function (event) {
        if (event.key === "ArrowLeft" || event.key === "ArrowRight") {
          event.preventDefault();
          setMode(state.mode === "password" ? "passphrase" : "password");
        }
      });
    });

    Object.keys(PwGen.PRESETS).forEach(function (key) {
      var chip = document.querySelector('[data-preset="' + key + '"]');
      if (chip) {
        chip.setAttribute("aria-pressed", "false");
        chip.addEventListener("click", function () {
          applyPreset(key);
        });
      }
    });

    // `input` on the sliders keeps the number label live; regeneration is
    // debounced onto `change` so dragging does not burn through the CSPRNG.
    el.length.addEventListener("input", function () {
      syncRangeLabels();
      renderCli();
    });
    el.words.addEventListener("input", function () {
      syncRangeLabels();
      renderCli();
    });
    el.length.addEventListener("change", onPolicyChange);
    el.words.addEventListener("change", onPolicyChange);

    [
      el.useLower,
      el.useUpper,
      el.useDigits,
      el.useSymbols,
      el.avoidAmbiguous,
      el.capitalize,
      el.addNumber,
      el.addSymbol,
      el.separator
    ].forEach(function (node) {
      node.addEventListener("change", onPolicyChange);
    });
    el.exclude.addEventListener("input", onPolicyChange);

    el.batchGenerate.addEventListener("click", generateBatch);
    el.batchCopy.addEventListener("click", function () {
      if (state.batch.length) {
        copySecret(state.batch.join("\n"), state.batch.length + " secrets");
      }
    });
    el.batchClear.addEventListener("click", function () {
      state.batch = [];
      renderBatch();
      status("Batch cleared.");
    });

    el.breachCheck.addEventListener("click", checkBreach);
    el.breachInput.addEventListener("keydown", function (event) {
      if (event.key === "Enter") {
        checkBreach();
      }
    });
    el.breachUseCurrent.addEventListener("click", function () {
      if (state.current) {
        el.breachInput.value = state.current;
        setBreachResult("Loaded the password above. Press Check breaches to send its hash prefix.", "warn");
      }
    });

    el.themeToggle.addEventListener("click", function () {
      var next = document.documentElement.getAttribute("data-theme") === "dark" ? "light" : "dark";
      setTheme(next);
      savePrefs();
    });

    // Drop secrets from memory when the tab is hidden for a while.
    document.addEventListener("visibilitychange", function () {
      if (document.visibilityState === "hidden") {
        window.clearTimeout(state.statusTimer);
      }
    });

    renderSecret();
    renderBatch();
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", init);
  } else {
    init();
  }
})();
