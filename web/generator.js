/*
 * pwmanager web generator core.
 *
 * Pure, dependency-free logic shared by the browser UI (web/app.js) and the
 * Node test suite (tests/js/run.mjs). Everything here mirrors
 * pwmanager/generators.py so a password made in the browser matches one made
 * by the CLI for the same policy; tests/test_web_parity.py enforces that.
 *
 * Randomness always comes from the platform CSPRNG (WebCrypto
 * getRandomValues). There is no Math.random fallback: if no CSPRNG is
 * available the generator refuses to produce a password rather than emitting
 * a predictable one.
 */
(function (root, factory) {
  if (typeof module === "object" && module.exports) {
    module.exports = factory();
  } else {
    root.PwGen = factory();
  }
})(typeof globalThis !== "undefined" ? globalThis : this, function () {
  "use strict";

  // Kept byte-for-byte in sync with pwmanager.constants.SYMBOLS.
  var SYMBOLS = "!@#$%^&*()-_=+[]{};:,.?/";
  // Kept in sync with the `ambiguous` set in generators.generate_password.
  var AMBIGUOUS = "Il1O0o`'\"|";
  var LOWER = "abcdefghijklmnopqrstuvwxyz";
  var UPPER = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
  var DIGITS = "0123456789";

  // Mirrors pwmanager.generators.GENERATOR_PRESETS.
  var PRESETS = {
    pin: {
      label: "PIN",
      hint: "6 digits, for phone locks and card PINs",
      length: 6,
      useLower: false,
      useUpper: false,
      useDigits: true,
      useSymbols: false,
      avoidAmbiguous: false,
      digitsOnly: true
    },
    wifi: {
      label: "Wi-Fi",
      hint: "16 chars, no symbols or lookalikes — easy to type on a TV",
      length: 16,
      useLower: true,
      useUpper: true,
      useDigits: true,
      useSymbols: false,
      avoidAmbiguous: true,
      digitsOnly: false
    },
    apple: {
      label: "Strong",
      hint: "20 chars, all classes, no lookalike glyphs",
      length: 20,
      useLower: true,
      useUpper: true,
      useDigits: true,
      useSymbols: true,
      avoidAmbiguous: true,
      digitsOnly: false
    },
    max: {
      label: "Maximum",
      hint: "64 chars, everything on — for a password manager to remember",
      length: 64,
      useLower: true,
      useUpper: true,
      useDigits: true,
      useSymbols: true,
      avoidAmbiguous: false,
      digitsOnly: false
    }
  };

  var MIN_LENGTH = 4;
  var MAX_LENGTH = 256;
  var MIN_WORDS = 3;
  var MAX_WORDS = 24;

  /* ---------------------------------------------------------------- random */

  function getCrypto() {
    var c =
      (typeof globalThis !== "undefined" && globalThis.crypto) ||
      (typeof self !== "undefined" && self.crypto) ||
      null;
    if (!c || typeof c.getRandomValues !== "function") {
      throw new Error(
        "No cryptographic random source available. Use a modern browser over https:// or localhost."
      );
    }
    return c;
  }

  /**
   * Uniform integer in [0, max) with rejection sampling.
   *
   * A plain `getRandomValues(...)[0] % max` is biased whenever max is not a
   * power of two — low values come up slightly more often. Discarding the
   * non-uniform tail of the 32-bit range removes that bias entirely, which is
   * what secrets.randbelow does on the Python side.
   */
  function randomInt(max) {
    if (!Number.isInteger(max) || max <= 0) {
      throw new Error("randomInt requires a positive integer bound");
    }
    if (max === 1) {
      return 0;
    }
    var crypto = getCrypto();
    var buffer = new Uint32Array(1);
    var range = 0x100000000; // 2**32
    var limit = range - (range % max); // largest multiple of max <= 2**32
    for (;;) {
      crypto.getRandomValues(buffer);
      if (buffer[0] < limit) {
        return buffer[0] % max;
      }
    }
  }

  function choice(pool) {
    if (!pool || pool.length === 0) {
      throw new Error("choice() called with an empty pool");
    }
    return pool[randomInt(pool.length)];
  }

  /** In-place Fisher-Yates using the same CSPRNG. */
  function shuffle(items) {
    for (var i = items.length - 1; i > 0; i -= 1) {
      var j = randomInt(i + 1);
      var tmp = items[i];
      items[i] = items[j];
      items[j] = tmp;
    }
    return items;
  }

  /* ------------------------------------------------------------- passwords */

  function stripChars(pool, blocked) {
    var out = "";
    for (var i = 0; i < pool.length; i += 1) {
      if (blocked.indexOf(pool[i]) === -1) {
        out += pool[i];
      }
    }
    return out;
  }

  function normalisePasswordOptions(options) {
    var opts = options || {};
    return {
      length: opts.length === undefined ? 16 : Number(opts.length),
      useLower: opts.useLower !== false,
      useUpper: opts.useUpper !== false,
      useDigits: opts.useDigits !== false,
      useSymbols: opts.useSymbols !== false,
      avoidAmbiguous: opts.avoidAmbiguous === true,
      digitsOnly: opts.digitsOnly === true,
      exclude: typeof opts.exclude === "string" ? opts.exclude : ""
    };
  }

  /**
   * Build the character pools for a policy without generating anything.
   * Returned so the UI can show the live alphabet size and explain errors.
   */
  function poolsFor(options) {
    var opts = normalisePasswordOptions(options);
    var blocked = opts.exclude;
    if (opts.avoidAmbiguous) {
      blocked += AMBIGUOUS;
    }

    if (opts.digitsOnly) {
      var only = stripChars(DIGITS, blocked);
      return { pools: only ? [only] : [], alphabet: only, options: opts };
    }

    var pools = [];
    if (opts.useLower) {
      pools.push(stripChars(LOWER, blocked));
    }
    if (opts.useUpper) {
      pools.push(stripChars(UPPER, blocked));
    }
    if (opts.useDigits) {
      pools.push(stripChars(DIGITS, blocked));
    }
    if (opts.useSymbols) {
      pools.push(stripChars(SYMBOLS, blocked));
    }
    pools = pools.filter(function (pool) {
      return pool.length > 0;
    });
    return { pools: pools, alphabet: pools.join(""), options: opts };
  }

  /**
   * Generate one password.
   *
   * Guarantees one character from every enabled class (so the result always
   * satisfies the policy a site advertises), then fills the rest from the
   * combined alphabet and shuffles.
   */
  function generatePassword(options) {
    var built = poolsFor(options);
    var opts = built.options;
    var length = opts.length;

    if (!Number.isInteger(length)) {
      throw new Error("Length must be a whole number.");
    }
    if (length < MIN_LENGTH) {
      throw new Error("Length must be at least " + MIN_LENGTH + ".");
    }
    if (length > MAX_LENGTH) {
      throw new Error("Length must be at most " + MAX_LENGTH + ".");
    }
    if (built.pools.length === 0) {
      throw new Error("Every character was excluded — enable a class or clear the exclude list.");
    }
    if (opts.digitsOnly) {
      var digits = built.pools[0];
      var out = "";
      for (var d = 0; d < length; d += 1) {
        out += choice(digits);
      }
      return out;
    }
    if (length < built.pools.length) {
      throw new Error("Length must be at least " + built.pools.length + " for the selected classes.");
    }

    var chars = built.pools.map(function (pool) {
      return choice(pool);
    });
    var alphabet = built.alphabet;
    while (chars.length < length) {
      chars.push(choice(alphabet));
    }
    return shuffle(chars).join("");
  }

  function generateFromPreset(name) {
    var preset = PRESETS[String(name || "").toLowerCase()];
    if (!preset) {
      throw new Error("Unknown preset: " + name);
    }
    return generatePassword(preset);
  }

  /* ----------------------------------------------------------- passphrases */

  function normalisePassphraseOptions(options) {
    var opts = options || {};
    return {
      words: opts.words === undefined ? 5 : Number(opts.words),
      separator: opts.separator === undefined ? "-" : String(opts.separator),
      capitalize: opts.capitalize === true,
      addNumber: opts.addNumber === true,
      addSymbol: opts.addSymbol === true,
      wordlist: opts.wordlist || []
    };
  }

  /**
   * Generate a passphrase by sampling words *with replacement* — the same
   * model the entropy figure assumes. Sampling without replacement would give
   * slightly less entropy than words * log2(listSize) claims.
   */
  function generatePassphrase(options) {
    var opts = normalisePassphraseOptions(options);
    if (!Number.isInteger(opts.words)) {
      throw new Error("Word count must be a whole number.");
    }
    if (opts.words < MIN_WORDS) {
      throw new Error("Use at least " + MIN_WORDS + " words.");
    }
    if (opts.words > MAX_WORDS) {
      throw new Error("Use at most " + MAX_WORDS + " words.");
    }
    if (!opts.wordlist || opts.wordlist.length < 100) {
      throw new Error("Wordlist is missing or too small.");
    }

    var picked = [];
    for (var i = 0; i < opts.words; i += 1) {
      var word = choice(opts.wordlist);
      picked.push(opts.capitalize ? word.charAt(0).toUpperCase() + word.slice(1) : word);
    }

    // Extras are appended to a random word rather than the last one, so their
    // position carries a little information too instead of being predictable.
    if (opts.addNumber) {
      var numberAt = randomInt(picked.length);
      picked[numberAt] += choice(DIGITS);
    }
    if (opts.addSymbol) {
      var symbolAt = randomInt(picked.length);
      // Never the separator itself: "word--word" reads as an empty word, not
      // as an extra symbol, and the promised symbol would silently vanish.
      picked[symbolAt] += choice(stripChars(SYMBOLS, opts.separator));
    }
    return picked.join(opts.separator);
  }

  /* --------------------------------------------------------------- entropy */

  function log2(value) {
    return Math.log(value) / Math.LN2;
  }

  /**
   * Character-pool entropy — the direct port of
   * pwmanager.generators.password_entropy_bits.
   */
  function passwordEntropyBits(password) {
    if (!password) {
      return 0;
    }
    var pool = 0;
    var hasLower = false;
    var hasUpper = false;
    var hasDigit = false;
    var hasSymbol = false;
    var hasOther = false;

    for (var i = 0; i < password.length; i += 1) {
      var c = password[i];
      if (c >= "a" && c <= "z") {
        hasLower = true;
      } else if (c >= "A" && c <= "Z") {
        hasUpper = true;
      } else if (c >= "0" && c <= "9") {
        hasDigit = true;
      } else if (SYMBOLS.indexOf(c) !== -1) {
        hasSymbol = true;
      } else {
        hasOther = true;
      }
    }

    if (hasLower) {
      pool += 26;
    }
    if (hasUpper) {
      pool += 26;
    }
    if (hasDigit) {
      pool += 10;
    }
    if (hasSymbol) {
      pool += SYMBOLS.length;
    }
    if (hasOther) {
      pool += 32; // rough other-chars allowance, same constant as the CLI
    }
    if (pool === 0) {
      return 0;
    }
    return password.length * log2(pool);
  }

  /** Entropy of a passphrase drawn from a known list: words * log2(listSize). */
  function passphraseEntropyBits(wordCount, listSize) {
    if (!wordCount || !listSize || listSize < 2) {
      return 0;
    }
    return wordCount * log2(listSize);
  }

  /**
   * Best estimate of how hard a secret is to guess.
   *
   * Character-pool entropy badly overstates dictionary passphrases: an
   * attacker who knows the wordlist guesses whole words, not letters, so
   * "absorb-cactus-jungle-rally-widen" is ~55 bits, not the ~150 the pool
   * formula reports. When the secret looks like separator-joined words from
   * our list we score it as a passphrase and take the smaller of the two
   * models, which is the one an attacker would actually use.
   */
  function estimateEntropyBits(secret, context) {
    var ctx = context || {};
    var charBits = passwordEntropyBits(secret);
    var wordlist = ctx.wordlist;
    if (!secret || !wordlist || wordlist.length < 100) {
      return { bits: charBits, model: "characters" };
    }

    var separators = ["-", " ", ".", "_", ",", "+", ""];
    var lookup = ctx.wordSet || buildWordSet(wordlist);

    for (var s = 0; s < separators.length; s += 1) {
      var sep = separators[s];
      if (sep === "" || secret.indexOf(sep) === -1) {
        continue;
      }
      var parts = secret.split(sep);
      if (parts.length < 2) {
        continue;
      }
      var recognised = 0;
      var extras = 0;
      for (var p = 0; p < parts.length; p += 1) {
        // Strip trailing digits/symbols added as "extras" and score them
        // separately rather than crediting them as full characters.
        var core = parts[p].replace(/[^A-Za-z]+$/, "");
        var tail = parts[p].slice(core.length);
        extras += tail.length;
        if (core && lookup[core.toLowerCase()] === true) {
          recognised += 1;
        }
      }
      if (recognised >= 2 && recognised >= parts.length - 1) {
        var wordBits = passphraseEntropyBits(recognised, wordlist.length);
        var unknownBits = (parts.length - recognised) * log2(1000); // crude, conservative
        var extraBits = extras * log2(DIGITS.length + SYMBOLS.length);
        var total = wordBits + unknownBits + extraBits;
        if (total < charBits) {
          return { bits: total, model: "passphrase", words: recognised };
        }
      }
    }
    return { bits: charBits, model: "characters" };
  }

  function buildWordSet(wordlist) {
    var set = Object.create(null);
    for (var i = 0; i < wordlist.length; i += 1) {
      set[wordlist[i].toLowerCase()] = true;
    }
    return set;
  }

  /** Same thresholds as pwmanager.generators.strength_label. */
  function strengthLabel(bits) {
    if (bits < 28) {
      return { label: "Very weak", level: 0 };
    }
    if (bits < 50) {
      return { label: "Weak", level: 1 };
    }
    if (bits < 70) {
      return { label: "Reasonable", level: 2 };
    }
    if (bits < 90) {
      return { label: "Strong", level: 3 };
    }
    return { label: "Very strong", level: 4 };
  }

  /**
   * Time to exhaust half the keyspace at a given offline guess rate.
   * 1e11 guesses/sec is a rough consumer-GPU figure against a fast hash; it is
   * deliberately pessimistic so the number is a floor, not a promise.
   */
  function crackTimeSeconds(bits, guessesPerSecond) {
    var rate = guessesPerSecond || 1e11;
    return Math.pow(2, bits - 1) / rate;
  }

  function humaniseSeconds(seconds) {
    if (!isFinite(seconds)) {
      return "longer than the universe has existed";
    }
    if (seconds < 1) {
      return "instantly";
    }
    var units = [
      ["second", 60],
      ["minute", 60],
      ["hour", 24],
      ["day", 365.25],
      ["year", 1000],
      ["thousand years", 1000],
      ["million years", 1000],
      ["billion years", 1000]
    ];
    var value = seconds;
    for (var i = 0; i < units.length; i += 1) {
      var name = units[i][0];
      var step = units[i][1];
      if (value < step) {
        var rounded = value < 10 ? Math.round(value * 10) / 10 : Math.round(value);
        var plural = name.indexOf(" ") === -1 && rounded !== 1 ? name + "s" : name;
        return rounded + " " + plural;
      }
      value /= step;
    }
    return "longer than the universe has existed";
  }

  /* ------------------------------------------------------------------- CLI */

  function shellQuote(value) {
    if (/^[A-Za-z0-9._\/-]+$/.test(value)) {
      return value;
    }
    return "'" + value.replace(/'/g, "'\\''") + "'";
  }

  /**
   * The `pwmanager gen` invocation that produces the same policy, so the site
   * doubles as documentation for the CLI.
   */
  function cliCommand(mode, options) {
    if (mode === "passphrase") {
      var pp = normalisePassphraseOptions(options);
      var phraseArgs = ["pwmanager", "gen", "--passphrase", "--words", String(pp.words)];
      if (pp.separator !== "-") {
        phraseArgs.push("--separator", shellQuote(pp.separator));
      }
      if (pp.capitalize) {
        phraseArgs.push("--capitalize");
      }
      return phraseArgs.join(" ");
    }

    var opts = normalisePasswordOptions(options);

    // A digits-only policy at the preset length is exactly `--preset pin`.
    var digitsOnly = opts.digitsOnly || (opts.useDigits && !opts.useLower && !opts.useUpper && !opts.useSymbols);
    if (digitsOnly && opts.length === PRESETS.pin.length) {
      return "pwmanager gen --preset pin";
    }

    var args = ["pwmanager", "gen", "--length", String(opts.length)];
    if (!opts.useLower || digitsOnly) {
      args.push("--no-lower");
    }
    if (!opts.useUpper || digitsOnly) {
      args.push("--no-upper");
    }
    if (!opts.useDigits) {
      args.push("--no-digits");
    }
    if (!opts.useSymbols || digitsOnly) {
      args.push("--no-symbols");
    }
    if (opts.avoidAmbiguous) {
      args.push("--avoid-ambiguous");
    }
    // `gen` has no --exclude; say so rather than printing a flag that fails.
    if (opts.exclude) {
      return args.join(" ") + "   # note: --exclude is web-only";
    }
    return args.join(" ");
  }

  /* ------------------------------------------------------------------ HIBP */

  /**
   * Split a SHA-1 hex digest for a k-anonymity range query: only the 5-char
   * prefix is ever sent to the API, and the suffix is matched locally.
   */
  function splitHibpDigest(hexDigest) {
    var upper = String(hexDigest || "").toUpperCase();
    if (!/^[0-9A-F]{40}$/.test(upper)) {
      throw new Error("Expected a 40-character SHA-1 hex digest");
    }
    return { prefix: upper.slice(0, 5), suffix: upper.slice(5) };
  }

  /** Parse a `SUFFIX:COUNT` range response and return the count for `suffix`. */
  function countInRangeResponse(body, suffix) {
    var target = String(suffix || "").toUpperCase();
    var lines = String(body || "").split("\n");
    for (var i = 0; i < lines.length; i += 1) {
      var line = lines[i].trim();
      if (!line) {
        continue;
      }
      var sep = line.indexOf(":");
      if (sep === -1) {
        continue;
      }
      if (line.slice(0, sep).toUpperCase() === target) {
        var count = parseInt(line.slice(sep + 1), 10);
        return Number.isFinite(count) ? count : 0;
      }
    }
    return 0;
  }

  return {
    SYMBOLS: SYMBOLS,
    AMBIGUOUS: AMBIGUOUS,
    LOWER: LOWER,
    UPPER: UPPER,
    DIGITS: DIGITS,
    PRESETS: PRESETS,
    MIN_LENGTH: MIN_LENGTH,
    MAX_LENGTH: MAX_LENGTH,
    MIN_WORDS: MIN_WORDS,
    MAX_WORDS: MAX_WORDS,
    randomInt: randomInt,
    choice: choice,
    shuffle: shuffle,
    poolsFor: poolsFor,
    generatePassword: generatePassword,
    generateFromPreset: generateFromPreset,
    generatePassphrase: generatePassphrase,
    passwordEntropyBits: passwordEntropyBits,
    passphraseEntropyBits: passphraseEntropyBits,
    estimateEntropyBits: estimateEntropyBits,
    buildWordSet: buildWordSet,
    strengthLabel: strengthLabel,
    crackTimeSeconds: crackTimeSeconds,
    humaniseSeconds: humaniseSeconds,
    cliCommand: cliCommand,
    splitHibpDigest: splitHibpDigest,
    countInRangeResponse: countInRangeResponse
  };
});
