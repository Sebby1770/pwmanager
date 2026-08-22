/*
 * Tests for the web generator core. Zero dependencies — run with:
 *   node tests/js/run.mjs
 *
 * These cover the parts where a subtle mistake produces passwords that *look*
 * fine but are weaker than advertised: modulo bias, missing character classes,
 * and entropy that overstates dictionary passphrases.
 */
import { createRequire } from "node:module";
import { fileURLToPath } from "node:url";
import path from "node:path";

const require = createRequire(import.meta.url);
const here = path.dirname(fileURLToPath(import.meta.url));
const root = path.resolve(here, "..", "..");

const PwGen = require(path.join(root, "web", "generator.js"));
const WORDLIST = require(path.join(root, "web", "wordlist.js"));

let passed = 0;
const failures = [];

function test(name, fn) {
  try {
    fn();
    passed += 1;
  } catch (err) {
    failures.push({ name, err });
  }
}

function assert(condition, message) {
  if (!condition) {
    throw new Error(message || "assertion failed");
  }
}

function assertEqual(actual, expected, message) {
  if (actual !== expected) {
    throw new Error(`${message || "not equal"}: got ${JSON.stringify(actual)}, expected ${JSON.stringify(expected)}`);
  }
}

function assertThrows(fn, needle) {
  let threw = false;
  try {
    fn();
  } catch (err) {
    threw = true;
    if (needle && !String(err.message).includes(needle)) {
      throw new Error(`wrong error: ${err.message} (wanted ${needle})`);
    }
  }
  assert(threw, "expected a throw");
}

/* ------------------------------------------------------------------ random */

test("randomInt stays inside its bound", () => {
  for (let i = 0; i < 2000; i += 1) {
    const value = PwGen.randomInt(7);
    assert(Number.isInteger(value) && value >= 0 && value < 7, `out of range: ${value}`);
  }
});

test("randomInt(1) is always 0", () => {
  assertEqual(PwGen.randomInt(1), 0);
});

test("randomInt rejects non-positive bounds", () => {
  assertThrows(() => PwGen.randomInt(0));
  assertThrows(() => PwGen.randomInt(-3));
  assertThrows(() => PwGen.randomInt(2.5));
});

test("randomInt is close to uniform over a non-power-of-two bound", () => {
  // A modulo-biased generator over 3 buckets skews measurably at this sample
  // size; a chi-square style spread check catches it without being flaky.
  const buckets = [0, 0, 0];
  const draws = 60000;
  for (let i = 0; i < draws; i += 1) {
    buckets[PwGen.randomInt(3)] += 1;
  }
  const expected = draws / 3;
  buckets.forEach((count, index) => {
    const drift = Math.abs(count - expected) / expected;
    assert(drift < 0.05, `bucket ${index} drifted ${(drift * 100).toFixed(2)}%`);
  });
});

test("shuffle keeps every element", () => {
  const source = "abcdefghijklmnop".split("");
  const shuffled = PwGen.shuffle(source.slice());
  assertEqual(shuffled.length, source.length);
  assertEqual(shuffled.slice().sort().join(""), source.slice().sort().join(""));
});

/* --------------------------------------------------------------- passwords */

test("generatePassword honours the requested length", () => {
  [4, 8, 20, 64, 128].forEach((length) => {
    assertEqual(PwGen.generatePassword({ length }).length, length, `length ${length}`);
  });
});

test("generatePassword includes every enabled class", () => {
  for (let i = 0; i < 200; i += 1) {
    const pw = PwGen.generatePassword({ length: 12 });
    assert(/[a-z]/.test(pw), `no lowercase in ${pw}`);
    assert(/[A-Z]/.test(pw), `no uppercase in ${pw}`);
    assert(/[0-9]/.test(pw), `no digit in ${pw}`);
    assert([...pw].some((c) => PwGen.SYMBOLS.includes(c)), `no symbol in ${pw}`);
  }
});

test("generatePassword omits disabled classes", () => {
  for (let i = 0; i < 50; i += 1) {
    const pw = PwGen.generatePassword({ length: 24, useSymbols: false, useUpper: false });
    assert(!/[A-Z]/.test(pw), `uppercase leaked: ${pw}`);
    assert(![...pw].some((c) => PwGen.SYMBOLS.includes(c)), `symbol leaked: ${pw}`);
  }
});

test("avoidAmbiguous removes lookalike glyphs", () => {
  for (let i = 0; i < 50; i += 1) {
    const pw = PwGen.generatePassword({ length: 40, avoidAmbiguous: true });
    assert(![...pw].some((c) => PwGen.AMBIGUOUS.includes(c)), `lookalike in ${pw}`);
  }
});

test("exclude list is respected", () => {
  for (let i = 0; i < 50; i += 1) {
    const pw = PwGen.generatePassword({ length: 30, exclude: "aeiou0123456789" });
    assert(!/[aeiou0-9]/.test(pw), `excluded char in ${pw}`);
  }
});

test("generatePassword rejects impossible policies", () => {
  assertThrows(() => PwGen.generatePassword({ length: 3 }), "at least 4");
  assertThrows(() => PwGen.generatePassword({ length: 999 }), "at most");
  assertThrows(
    () =>
      PwGen.generatePassword({
        length: 10,
        useLower: false,
        useUpper: false,
        useDigits: false,
        useSymbols: false
      }),
    "excluded"
  );
  // Every character of every enabled class excluded by hand.
  assertThrows(
    () =>
      PwGen.generatePassword({
        length: 10,
        useUpper: false,
        useDigits: false,
        useSymbols: false,
        exclude: PwGen.LOWER
      }),
    "excluded"
  );
});

test("the shortest allowed password still satisfies all four classes", () => {
  // length 4 with 4 classes is the tightest fit the policy permits; the
  // one-per-class guarantee must still hold rather than silently dropping one.
  for (let i = 0; i < 100; i += 1) {
    const pw = PwGen.generatePassword({ length: 4 });
    assertEqual(pw.length, 4);
    assert(/[a-z]/.test(pw) && /[A-Z]/.test(pw) && /[0-9]/.test(pw), `missing a class: ${pw}`);
    assert([...pw].some((c) => PwGen.SYMBOLS.includes(c)), `missing a symbol: ${pw}`);
  }
});

test("pin preset produces digits only", () => {
  for (let i = 0; i < 50; i += 1) {
    const pin = PwGen.generateFromPreset("pin");
    assertEqual(pin.length, 6);
    assert(/^[0-9]{6}$/.test(pin), `not a pin: ${pin}`);
  }
});

test("every preset generates something matching its own policy", () => {
  Object.keys(PwGen.PRESETS).forEach((name) => {
    const preset = PwGen.PRESETS[name];
    const value = PwGen.generateFromPreset(name);
    assertEqual(value.length, preset.length, `${name} length`);
    if (preset.avoidAmbiguous) {
      assert(![...value].some((c) => PwGen.AMBIGUOUS.includes(c)), `${name} has lookalikes`);
    }
    if (!preset.useSymbols) {
      assert(![...value].some((c) => PwGen.SYMBOLS.includes(c)), `${name} has symbols`);
    }
  });
});

test("unknown preset is rejected", () => {
  assertThrows(() => PwGen.generateFromPreset("nope"), "Unknown preset");
});

test("generated passwords do not repeat", () => {
  const seen = new Set();
  for (let i = 0; i < 500; i += 1) {
    seen.add(PwGen.generatePassword({ length: 16 }));
  }
  assertEqual(seen.size, 500, "duplicate password generated");
});

/* ------------------------------------------------------------- passphrases */

test("wordlist loaded and large enough", () => {
  assert(Array.isArray(WORDLIST), "wordlist is not an array");
  assert(WORDLIST.length >= 1000, `only ${WORDLIST.length} words`);
  assert(
    WORDLIST.every((w) => typeof w === "string" && /^[a-z]+$/.test(w)),
    "wordlist has a non-lowercase-alpha entry"
  );
  assertEqual(new Set(WORDLIST).size, WORDLIST.length, "wordlist has duplicates");
});

test("generatePassphrase produces the requested word count", () => {
  for (let words = 3; words <= 10; words += 1) {
    const phrase = PwGen.generatePassphrase({ words, wordlist: WORDLIST });
    assertEqual(phrase.split("-").length, words, `words=${words}`);
  }
});

test("passphrase separator and capitalisation apply", () => {
  const phrase = PwGen.generatePassphrase({
    words: 4,
    separator: ".",
    capitalize: true,
    wordlist: WORDLIST
  });
  const parts = phrase.split(".");
  assertEqual(parts.length, 4);
  parts.forEach((word) => {
    assert(/^[A-Z][a-z]+$/.test(word), `not capitalised: ${word}`);
  });
});

test("passphrase extras add exactly one digit and one symbol", () => {
  const phrase = PwGen.generatePassphrase({
    words: 5,
    addNumber: true,
    addSymbol: true,
    wordlist: WORDLIST
  });
  const digits = [...phrase].filter((c) => /[0-9]/.test(c));
  const symbols = [...phrase].filter((c) => PwGen.SYMBOLS.includes(c) && c !== "-");
  assertEqual(digits.length, 1, "expected one digit");
  assertEqual(symbols.length, 1, "expected one symbol");
});

test("passphrase rejects bad input", () => {
  assertThrows(() => PwGen.generatePassphrase({ words: 2, wordlist: WORDLIST }), "at least 3");
  assertThrows(() => PwGen.generatePassphrase({ words: 99, wordlist: WORDLIST }), "at most");
  assertThrows(() => PwGen.generatePassphrase({ words: 5, wordlist: ["a", "b"] }), "too small");
});

test("passphrase words all come from the list", () => {
  const set = new Set(WORDLIST);
  for (let i = 0; i < 50; i += 1) {
    PwGen.generatePassphrase({ words: 6, wordlist: WORDLIST })
      .split("-")
      .forEach((word) => assert(set.has(word), `off-list word: ${word}`));
  }
});

/* ----------------------------------------------------------------- entropy */

test("passwordEntropyBits matches the closed form", () => {
  assertEqual(PwGen.passwordEntropyBits(""), 0);
  // 8 lowercase chars over a 26-char pool
  const bits = PwGen.passwordEntropyBits("abcdefgh");
  assert(Math.abs(bits - 8 * Math.log2(26)) < 1e-9, `got ${bits}`);
  // lower + upper + digits + symbols = 26 + 26 + 10 + len(SYMBOLS)
  const pool = 26 + 26 + 10 + PwGen.SYMBOLS.length;
  const mixed = PwGen.passwordEntropyBits("aB3!");
  assert(Math.abs(mixed - 4 * Math.log2(pool)) < 1e-9, `got ${mixed}`);
});

test("passphraseEntropyBits is words * log2(listSize)", () => {
  const bits = PwGen.passphraseEntropyBits(5, 2048);
  assert(Math.abs(bits - 55) < 1e-9, `got ${bits}`);
});

test("a dictionary passphrase is scored as words, not characters", () => {
  const phrase = [WORDLIST[3], WORDLIST[40], WORDLIST[900], WORDLIST[1200], WORDLIST[77]].join("-");
  const estimate = PwGen.estimateEntropyBits(phrase, { wordlist: WORDLIST });
  assertEqual(estimate.model, "passphrase", "should use the passphrase model");
  assertEqual(estimate.words, 5);
  const expected = 5 * Math.log2(WORDLIST.length);
  assert(Math.abs(estimate.bits - expected) < 1e-9, `got ${estimate.bits}, wanted ${expected}`);
  // The per-character model would wildly overstate this.
  assert(
    estimate.bits < PwGen.passwordEntropyBits(phrase),
    "passphrase model should be the more conservative of the two"
  );
});

test("a random password keeps the character model", () => {
  const estimate = PwGen.estimateEntropyBits("aB3!xY9$qW2@mN7#", { wordlist: WORDLIST });
  assertEqual(estimate.model, "characters");
});

test("strengthLabel thresholds match the CLI", () => {
  assertEqual(PwGen.strengthLabel(10).label, "Very weak");
  assertEqual(PwGen.strengthLabel(30).label, "Weak");
  assertEqual(PwGen.strengthLabel(55).label, "Reasonable");
  assertEqual(PwGen.strengthLabel(75).label, "Strong");
  assertEqual(PwGen.strengthLabel(128).label, "Very strong");
});

test("crack time grows with entropy and reads sensibly", () => {
  assert(PwGen.crackTimeSeconds(80) > PwGen.crackTimeSeconds(40));
  assertEqual(PwGen.humaniseSeconds(0.2), "instantly");
  assert(PwGen.humaniseSeconds(90).includes("minute"));
  assert(PwGen.humaniseSeconds(1e18).includes("years"));
});

/* --------------------------------------------------------------------- CLI */

test("cliCommand describes the current policy", () => {
  assertEqual(PwGen.cliCommand("password", { length: 20 }), "pwmanager gen --length 20");
  assertEqual(
    PwGen.cliCommand("password", { length: 16, useSymbols: false, avoidAmbiguous: true }),
    "pwmanager gen --length 16 --no-symbols --avoid-ambiguous"
  );
  assertEqual(
    PwGen.cliCommand("passphrase", { words: 6, separator: "-" }),
    "pwmanager gen --passphrase --words 6"
  );
  assertEqual(
    PwGen.cliCommand("passphrase", { words: 4, separator: " " }),
    "pwmanager gen --passphrase --words 4 --separator ' '"
  );
});

test("cliCommand recognises a digits-only policy as the pin preset", () => {
  assertEqual(PwGen.cliCommand("password", PwGen.PRESETS.pin), "pwmanager gen --preset pin");
  // The UI expresses "PIN" as checkboxes rather than a digitsOnly flag; both
  // spellings must produce the same command.
  assertEqual(
    PwGen.cliCommand("password", {
      length: 6,
      useLower: false,
      useUpper: false,
      useDigits: true,
      useSymbols: false
    }),
    "pwmanager gen --preset pin"
  );
});

test("a digits-only policy at another length spells out the flags", () => {
  assertEqual(
    PwGen.cliCommand("password", {
      length: 8,
      useLower: false,
      useUpper: false,
      useDigits: true,
      useSymbols: false
    }),
    "pwmanager gen --length 8 --no-lower --no-upper --no-symbols"
  );
});

test("cliCommand never invents a flag the CLI does not have", () => {
  // `gen` has no --exclude, so the hint must flag it rather than print it.
  const full = PwGen.cliCommand("password", { length: 20, exclude: "abc" });
  assert(full.includes("web-only"), `unexpected: ${full}`);
  const runnable = full.split("#")[0].trim();
  assertEqual(runnable, "pwmanager gen --length 20");
});

/* -------------------------------------------------------------------- HIBP */

test("splitHibpDigest sends only a 5-character prefix", () => {
  const digest = "5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8"; // SHA-1("password")
  const parts = PwGen.splitHibpDigest(digest);
  assertEqual(parts.prefix, "5BAA6");
  assertEqual(parts.suffix, "1E4C9B93F3F0682250B6CF8331B7EE68FD8");
  assertEqual(parts.prefix.length + parts.suffix.length, 40);
});

test("splitHibpDigest rejects anything that is not a SHA-1 hex digest", () => {
  assertThrows(() => PwGen.splitHibpDigest("nope"), "SHA-1");
  assertThrows(() => PwGen.splitHibpDigest("5BAA61E4"), "SHA-1");
});

test("countInRangeResponse finds the matching suffix", () => {
  const body = [
    "1E4C9B93F3F0682250B6CF8331B7EE68FD8:9659365",
    "0018A45C4D1DEF81644B54AB7F969B88D65:1",
    "malformed-line",
    ""
  ].join("\r\n");
  assertEqual(countOf(body, "1E4C9B93F3F0682250B6CF8331B7EE68FD8"), 9659365);
  assertEqual(countOf(body, "0018A45C4D1DEF81644B54AB7F969B88D65"), 1);
  assertEqual(countOf(body, "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"), 0);
});

function countOf(body, suffix) {
  return PwGen.countInRangeResponse(body, suffix);
}

/* ------------------------------------------------------------------ report */

if (failures.length) {
  console.error(`\n${failures.length} failing, ${passed} passing\n`);
  failures.forEach(({ name, err }) => {
    console.error(`  ✗ ${name}\n    ${err.message}`);
  });
  process.exit(1);
}

console.log(`${passed} passing`);
