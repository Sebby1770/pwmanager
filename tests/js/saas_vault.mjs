/**
 * Sync-ordering rules for the web vault (audit finding F7).
 *   node tests/js/saas_vault.mjs
 */
import assert from "node:assert/strict";
import { pickNewer, savedAt } from "../../web/saas/vault.js";

assert.equal(savedAt({ saved_at: 5 }), 5);
assert.equal(savedAt({}), 0);
assert.equal(savedAt(null), 0);
assert.equal(savedAt({ saved_at: "2026-01-01T00:00:00Z" }), 0, "ISO strings are not timestamps");
assert.equal(pickNewer({ saved_at: 1 }, { saved_at: 2 }), "remote");
assert.equal(pickNewer({ saved_at: 2 }, { saved_at: 1 }), "local", "an older (replayed) cloud copy loses");
assert.equal(pickNewer({}, { saved_at: 1 }), "remote");
assert.equal(pickNewer({ saved_at: 1 }, {}), "local", "a legacy cloud copy cannot roll back a stamped local one");
assert.equal(pickNewer({}, {}), "remote", "legacy on both sides: prefer the cloud, as before");
console.log("saas vault sync ordering ok");
