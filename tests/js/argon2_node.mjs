/** Loads the vendored Argon2 WASM build the way vault.html's <script> tag does. */
import { createRequire } from "node:module";

const require = createRequire(import.meta.url);
globalThis.hashwasm = require("../../web/vendor/hash-wasm-argon2-4.13.0.umd.min.js");
