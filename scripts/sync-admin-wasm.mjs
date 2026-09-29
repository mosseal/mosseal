#!/usr/bin/env node
/**
 * Build + vendor the admin wasm for the `mosseal` TS CLI (spec 05).
 *
 * `npx mosseal gen-secret|seal|open` runs the SAME crypto as the native
 * `mosseal-cli` binary, but without requiring a Rust toolchain on the
 * consumer's machine. To make that possible, a precompiled admin wasm module
 * (`crates/mosseal-admin-wasm`) is shipped inside the `@mosseal/cli` npm
 * package under `packages/mosseal/vendor/admin-wasm/`.
 *
 * The artifact is a DERIVED build output and is deliberately NOT committed
 * (see .gitignore). It is regenerated:
 *   - by the CI publish job before `npm publish`,
 *   - automatically by `npm pack` / `npm publish` (the `prepack` script), and
 *   - on demand via `npm run sync:admin-wasm`.
 *
 * Because it is generated on demand it can never drift from
 * `crates/mosseal-admin-wasm` — there is no manual refresh step.
 *
 * Usage:
 *   node scripts/sync-admin-wasm.mjs           # build + vendor the admin wasm
 *   node scripts/sync-admin-wasm.mjs --check   # verify the vendored artifact exists
 */
import { execFileSync } from "node:child_process";
import { existsSync, readdirSync, renameSync, rmSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const HERE = dirname(fileURLToPath(import.meta.url));
const ROOT = resolve(HERE, "..");
const CRATE_DIR = join(ROOT, "crates", "mosseal-admin-wasm");
const VENDOR_DIR = join(ROOT, "packages", "mosseal", "vendor", "admin-wasm");

/**
 * Files we ship. The wasm-bindgen `--target nodejs` glue is CommonJS, but the
 * `@mosseal/cli` package is `"type": "module"`, so a `.js` glue would be
 * parsed as ESM and fail on `exports`. Renaming it to `.cjs` keeps it CJS.
 */
const GLUE_SRC = "mosseal_admin_wasm.js";
const GLUE_DST = "mosseal_admin_wasm.cjs";
const WASM = "mosseal_admin_wasm_bg.wasm";
const REQUIRED = [GLUE_DST, WASM];

/** True when the vendored admin wasm is present. */
export function hasVendoredAdminWasm() {
  return REQUIRED.every((f) => existsSync(join(VENDOR_DIR, f)));
}

/**
 * Build the admin wasm and copy it into the CLI package's `vendor/` dir.
 * @param {object} [opts]
 * @param {boolean} [opts.check]  verify presence instead of building
 */
export function syncAdminWasm({ check = false } = {}) {
  if (check) {
    if (!hasVendoredAdminWasm()) {
      throw new Error(
        `vendored admin wasm is missing from ${VENDOR_DIR} — run ` +
          `\`npm run sync:admin-wasm\` (it is generated on demand and not committed)`
      );
    }
    console.log("✔ vendored admin wasm present");
    return;
  }

  console.log("building mosseal-admin-wasm (wasm-pack --target nodejs) …");
  // Fresh output dir so a stale artifact can never linger.
  rmSync(VENDOR_DIR, { recursive: true, force: true });
  execFileSync(
    "wasm-pack",
    ["build", "--target", "nodejs", "--release", "--out-dir", VENDOR_DIR, "."],
    { cwd: CRATE_DIR, stdio: "inherit" }
  );

  const missing = [GLUE_SRC, WASM].filter((f) => !existsSync(join(VENDOR_DIR, f)));
  if (missing.length > 0) {
    throw new Error(`wasm-pack did not emit: ${missing.join(", ")}`);
  }

  // Rename the CJS glue to `.cjs` (see GLUE_DST note above).
  renameSync(join(VENDOR_DIR, GLUE_SRC), join(VENDOR_DIR, GLUE_DST));

  // Drop wasm-pack's package.json / .d.ts / README so the npm tarball ships
  // only the two runtime files (the CLI loads the glue via createRequire).
  for (const f of readdirSync(VENDOR_DIR)) {
    if (!REQUIRED.includes(f)) {
      rmSync(join(VENDOR_DIR, f), { recursive: true, force: true });
    }
  }

  console.log(`✔ vendored admin wasm → packages/mosseal/vendor/admin-wasm/`);
}

// Run as a CLI only when invoked directly (not when imported).
if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  syncAdminWasm({ check: process.argv.includes("--check") });
}
