#!/usr/bin/env node
/**
 * Sync the vendored `mosseal-core` crate (spec 05/06).
 *
 * `packages/mosseal/template/mosseal-core-<ver>.crate` is a packaged snapshot of
 * `crates/mosseal-core`, shipped inside the `mosseal` npm package so the CLI can
 * compile the template without publishing `mosseal-core` to crates.io.
 *
 * It is a DERIVED artifact and is deliberately NOT committed (see .gitignore).
 * It is regenerated:
 *   - automatically by `npm pack` / `npm publish` (the `prepack` script),
 *   - automatically by the conformance-wasm builder when it is missing
 *     (`packages/core/test/build-conformance-wasm.mjs`), and
 *   - on demand via `npm run sync:core`.
 *
 * Because it is generated on demand, it can never drift from
 * `crates/mosseal-core` — there is no manual refresh step.
 *
 * Usage:
 *   node scripts/sync-core-crate.mjs           # regenerate the vendored crate
 *   node scripts/sync-core-crate.mjs --check   # verify it exists at the right version
 */
import { execFileSync } from "node:child_process";
import { copyFileSync, existsSync, readdirSync, readFileSync, rmSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const HERE = dirname(fileURLToPath(import.meta.url));
const ROOT = resolve(HERE, "..");
const TEMPLATE_DIR = join(ROOT, "packages", "mosseal", "template");
const CRATE_RE = /^mosseal-core-\d+\.\d+\.\d+\.crate$/;

/** Read `[workspace.package] version` from the root Cargo.toml. */
export function workspaceVersion() {
  const content = readFileSync(join(ROOT, "Cargo.toml"), "utf8");
  const header = "[workspace.package]";
  const start = content.indexOf(header);
  if (start === -1) throw new Error(`Cargo section ${header} not found`);
  const m = /^version\s*=\s*"([^"]+)"/m.exec(content.slice(start + header.length));
  if (!m) throw new Error(`no version key in ${header}`);
  return m[1];
}

/** True when the template already holds a vendored crate at the current version. */
export function hasVendoredCrate() {
  const expected = `mosseal-core-${workspaceVersion()}.crate`;
  return readdirSync(TEMPLATE_DIR).includes(expected);
}

/**
 * Regenerate the vendored crate from `crates/mosseal-core`.
 * @param {object} [opts]
 * @param {boolean} [opts.check]  verify presence instead of regenerating
 */
export function syncCoreCrate({ check = false } = {}) {
  const version = workspaceVersion();
  const expected = `mosseal-core-${version}.crate`;
  const dest = join(TEMPLATE_DIR, expected);

  if (check) {
    if (!existsSync(dest)) {
      throw new Error(
        `vendored crate ${expected} is missing — run \`npm run sync:core\` ` +
          `(it is generated on demand and not committed)`
      );
    }
    console.log(`✔ vendored crate present: ${expected}`);
    return;
  }

  console.log(`packaging mosseal-core ${version} …`);
  execFileSync(
    "cargo",
    ["package", "-p", "mosseal-core", "--allow-dirty", "--no-verify"],
    { cwd: ROOT, stdio: "inherit" }
  );

  const packaged = join(ROOT, "target", "package", expected);
  if (!existsSync(packaged)) {
    throw new Error(`expected packaged crate at ${packaged}`);
  }

  // Drop any stale crate from a previous version so the template ships exactly one.
  for (const f of readdirSync(TEMPLATE_DIR)) {
    if (CRATE_RE.test(f) && f !== expected) {
      rmSync(join(TEMPLATE_DIR, f));
      console.log(`  removed stale ${f}`);
    }
  }

  copyFileSync(packaged, dest);
  console.log(`✔ vendored ${expected} → packages/mosseal/template/`);
}

// Run as a CLI only when invoked directly (not when imported).
if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  syncCoreCrate({ check: process.argv.includes("--check") });
}
