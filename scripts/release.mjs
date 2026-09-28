#!/usr/bin/env node
/**
 * Release automation (spec 06, docs/versioning.md).
 *
 * The manual 6-step release checklist is error-prone: three manifests must move
 * in lockstep, the vendored `mosseal-core` crate is a derived artifact, and
 * `vectors.json` is a checked-in artifact with a CI drift tripwire. This script
 * does the mechanical parts and refuses to run if anything is already inconsistent.
 *
 * Usage:
 *   node scripts/release.mjs --version 0.2.0        # bump + regenerate
 *   node scripts/release.mjs --version 0.2.0 --dry-run
 *   node scripts/release.mjs --check                # verify consistency only
 *
 * What it does (the parts a script can do safely):
 *   1. Bump the version in lockstep:
 *        - root Cargo.toml `[workspace.package] version`
 *        - packages/core/package.json
 *        - packages/mosseal/package.json
 *        - packages/mosseal/template/Cargo.toml (its own version + the vendored
 *          `mosseal-core-<ver>` path dependency)
 *   2. Regenerate `crates/mosseal-vectors/vectors.json`.
 *   3. Re-package `mosseal-core` and refresh the vendored
 *      `packages/mosseal/template/mosseal-core-<ver>.crate` (via
 *      `scripts/sync-core-crate.mjs`; the crate is a derived artifact and is
 *      NOT committed — it is also regenerated at `npm pack` time).
 *
 * What it deliberately does NOT do (manual judgement required):
 *   - Write the CHANGELOG entry (release notes are prose).
 *   - Bump the envelope `version` byte (only on a wire-format change, spec 01).
 *   - Commit, tag, or publish.
 */
import { execFileSync } from "node:child_process";
import { readFileSync, writeFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const HERE = dirname(fileURLToPath(import.meta.url));
const ROOT = resolve(HERE, "..");

const PATHS = {
  rootCargo: join(ROOT, "Cargo.toml"),
  corePkg: join(ROOT, "packages", "core", "package.json"),
  cliPkg: join(ROOT, "packages", "mosseal", "package.json"),
  templateCargo: join(ROOT, "packages", "mosseal", "template", "Cargo.toml"),
};

const SEMVER_RE = /^\d+\.\d+\.\d+(-[0-9A-Za-z.-]+)?$/;

/** Extract a `version = "x.y.z"` from a Cargo section. */
function cargoSectionVersion(content, section) {
  const header = `[${section}]`;
  const start = content.indexOf(header);
  if (start === -1) throw new Error(`Cargo section ${header} not found`);
  const rest = content.slice(start + header.length);
  const m = /^version\s*=\s*"([^"]+)"/m.exec(rest);
  if (!m) throw new Error(`no version key in ${header}`);
  return m[1];
}

/** Replace the `version = "..."` inside a Cargo section. */
function setCargoSectionVersion(content, section, version) {
  const header = `[${section}]`;
  const start = content.indexOf(header);
  if (start === -1) throw new Error(`Cargo section ${header} not found`);
  const before = content.slice(0, start + header.length);
  const after = content.slice(start + header.length);
  const next = after.replace(/^(version\s*=\s*")[^"]+(")/m, `$1${version}$2`);
  if (next === after) throw new Error(`no version key to replace in ${header}`);
  return before + next;
}

function readJson(p) {
  return JSON.parse(readFileSync(p, "utf8"));
}

function writeJson(p, obj) {
  writeFileSync(p, JSON.stringify(obj, null, 2) + "\n", "utf8");
}

/** Collect the current versions from every manifest. */
function readVersions() {
  const rootCargo = readFileSync(PATHS.rootCargo, "utf8");
  const templateCargo = readFileSync(PATHS.templateCargo, "utf8");
  return {
    cargoWorkspace: cargoSectionVersion(rootCargo, "workspace.package"),
    corePkg: readJson(PATHS.corePkg).version,
    cliPkg: readJson(PATHS.cliPkg).version,
    templateCargo: cargoSectionVersion(templateCargo, "package"),
    vendoredPath: /path\s*=\s*"\.\/mosseal-core-([^"]+)"/.exec(templateCargo)?.[1],
  };
}

/** Fail unless every manifest agrees on one version. */
function checkConsistency() {
  const v = readVersions();
  const values = [
    v.cargoWorkspace,
    v.corePkg,
    v.cliPkg,
    v.templateCargo,
    v.vendoredPath,
  ];
  const unique = [...new Set(values)];
  if (unique.length !== 1) {
    throw new Error(
      `version mismatch across manifests:\n` +
        `  Cargo [workspace.package]   ${v.cargoWorkspace}\n` +
        `  packages/core/package.json  ${v.corePkg}\n` +
        `  packages/mosseal/package.json ${v.cliPkg}\n` +
        `  template [package]          ${v.templateCargo}\n` +
        `  template vendored path      ${v.vendoredPath}\n` +
        `Run \`node scripts/release.mjs --version <X.Y.Z>\` to fix.`
    );
  }
  return unique[0];
}

function bump(version, dryRun) {
  const rootCargo = readFileSync(PATHS.rootCargo, "utf8");
  const templateCargo = readFileSync(PATHS.templateCargo, "utf8");

  let nextRoot = setCargoSectionVersion(rootCargo, "workspace.package", version);
  let nextTemplate = setCargoSectionVersion(templateCargo, "package", version);
  // The vendored crate path encodes the version: ./mosseal-core-<ver>.
  nextTemplate = nextTemplate.replace(
    /(path\s*=\s*"\.\/mosseal-core-)[^"]+(")/,
    `$1${version}$2`
  );

  const corePkg = readJson(PATHS.corePkg);
  const cliPkg = readJson(PATHS.cliPkg);
  corePkg.version = version;
  cliPkg.version = version;

  if (dryRun) {
    console.log(`dry-run: would bump all manifests to ${version}`);
    return;
  }
  writeFileSync(PATHS.rootCargo, nextRoot, "utf8");
  writeFileSync(PATHS.templateCargo, nextTemplate, "utf8");
  writeJson(PATHS.corePkg, corePkg);
  writeJson(PATHS.cliPkg, cliPkg);
  console.log(`✔ bumped manifests to ${version}`);
}

function run(cmd, args) {
  console.log(`  $ ${cmd} ${args.join(" ")}`);
  execFileSync(cmd, args, { cwd: ROOT, stdio: "inherit" });
}

function regenerateArtifacts(dryRun) {
  if (dryRun) {
    console.log("dry-run: would regenerate vectors.json + the vendored crate");
    return;
  }
  // 1. vectors.json — the drift tripwire fails CI if this is stale.
  console.log("regenerating vectors.json …");
  run("cargo", ["run", "-p", "mosseal-vectors"]);

  // 2. vendored mosseal-core crate (a derived artifact; not committed).
  //    Delegated to sync-core-crate.mjs so there is a single implementation.
  console.log("re-packaging mosseal-core …");
  run("node", [join(HERE, "sync-core-crate.mjs")]);
}

function main() {
  const argv = process.argv.slice(2);
  const check = argv.includes("--check");
  const dryRun = argv.includes("--dry-run");
  const vi = argv.indexOf("--version");
  const version = vi === -1 ? null : argv[vi + 1];

  if (check) {
    const v = checkConsistency();
    console.log(`✔ all manifests agree on ${v}`);
    return;
  }

  if (!version) {
    console.error(
      "usage: node scripts/release.mjs --version <X.Y.Z> [--dry-run]\n" +
        "       node scripts/release.mjs --check"
    );
    process.exitCode = 2;
    return;
  }
  if (!SEMVER_RE.test(version)) {
    throw new Error(`not a semver version: ${version}`);
  }

  // Refuse to start from an inconsistent state — that hides earlier mistakes.
  const current = checkConsistency();
  console.log(`current version: ${current} → ${version}`);
  if (current === version) {
    console.log("already at that version; nothing to bump (regenerating artifacts)");
  } else {
    bump(version, dryRun);
  }
  regenerateArtifacts(dryRun);

  if (!dryRun) {
    console.log(
      "\nNext steps (manual — see docs/versioning.md):\n" +
        `  1. Add a CHANGELOG.md entry under [${version}].\n` +
        `  2. If the envelope layout changed, bump the version byte (spec 01).\n` +
        `  3. Review the regenerated vectors.json + vendored crate diff.\n` +
        `  4. Commit, tag v${version}, and publish both npm packages.`
    );
  }
}

main();
