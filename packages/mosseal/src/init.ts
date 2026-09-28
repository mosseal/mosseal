/**
 * `mosseal init` and `mosseal rotate` (spec 05).
 *
 * init:    generate MOSSEAL_SECRET_0, merge .env non-destructively, warn
 *          loudly if .env is not gitignored (the #1 footgun).
 * rotate:  append MOSSEAL_SECRET_<N+1> past the highest slot (retired holes are
 *          preserved, never renumbered), print grace-window removal
 *          instructions (removal = EPOCH_RETIRED).
 */
import { randomBytes } from "node:crypto";
import { writeFileSync } from "node:fs";
import { join, resolve } from "node:path";
import { mergeDotenv, isGitIgnored, loadEnvFile } from "./dotenv.js";
import { validateEnv } from "./env.js";

export interface InitOpts {
  cwd?: string;
  dryRun?: boolean;
}

function b64url32(): string {
  return randomBytes(32).toString("base64url");
}

function envPath(cwd?: string): string {
  return join(resolve(cwd ?? process.cwd()), ".env");
}

export function cmdInit(opts: InitOpts = {}): { ok: true } {
  const cwd = resolve(opts.cwd ?? process.cwd());
  const ePath = envPath(cwd);
  const secret = b64url32();

  const merge = mergeDotenv(ePath, [["MOSSEAL_SECRET_0", secret]]);

  if (merge.skipped.includes("MOSSEAL_SECRET_0")) {
    console.log("✔ MOSSEAL_SECRET_0 already exists in .env — left untouched.");
  } else if (opts.dryRun) {
    console.log(`dry-run: would append MOSSEAL_SECRET_0 to ${ePath}`);
  } else {
    writeFileSync(ePath, merge.text!, "utf8");
    console.log(`✔ wrote MOSSEAL_SECRET_0 to ${ePath}`);
  }

  // Loud gitignore warning (spec 05: the #1 footgun for this model)
  const ignored = isGitIgnored(ePath, cwd);
  if (ignored === false) {
    console.warn(
      "⚠ DANGER: .env is NOT gitignored. Epoch secrets are the keys to every\n" +
        "  link your app seals. Add `.env` to .gitignore BEFORE committing.\n" +
        "  If it was ever committed, rotate ALL epochs and purge history."
    );
  } else if (ignored === null) {
    console.warn(
      "⚠ Could not verify .env is gitignored (no git repo or .gitignore found).\n" +
        "  Confirm manually: git check-ignore .env"
    );
  } else {
    console.log("✔ .env is gitignored.");
  }

  console.log(`
Next steps:
  1. Add your deployment hostnames to .env:
       MOSSEAL_ALLOWED_DOMAINS=your-site.github.io
  2. Optional:
       MOSSEAL_STRICT_TIME=false        # strict = fail open() without net time
       MOSSEAL_ARGON2_PROFILE=minimum   # or "interactive" (47 MiB)
  3. Build the per-consumer wasm:
       mosseal build                    # emits ./mosseal-out/
  4. Add "prebuild": "mosseal build" to package.json scripts.
`);
  return { ok: true };
}

export function cmdRotate(opts: InitOpts = {}): { ok: true; epoch: number } {
  const cwd = resolve(opts.cwd ?? process.cwd());
  const ePath = envPath(cwd);

  // Load current env to determine the next epoch index.
  loadEnvFile(ePath);

  const { config } = validateEnv(process.env);
  // Slot count = highest epoch index + 1 (trailing holes are trimmed), so the
  // next epoch is one past the highest slot. Retired holes below it are
  // preserved — they keep their index (spec 02 § Key epochs).
  const next = config.secrets.length;
  const secret = b64url32();

  const merge = mergeDotenv(ePath, [[`MOSSEAL_SECRET_${next}`, secret]]);
  if (merge.skipped.length > 0) {
    throw new Error(`MOSSEAL_SECRET_${next} already exists — refusing to overwrite.`);
  }

  if (opts.dryRun) {
    console.log(`dry-run: would append MOSSEAL_SECRET_${next} to ${ePath}`);
    return { ok: true, epoch: next };
  }
  writeFileSync(ePath, merge.text!, "utf8");

  console.log(`✔ appended MOSSEAL_SECRET_${next} (now sealing with epoch ${next}).`);
  console.log(`
Rotation notes (spec 02 § Key epochs):
  • Links sealed under epochs 0..${next - 1} keep opening during the grace window.
  • The actual invalidation event is RETIRING an old epoch: delete its
    MOSSEAL_SECRET_<n> line from .env. open() then fails with EPOCH_RETIRED
    for links sealed under it, while every other epoch keeps opening.
  • Retiring an epoch leaves a HOLE in the list — that is expected. Do NOT
    renumber the remaining secrets: epoch indices are positional, so
    renumbering would silently re-key every surviving link.
  • After your grace period (e.g. 30 days), delete the oldest epoch line.
    You may retire epochs in any order; each hole is independent.
`);
  return { ok: true, epoch: next };
}
