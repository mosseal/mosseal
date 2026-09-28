/**
 * Build the conformance wasm for the Node suite (spec 08).
 *
 * The conformance surface (`sealDeterministic` / `openWithTime`) is
 * feature-gated and baked with the FIXED test secrets from `vectors.json`
 * (never the consumer's). This script:
 *   1. reads `vectors.json` config (test secrets + domains),
 *   2. copies the shipped template to a temp dir,
 *   3. writes the generated `secrets.rs` with those test secrets,
 *   4. unpacks the vendored `mosseal-core` crate,
 *   5. runs `wasm-pack build --target nodejs --features conformance`.
 *
 * Output: `test/fixtures/conformance-wasm/` (gitignored). Idempotent: skips
 * the build when the output already exists unless `--force` is passed.
 */
import { spawnSync, execFileSync } from "node:child_process";
import {
  mkdtempSync,
  cpSync,
  mkdirSync,
  writeFileSync,
  readFileSync,
  readdirSync,
  rmSync,
  existsSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const HERE = dirname(fileURLToPath(import.meta.url));
const CORE_ROOT = resolve(HERE, "..");
const REPO_ROOT = resolve(CORE_ROOT, "..", "..");
const TEMPLATE_DIR = join(REPO_ROOT, "packages", "mosseal", "template");
const VECTORS = join(REPO_ROOT, "crates", "mosseal-vectors", "vectors.json");

/**
 * Fixture output dir per build variant (all gitignored):
 *  - node         → nodejs target + `conformance` feature (byte-exact vectors)
 *  - web-lenient  → web target, default lenient time mode (browser suite)
 *  - web-strict   → web target, `MOSSEAL_STRICT_TIME=true` (browser suite)
 *  - web-custom   → web target + a baked `MOSSEAL_TIME_SOURCES` override (N1)
 *
 * `MOSSEAL_STRICT_TIME` is a compile-time flag (spec 07), so the browser suite
 * needs a separate build per mode — the harness selects one via `?strict=1`.
 */
const FIXTURE_DIRS = {
  node: join(CORE_ROOT, "test", "fixtures", "conformance-wasm"),
  "web-lenient": join(CORE_ROOT, "test", "fixtures", "conformance-wasm-web"),
  "web-strict": join(CORE_ROOT, "test", "fixtures", "conformance-wasm-web-strict"),
  "web-custom": join(CORE_ROOT, "test", "fixtures", "conformance-wasm-web-custom"),
};

/** Custom time source baked into the `web-custom` fixture (N1, spec 07). */
export const CUSTOM_TIME_SOURCE = "https://custom-time.test/api";

/** Back-compat: the Node conformance suite's output dir. */
export function conformanceWasmDir() {
  return FIXTURE_DIRS.node;
}

/**
 * Build the conformance wasm.
 * @param {object} [opts]
 * @param {boolean} [opts.force]   rebuild even if the fixture already exists
 * @param {"nodejs"|"web"} [opts.target]
 * @param {boolean} [opts.strict]  web target only: build the strict-time variant
 * @param {"web-lenient"|"web-strict"|"web-custom"} [opts.variant]  explicit web variant
 * @param {string[]|null} [opts.timeSources]  bake a `MOSSEAL_TIME_SOURCES` override
 * @returns {string} the fixture output dir
 */
export function buildConformanceWasm({
  force = false,
  target = "nodejs",
  strict = false,
  variant,
  timeSources = null,
} = {}) {
  const key =
    variant ?? (target === "web" ? (strict ? "web-strict" : "web-lenient") : "node");
  const outDir = FIXTURE_DIRS[key];
  if (!force && existsSync(join(outDir, "mosseal_wasm.js"))) {
    return outDir;
  }

  const vectors = JSON.parse(readFileSync(VECTORS, "utf8"));
  const { secrets, domains } = vectors.config;

  const tmp = mkdtempSync(join(tmpdir(), "mosseal-conformance-"));
  try {
    cpSync(TEMPLATE_DIR, tmp, { recursive: true });

    // Generated secrets.rs with the FIXED test secrets (spec 08). An explicit
    // `timeSources` override is baked in for the N1 custom-source variant;
    // otherwise the literal is empty and the core defaults apply (spec 07).
    const timeSourcesLiteral = (timeSources ?? []).join(",");
    writeFileSync(
      join(tmp, "src", "secrets.rs"),
      `// GENERATED for conformance tests (spec 08) — test secrets only.\n` +
        `pub fn epochs_registry_str() -> String {\n` +
        `    obfuse::obfuse!("${secrets.join(";")}").as_str().to_string()\n` +
        `}\n` +
        `pub fn allowed_domains_str() -> String {\n` +
        `    obfuse::obfuse!("${domains.join(",")}").as_str().to_string()\n` +
        `}\n` +
        `pub fn time_sources_str() -> String {\n` +
        `    obfuse::obfuse!("${timeSourcesLiteral}").as_str().to_string()\n` +
        `}\n`,
      "utf8"
    );

    // Unpack the vendored mosseal-core crate.
    const crate = readdirSync(tmp).find((f) =>
      /^mosseal-core-\d+\.\d+\.\d+\.crate$/.test(f)
    );
    if (!crate) throw new Error("template is missing the vendored mosseal-core crate");
    execFileSync("tar", ["-xzf", crate], { cwd: tmp, stdio: "ignore" });

    mkdirSync(outDir, { recursive: true });
    const args = ["build", "--target", target, "--out-dir", outDir, "."];
    if (target === "nodejs") {
      // wasm-pack 0.13 forwards args after `--` to `cargo build`.
      args.push("--", "--features", "conformance");
    }
    const res = spawnSync("wasm-pack", args, {
      cwd: tmp,
      stdio: "inherit",
      // Strict time mode is a compile-time flag baked into mosseal-core
      // (spec 07); a fresh temp target dir per build means no stale artifact.
      env: strict ? { ...process.env, MOSSEAL_STRICT_TIME: "true" } : process.env,
    });
    if (res.status !== 0) {
      throw new Error(
        `wasm-pack conformance build failed (target=${target}, strict=${strict}, exit ${res.status})`
      );
    }
    return outDir;
  } finally {
    rmSync(tmp, { recursive: true, force: true });
  }
}

// Allow `node build-conformance-wasm.mjs [--force] [--web] [--strict]`.
if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const force = process.argv.includes("--force");
  const target = process.argv.includes("--web") ? "web" : "nodejs";
  const strict = process.argv.includes("--strict");
  const dir = buildConformanceWasm({ force, target, strict });
  console.log(`✔ conformance wasm (${target}${strict ? ", strict" : ""}) at ${dir}`);
}