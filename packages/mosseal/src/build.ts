/**
 * `mosseal build` (spec 05 § build flow).
 *
 * 1. Pre-validate env (fail fast — `env!()` errors are cryptic).
 * 2. Resolve toolchain (actionable failure + `mosseal doctor` hint).
 * 3. Copy the pinned Rust template to a temp dir, write generated
 *    `secrets.rs` (obfuse literals), spawn
 *    `wasm-pack build --target bundler` (single target).
 * 4. Emit `mosseal-out/meta.json` (provenance, no secrets).
 * 5. Exit non-zero on any failure, passing wasm-pack output through.
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
import { validateEnv, configFingerprint } from "./env.js";
import { generateSecretsRs, generateMetaJson } from "./codegen.js";
import { assertToolchain } from "./toolchain.js";
import { loadEnvFile } from "./dotenv.js";

/**
 * Package root. The bundled entry is `dist/mosseal.js`, so `import.meta.url`
 * points into `dist/`; the parent is the package root that holds `template/`
 * and `package.json`.
 */
const PKG_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const TEMPLATE_DIR = join(PKG_ROOT, "template");

export interface BuildOpts {
  cwd?: string;
  dryRun?: boolean;
  outDir?: string;
}

export async function cmdBuild(
  opts: BuildOpts = {}
): Promise<{ ok: true; dryRun?: boolean; outDir?: string }> {
  const cwd = resolve(opts.cwd ?? process.cwd());
  const outDir = resolve(opts.outDir ?? join(cwd, "mosseal-out"));
  const dryRun = opts.dryRun ?? false;

  // 1. Pre-validate env (load .env into process.env non-destructively;
  //    real environment wins over .env values)
  loadEnvFile(join(cwd, ".env"));

  const { config, warnings } = validateEnv(process.env);
  for (const w of warnings) console.warn(`⚠ ${w}`);
  const activeEpochs = config.secrets.filter((s) => s !== null).length;
  const retired = config.secrets.length - activeEpochs;
  console.log(
    `✔ env ok: ${activeEpochs} active epoch(s)` +
      (retired > 0 ? ` (+${retired} retired)` : "") +
      `, ${config.domains.length} domain(s), argon=${config.argonProfile}, ` +
      `time=${config.strictTime ? "strict" : "lenient"}`
  );

  if (dryRun) {
    console.log("dry-run: validation passed, skipping wasm-pack build");
    return { ok: true, dryRun: true };
  }

  // 2. Toolchain
  assertToolchain();

  // 3. Template copy + codegen + wasm-pack
  const tmp = mkdtempSync(join(tmpdir(), "mosseal-build-"));
  try {
    cpSync(TEMPLATE_DIR, tmp, { recursive: true });
    writeFileSync(join(tmp, "src", "secrets.rs"), generateSecretsRs(config), "utf8");

    // Unpack the vendored mosseal-core .crate (spec 05: template ships the
    // pinned Rust source; core is vendored so the template is self-contained).
    unpackCoreCrate(tmp);

    mkdirSync(outDir, { recursive: true });
    const res = spawnSync(
      "wasm-pack",
      ["build", "--target", "bundler", "--out-dir", outDir, "."],
      {
        cwd: tmp,
        stdio: "inherit", // pass wasm-pack output through (spec 05 step 5)
        env: {
          ...process.env,
          // Defense in depth: even though secrets flow through codegen,
          // never leak the raw env into the child beyond what's needed.
          MOSSEAL_SECRET_0: undefined,
        },
      }
    );
    if (res.status !== 0) {
      throw new Error(
        `wasm-pack build failed (exit ${res.status ?? "signal"}). ` +
          "Output above; run `mosseal doctor` if tools are missing."
      );
    }

    // 4. meta.json provenance (no secrets)
    const fingerprint = configFingerprint(config);
    writeFileSync(
      join(outDir, "meta.json"),
      generateMetaJson(config, fingerprint, version()),
      "utf8"
    );
    console.log(`✔ build complete → ${outDir}`);
    return { ok: true, outDir };
  } finally {
    rmSync(tmp, { recursive: true, force: true });
  }
}

function version(): string {
  try {
    return (
      JSON.parse(readFileSync(join(PKG_ROOT, "package.json"), "utf8")).version ?? "0.0.0"
    );
  } catch {
    return "0.0.0";
  }
}

/**
 * Unpack the vendored `mosseal_core-<ver>.crate` into the template copy so
 * `path = "./mosseal-core-<ver>"` in the template Cargo.toml resolves.
 * .crate files are gzipped tarballs.
 */
function unpackCoreCrate(templateDir: string): void {
  const crate = readdirSync(templateDir).find((f) =>
    /^mosseal-core-\d+\.\d+\.\d+\.crate$/.test(f)
  );
  if (!crate) {
    throw new Error(
      "template is missing the vendored mosseal_core-*.crate file — package is corrupt"
    );
  }
  const ver = crate.replace(/\.crate$/, "");
  execFileSync("tar", ["-xzf", crate], { cwd: templateDir, stdio: "ignore" });
  if (!existsSync(join(templateDir, ver, "Cargo.toml"))) {
    throw new Error(`failed to unpack vendored ${crate}`);
  }
}
