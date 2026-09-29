/**
 * CLI dispatcher (spec 05 § Command surface).
 *
 *   mosseal init | build | rotate | doctor
 *   mosseal gen-secret | seal | open        (admin surface, spec 05)
 */
import { cmdInit, cmdRotate } from "./init.js";
import { cmdBuild } from "./build.js";
import { doctorReport, probeNetwork, probeToolchain } from "./toolchain.js";
import { cmdGenSecret, cmdOpen, cmdSeal, type AdminOpts } from "./admin.js";
import { version } from "./version.js";

const USAGE = `mosseal — compile-time-injection builder for MOSSEAL (spec 05)

Usage:
  mosseal init            Scaffold .env with a fresh MOSSEAL_SECRET_0
  mosseal build           Validate env → generate secrets.rs → wasm-pack → ./mosseal-out/
  mosseal rotate          Append MOSSEAL_SECRET_<N+1> (keeps old epochs for grace)
  mosseal doctor          Check node/cargo/rustc/wasm-pack/wasm32-target

Admin commands (trusted path; no Rust toolchain required):
  mosseal gen-secret      Print a fresh 32-byte base64url epoch secret
  mosseal seal <token>    Seal a token into a share-link fragment
  mosseal open <fragment> Open and verify a fragment

Flags:
  --dry-run               Validate/plan without writing files or building
  --cwd <dir>             Run in a different directory
  --out-dir <dir>         (build) override output dir (default ./mosseal-out)
  --network               (doctor) also probe time-source reachability
  -V, --version           Print version
  -h, --help              Print this help

Admin flags:
  --epochs <s;e;c>        Epoch secrets, base64url, ';'-joined (or MOSSEAL_EPOCHS)
  --domains <a,b>         Allowed hostnames, comma-separated (or MOSSEAL_ALLOWED_DOMAINS)
  --password <pw>         Password (bare --password prompts on a TTY)
  --exp <unix-secs>       (seal) expiry; omit/0 = never expires
  --kind <token|binary-blob>  (seal) payload kind (default token)
  --ignore-expiry         (open) skip the expiry check (admin debugging)
`;

export interface CliOpts {
  cwd: string;
  dryRun: boolean;
  outDir?: string;
  network?: boolean;
  admin: AdminOpts;
}

export async function run(argv: string[]): Promise<unknown> {
  const args = [...argv];
  const opts: CliOpts = { cwd: process.cwd(), dryRun: false, admin: {} };
  const positional: string[] = [];

  for (let i = 0; i < args.length; i++) {
    const a = args[i];
    if (a === "--dry-run") opts.dryRun = true;
    else if (a === "--network") opts.network = true;
    else if (a === "--cwd") opts.cwd = args[++i];
    else if (a === "--out-dir") opts.outDir = args[++i];
    else if (a === "--epochs") opts.admin.epochs = args[++i];
    else if (a === "--domains") opts.admin.domains = args[++i];
    else if (a === "--password") {
      // Optional value: `--password <pw>` uses the value; a bare `--password`
      // (last arg, or followed by another flag) prompts on the TTY.
      const next = args[i + 1];
      if (next === undefined || next.startsWith("-")) opts.admin.passwordPrompt = true;
      else opts.admin.password = args[++i];
    }
    else if (a === "--exp") {
      const raw = args[++i];
      // Mirror clap's `u64` parse: reject non-integers and negatives rather
      // than silently coercing to NaN (which would drop the expiry).
      if (raw === undefined || !/^\d+$/.test(raw)) {
        throw new Error(
          `invalid value '${raw}' for '--exp <EXP>': expected a non-negative integer`
        );
      }
      opts.admin.exp = Number(raw);
    }
    else if (a === "--kind") opts.admin.kind = args[++i];
    else if (a === "--ignore-expiry") opts.admin.ignoreExpiry = true;
    else if (a === "-V" || a === "--version") {
      console.log(`mosseal ${version()}`);
      return;
    }
    else if (a === "-h" || a === "--help") {
      console.log(USAGE);
      return;
    } else positional.push(a);
  }

  const [cmd, arg] = positional;
  switch (cmd) {
    case "init":
      return cmdInit(opts);
    case "build":
      return cmdBuild(opts);
    case "rotate":
      return cmdRotate(opts);
    case "doctor": {
      const probe = probeToolchain();
      if (opts.network) probe.network = await probeNetwork();
      const report = doctorReport(probe);
      for (const line of report.lines) console.log(line);
      if (!report.ok) process.exitCode = 1;
      return;
    }
    case "gen-secret":
      return cmdGenSecret();
    case "seal":
      return cmdSeal(arg, { ...opts.admin, cwd: opts.cwd });
    case "open":
      if (!arg) throw new Error(`open requires a <fragment> argument\n\n${USAGE}`);
      return cmdOpen(arg, { ...opts.admin, cwd: opts.cwd });
    case undefined:
      console.log(USAGE);
      return;
    default:
      throw new Error(`Unknown command: ${cmd}\n\n${USAGE}`);
  }
}
