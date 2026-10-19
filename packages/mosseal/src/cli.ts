/**
 * CLI dispatcher (spec 05 § Command surface).
 *
 *   mosseal init | build | rotate | doctor
 *   mosseal gen-secret | seal | open        (admin surface, spec 05)
 *   mosseal seal-multi | seal-deniable      (admin surface, v2)
 */
import { cmdInit, cmdRotate } from "./init.js";
import { cmdBuild } from "./build.js";
import { doctorReport, probeNetwork, probeToolchain } from "./toolchain.js";
import {
  cmdGenSecret,
  cmdOpen,
  cmdSeal,
  cmdSealDeniable,
  cmdSealMulti,
  type AdminOpts,
} from "./admin.js";
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
  mosseal seal-multi      Seal N password-keyed secrets into one MULTI link
  mosseal seal-deniable   Seal a cover link hiding a hidden layer (spec 09)
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
  --exp <unix-secs>       (seal/seal-multi) expiry; omit/0 = never expires
  --kind <token|binary-blob>  (seal) payload kind (default token)
  --ignore-expiry         (open) skip the expiry check (admin debugging)
  --slot <pw=secret>      (seal-multi/seal-deniable) repeatable slot
  --slots-file <path>     (seal-multi) JSON file with a slot array
  --hidden-slot <pw=secret>  (seal-deniable) repeatable hidden slot
  --hidden-slots-file <path>  (seal-deniable) JSON file with the hidden slots
  --cover-mode <hidden|plain>  (seal-deniable) cover keying (default hidden)
  --cover-password <pw>   (seal-deniable) cover password (prompts if hidden)
  --cover-decoy <bytes>   (seal-deniable) decoy content for the cover padding
  --hidden-password <pw>  (seal-deniable/open) locating password for the hidden layer
  --size-class <1|2|4>    (seal-deniable) total envelope size in KiB
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
    else if (a === "--slot") {
      (opts.admin.slots ??= []).push(args[++i]);
    }
    else if (a === "--hidden-slot") {
      (opts.admin.hiddenSlots ??= []).push(args[++i]);
    }
    else if (a === "--slots-file") opts.admin.slotsFile = args[++i];
    else if (a === "--hidden-slots-file") opts.admin.hiddenSlotsFile = args[++i];
    else if (a === "--cover-mode") opts.admin.coverMode = args[++i];
    else if (a === "--cover-password") opts.admin.coverPassword = args[++i];
    else if (a === "--cover-decoy") opts.admin.coverDecoy = args[++i];
    else if (a === "--hidden-password") opts.admin.hiddenPassword = args[++i];
    else if (a === "--size-class") {
      const raw = args[++i];
      if (raw !== "1" && raw !== "2" && raw !== "4") {
        throw new Error(
          `invalid value '${raw}' for '--size-class <CLASS>' [possible values: 1, 2, 4]`
        );
      }
      opts.admin.sizeClass = Number(raw);
    }
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
    case "seal-multi":
      return cmdSealMulti({ ...opts.admin, cwd: opts.cwd });
    case "seal-deniable": {
      // Parity with the native CLI: seal-deniable takes only the
      // --hidden-slot/--hidden-slots-file flags; a --slot here would be
      // silently dropped otherwise (a lost secret, not a typo warning).
      if ((opts.admin.slots?.length ?? 0) > 0 || opts.admin.slotsFile !== undefined) {
        throw new Error(
          "seal-deniable takes --hidden-slot/--hidden-slots-file, not --slot/--slots-file"
        );
      }
      return cmdSealDeniable({
        ...opts.admin,
        cwd: opts.cwd,
        slots: opts.admin.hiddenSlots,
        slotsFile: opts.admin.hiddenSlotsFile,
      });
    }
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
