/**
 * CLI dispatcher (spec 05 § Command surface).
 *
 *   mosseal init | build | rotate | doctor
 */
import { cmdInit, cmdRotate } from "./init.js";
import { cmdBuild } from "./build.js";
import { doctorReport, probeNetwork, probeToolchain } from "./toolchain.js";

const USAGE = `mosseal — compile-time-injection builder for MOSSEAL (spec 05)

Usage:
  mosseal init            Scaffold .env with a fresh MOSSEAL_SECRET_0
  mosseal build           Validate env → generate secrets.rs → wasm-pack → ./mosseal-out/
  mosseal rotate          Append MOSSEAL_SECRET_<N+1> (keeps old epochs for grace)
  mosseal doctor          Check node/cargo/rustc/wasm-pack/wasm32-target

Flags:
  --dry-run               Validate/plan without writing files or building
  --cwd <dir>             Run in a different directory
  --out-dir <dir>         (build) override output dir (default ./mosseal-out)
  --network               (doctor) also probe time-source reachability
`;

export interface CliOpts {
  cwd: string;
  dryRun: boolean;
  outDir?: string;
  network?: boolean;
}

export async function run(argv: string[]): Promise<unknown> {
  const args = [...argv];
  const opts: CliOpts = { cwd: process.cwd(), dryRun: false };
  const positional: string[] = [];

  for (let i = 0; i < args.length; i++) {
    const a = args[i];
    if (a === "--dry-run") opts.dryRun = true;
    else if (a === "--network") opts.network = true;
    else if (a === "--cwd") opts.cwd = args[++i];
    else if (a === "--out-dir") opts.outDir = args[++i];
    else if (a === "-h" || a === "--help") {
      console.log(USAGE);
      return;
    } else positional.push(a);
  }

  const [cmd] = positional;
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
    case undefined:
      console.log(USAGE);
      return;
    default:
      throw new Error(`Unknown command: ${cmd}\n\n${USAGE}`);
  }
}
