/**
 * Toolchain resolution + `mosseal doctor` checks (spec 05 § doctor).
 * Fail fast with actionable messages + links before wasm-pack runs.
 */
import { execFileSync } from "node:child_process";

interface RunResult {
  ok: boolean;
  out: string;
  err?: unknown;
}

function run(cmd: string, args: string[]): RunResult {
  try {
    return {
      ok: true,
      out: execFileSync(cmd, args, {
        encoding: "utf8",
        stdio: ["ignore", "pipe", "pipe"],
      }).trim(),
    };
  } catch (err) {
    const e = err as { stdout?: { toString?: () => string } };
    return { ok: false, out: e?.stdout?.toString?.() ?? "", err };
  }
}

function firstLine(s: string): string {
  return s.split(/\r?\n/)[0] ?? "";
}

export interface ToolchainItem {
  ok: boolean;
  version?: string | null;
  required?: string;
}

export interface ToolchainProbe {
  node: ToolchainItem;
  cargo: ToolchainItem;
  rustc: ToolchainItem;
  wasmPack: ToolchainItem;
  wasmTarget: ToolchainItem;
}

export interface DoctorReport {
  ok: boolean;
  lines: string[];
}

/**
 * Probe the local toolchain. Never throws; returns a structured report.
 */
export function probeToolchain(): ToolchainProbe {
  const nodeMajor = Number(process.versions.node.split(".")[0]);
  const nodeOk = nodeMajor >= 20;

  const cargo = run("cargo", ["--version"]);
  const rustc = run("rustc", ["--version"]);
  const wasmPack = run("wasm-pack", ["--version"]);
  const rustup = run("rustup", ["target", "list", "--installed"]);
  const wasmTargetOk =
    rustup.ok && rustup.out.split(/\r?\n/).some((l) => l.trim() === "wasm32-unknown-unknown");

  return {
    node: { ok: nodeOk, version: process.version, required: ">=20" },
    cargo: { ok: cargo.ok, version: cargo.ok ? firstLine(cargo.out) : null },
    rustc: { ok: rustc.ok, version: rustc.ok ? firstLine(rustc.out) : null },
    wasmPack: { ok: wasmPack.ok, version: wasmPack.ok ? firstLine(wasmPack.out) : null },
    wasmTarget: { ok: wasmTargetOk },
  };
}

/**
 * Human-readable doctor report. Returns { ok, lines }.
 */
export function doctorReport(probe: ToolchainProbe = probeToolchain()): DoctorReport {
  const lines: string[] = [];
  let ok = true;

  const check = (label: string, item: ToolchainItem, hint?: string) => {
    if (item.ok) {
      lines.push(`✔ ${label}${item.version ? ` — ${item.version}` : ""}`);
    } else {
      ok = false;
      lines.push(`✘ ${label}${hint ? `\n    ${hint}` : ""}`);
    }
  };

  check(
    `node ${probe.node.required}`,
    probe.node,
    "Install Node.js 20 or newer: https://nodejs.org"
  );
  check(
    "cargo",
    probe.cargo,
    "Install Rust: https://rustup.rs (mosseal compiles a Rust template per consumer)"
  );
  check("rustc", probe.rustc);
  check(
    "wasm-pack",
    probe.wasmPack,
    "Install wasm-pack: https://rustwasm.github.io/wasm-pack/installer/ " +
      "(on Windows CI use `npx wasm-pack`, never curl | sh)"
  );
  check(
    "wasm32-unknown-unknown target",
    probe.wasmTarget,
    "Run: rustup target add wasm32-unknown-unknown"
  );

  return { ok, lines };
}

/**
 * Assert the toolchain is build-ready; throws with an actionable message.
 */
export function assertToolchain(probe: ToolchainProbe = probeToolchain()): DoctorReport {
  const report = doctorReport(probe);
  if (!report.ok) {
    throw new Error(
      "Toolchain check failed — run `mosseal doctor` for details:\n" +
        report.lines.join("\n")
    );
  }
  return report;
}
