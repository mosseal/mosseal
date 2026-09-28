/**
 * CLI dispatcher + dry-run tests (spec 05 § Command surface, § Implementation:
 * "All file writes go through a `--dry-run`-able planner for testability").
 *
 * These exercise `run()` end-to-end for the non-building paths so the CLI
 * contract (arg parsing, usage, dry-run safety) is pinned without spawning
 * wasm-pack.
 */
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { mkdtempSync, rmSync, writeFileSync, readFileSync, existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { run } from "../src/cli.js";
import { doctorReport } from "../src/toolchain.js";

const tmpDirs: string[] = [];
function makeTmp(): string {
  const d = mkdtempSync(join(tmpdir(), "mosseal-cli-"));
  tmpDirs.push(d);
  return d;
}

let logSpy: ReturnType<typeof vi.spyOn>;
let warnSpy: ReturnType<typeof vi.spyOn>;

beforeEach(() => {
  logSpy = vi.spyOn(console, "log").mockImplementation(() => {});
  warnSpy = vi.spyOn(console, "warn").mockImplementation(() => {});
});
afterEach(() => {
  logSpy.mockRestore();
  warnSpy.mockRestore();
  for (const d of tmpDirs.splice(0)) rmSync(d, { recursive: true, force: true });
  for (const k of Object.keys(process.env)) {
    if (k.startsWith("MOSSEAL_")) delete process.env[k];
  }
});

function secret(seed = 1): string {
  return Buffer.alloc(32, seed).toString("base64url");
}

function logged(): string {
  return logSpy.mock.calls.map((c: unknown[]) => c.join(" ")).join("\n");
}

describe("run — usage & dispatch", () => {
  it("prints usage when no command is given", async () => {
    await run([]);
    expect(logged()).toMatch(/mosseal — compile-time-injection builder/);
  });

  it("prints usage for --help", async () => {
    await run(["--help"]);
    expect(logged()).toMatch(/Usage:/);
  });

  it("throws on an unknown command", async () => {
    await expect(run(["frobnicate"])).rejects.toThrow(/Unknown command: frobnicate/);
  });
});

describe("run — init --dry-run", () => {
  it("does not create .env and reports the planned write", async () => {
    const dir = makeTmp();
    await run(["init", "--dry-run", "--cwd", dir]);
    expect(existsSync(join(dir, ".env"))).toBe(false);
    expect(logged()).toMatch(/dry-run: would append MOSSEAL_SECRET_0/);
  });

  it("warns when .env is not gitignored", async () => {
    const dir = makeTmp();
    await run(["init", "--dry-run", "--cwd", dir]);
    expect(warnSpy.mock.calls.map((c: unknown[]) => c.join(" ")).join("\n")).toMatch(
      /Could not verify .env is gitignored|NOT gitignored/
    );
  });
});

describe("run — build --dry-run", () => {
  it("validates env and skips wasm-pack", async () => {
    const dir = makeTmp();
    writeFileSync(
      join(dir, ".env"),
      `MOSSEAL_SECRET_0=${secret(1)}\nMOSSEAL_ALLOWED_DOMAINS=example.com\n`
    );
    const res = (await run(["build", "--dry-run", "--cwd", dir])) as {
      ok: boolean;
      dryRun?: boolean;
    };
    expect(res).toMatchObject({ ok: true, dryRun: true });
    expect(logged()).toMatch(/env ok: 1 active epoch\(s\)/);
    expect(logged()).toMatch(/dry-run: validation passed/);
  });

  it("fails fast on invalid env before any build", async () => {
    const dir = makeTmp();
    writeFileSync(join(dir, ".env"), "MOSSEAL_ALLOWED_DOMAINS=example.com\n");
    await expect(run(["build", "--dry-run", "--cwd", dir])).rejects.toThrow(
      /No MOSSEAL_SECRET_0/
    );
  });
});

describe("run — rotate --dry-run", () => {
  it("plans the next contiguous epoch without writing", async () => {
    const dir = makeTmp();
    const envPath = join(dir, ".env");
    const before = `MOSSEAL_SECRET_0=${secret(1)}\nMOSSEAL_ALLOWED_DOMAINS=example.com\n`;
    writeFileSync(envPath, before);
    const res = (await run(["rotate", "--dry-run", "--cwd", dir])) as {
      ok: boolean;
      epoch: number;
    };
    expect(res).toMatchObject({ ok: true, epoch: 1 });
    expect(readFileSync(envPath, "utf8")).toBe(before);
    expect(logged()).toMatch(/dry-run: would append MOSSEAL_SECRET_1/);
  });

  it("appends past a retired hole without renumbering", async () => {
    const dir = makeTmp();
    const envPath = join(dir, ".env");
    // Epoch 1 is retired (a hole); the next epoch must be 2, not 1.
    writeFileSync(
      envPath,
      `MOSSEAL_SECRET_0=${secret(1)}\nMOSSEAL_SECRET_2=${secret(3)}\n` +
        `MOSSEAL_ALLOWED_DOMAINS=example.com\n`
    );
    const res = (await run(["rotate", "--dry-run", "--cwd", dir])) as {
      ok: boolean;
      epoch: number;
    };
    expect(res).toMatchObject({ ok: true, epoch: 3 });
    expect(logged()).toMatch(/dry-run: would append MOSSEAL_SECRET_3/);
  });
});

describe("doctorReport (pure, synthetic probe)", () => {
  it("reports ok when every tool is present", () => {
    const report = doctorReport({
      node: { ok: true, version: "v22.0.0", required: ">=20" },
      cargo: { ok: true, version: "cargo 1.85.0" },
      rustc: { ok: true, version: "rustc 1.85.0" },
      wasmPack: { ok: true, version: "wasm-pack 0.15.0" },
      wasmTarget: { ok: true },
    });
    expect(report.ok).toBe(true);
    expect(report.lines.every((l) => l.startsWith("✔"))).toBe(true);
  });

  it("fails and prints a hint when wasm-pack is missing", () => {
    const report = doctorReport({
      node: { ok: true, version: "v22.0.0", required: ">=20" },
      cargo: { ok: true, version: "cargo 1.85.0" },
      rustc: { ok: true, version: "rustc 1.85.0" },
      wasmPack: { ok: false },
      wasmTarget: { ok: true },
    });
    expect(report.ok).toBe(false);
    expect(report.lines.join("\n")).toMatch(/wasm-pack/);
    expect(report.lines.join("\n")).toMatch(/rustwasm\.github\.io/);
  });

  it("omits the network line unless a network probe is supplied", () => {
    const base = {
      node: { ok: true, version: "v22.0.0", required: ">=20" },
      cargo: { ok: true, version: "cargo 1.85.0" },
      rustc: { ok: true, version: "rustc 1.85.0" },
      wasmPack: { ok: true, version: "wasm-pack 0.15.0" },
      wasmTarget: { ok: true },
    };
    expect(doctorReport(base).lines.join("\n")).not.toMatch(/network reachability/);
    const withNet = doctorReport({ ...base, network: { ok: true, version: "reachable" } });
    expect(withNet.ok).toBe(true);
    expect(withNet.lines.join("\n")).toMatch(/network reachability/);
  });

  it("fails the report when the network probe is unreachable", () => {
    const report = doctorReport({
      node: { ok: true, version: "v22.0.0", required: ">=20" },
      cargo: { ok: true, version: "cargo 1.85.0" },
      rustc: { ok: true, version: "rustc 1.85.0" },
      wasmPack: { ok: true, version: "wasm-pack 0.15.0" },
      wasmTarget: { ok: true },
      network: { ok: false },
    });
    expect(report.ok).toBe(false);
    expect(report.lines.join("\n")).toMatch(/network reachability/);
  });
});