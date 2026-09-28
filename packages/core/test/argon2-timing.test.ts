/**
 * Argon2id timing assertion (spec 08 § Timing assertions, amended 2026-09-26).
 *
 * Purpose: prove memory-hardness was NOT silently compiled out while keeping
 * the UX budget. The `minimum` profile is the OWASP floor (19 MiB, t=2, p=1 —
 * decision D8), which measures ~30–60 ms in wasm, NOT the ≥ 250 ms the original
 * spec text assumed. The assertion therefore checks:
 *
 *   1. Argon2id is **meaningfully slower than HKDF** (the memory-hard path is
 *      actually running — a stubbed/compiled-out Argon2 would be near-instant), and
 *   2. it stays within the **UX budget** (< 1.5 s) even with generous headroom
 *      for slow CI.
 *
 * Run against the conformance wasm (real code, nodejs target).
 */
import { beforeAll, describe, expect, it } from "vitest";
import { join } from "node:path";
import { buildConformanceWasm } from "./build-conformance-wasm.mjs";

interface ConformanceMosseal {
  sealDeterministic(
    data: string,
    password: string | null,
    expSecs: number | null,
    kind: number | null,
    saltHex: string,
    nonceHex: string,
    epoch?: number | null
  ): string;
}

let wasm: ConformanceMosseal;

beforeAll(async () => {
  const dir = buildConformanceWasm();
  const mod = await import(join(dir, "mosseal_wasm.js"));
  wasm = new mod.Mosseal();
}, 120_000);

const SALT = "00".repeat(16);
const NONCE = "00".repeat(12);

/** Median of `n` runs of `fn` (ms) — robust against one-off scheduler jitter. */
function medianMs(fn: () => void, n = 5): number {
  const samples: number[] = [];
  for (let i = 0; i < n; i++) {
    const t = process.hrtime.bigint();
    fn();
    samples.push(Number(process.hrtime.bigint() - t) / 1e6);
  }
  samples.sort((a, b) => a - b);
  return samples[Math.floor(samples.length / 2)];
}

describe("Argon2id timing (spec 08, amended)", () => {
  it("password mode is meaningfully slower than the HKDF path", () => {
    // Warm up (JIT + wasm instantiation of the memory arena).
    wasm.sealDeterministic("warm", "pw", null, 1, SALT, NONCE, null);

    const hkdf = medianMs(() =>
      wasm.sealDeterministic("x", null, null, 1, SALT, NONCE, null)
    );
    const argon = medianMs(() =>
      wasm.sealDeterministic("x", "pw", null, 1, SALT, NONCE, null)
    );

    // HKDF should be near-instant; Argon2 must dominate by a wide margin.
    // 10 ms is a conservative floor well below the observed ~30 ms, so the
    // test is robust on slow CI while still catching a compiled-out Argon2.
    expect(argon).toBeGreaterThan(hkdf + 10);
  });

  it("stays within the UX budget (< 1.5 s) with generous headroom", () => {
    const argon = medianMs(() =>
      wasm.sealDeterministic("x", "pw", null, 1, SALT, NONCE, null)
    );
    expect(argon).toBeLessThan(1500);
  });
});
