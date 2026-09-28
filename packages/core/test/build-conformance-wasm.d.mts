/**
 * Type declarations for `build-conformance-wasm.mjs` (spec 08).
 *
 * The helper is plain ESM (`.mjs`) so it can be run directly with `node` and
 * imported by the Playwright harness; this `.d.mts` gives the vitest suites a
 * typed surface without converting the file to TypeScript.
 */

export interface BuildConformanceWasmOptions {
  /** Rebuild even if the fixture already exists. */
  force?: boolean;
  /** wasm-pack target. */
  target?: "nodejs" | "web";
  /** Web target only: build the strict-time variant. */
  strict?: boolean;
  /** Explicit web variant (overrides `target`/`strict`). */
  variant?: "web-lenient" | "web-strict" | "web-custom";
  /** Bake a `MOSSEAL_TIME_SOURCES` override into the generated `secrets.rs`. */
  timeSources?: string[] | null;
}

/** Build the conformance wasm; returns the fixture output dir. */
export function buildConformanceWasm(
  opts?: BuildConformanceWasmOptions
): string;

/** Back-compat: the Node conformance suite's output dir. */
export function conformanceWasmDir(): string;

/** Custom time source baked into the `web-custom` fixture (spec 07). */
export const CUSTOM_TIME_SOURCE: string;