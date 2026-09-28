import { defineConfig } from "vitest/config";

/**
 * Vite 8 build for @mosseal/core.
 *
 * Library mode, ESM only, no minification (readable wasm-loader glue).
 * `tsc -p tsconfig.build.json` emits the `.d.ts` files separately; this
 * config only bundles the runtime JS.
 *
 * The package has zero runtime dependencies (spec 04), so nothing needs
 * externalising — but we keep the `external` hook explicit and defensive
 * so a future accidental import cannot be silently inlined.
 */
export default defineConfig({
  build: {
    lib: {
      entry: "src/index.ts",
      formats: ["es"],
      fileName: "index",
    },
    sourcemap: true,
    minify: false,
    target: "es2022",
    outDir: "dist",
    emptyOutDir: false, // keep the tsc-emitted .d.ts files
    rollupOptions: {
      external: [],
    },
  },
  test: {
    // spec 08 Node suite: conformance vectors, URL/QR budget, Argon2 timing.
    // The Playwright browser specs live in `e2e/` and run via `playwright test`
    // (not vitest) — exclude them here.
    include: ["test/**/*.test.ts"],
    exclude: ["e2e/**", "node_modules/**", "dist/**"],
    // Generous per-test timeout: the conformance wasm is built on demand.
    testTimeout: 120_000,
  },
});
