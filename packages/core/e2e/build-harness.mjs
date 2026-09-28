/**
 * Build the browser-suite harness (spec 08 § Cross-origin/browser suite).
 *
 *   1. Build BOTH web-target wasm fixtures (lenient + strict) with the fixed
 *      test secrets from `vectors.json` — strict mode is a compile-time flag,
 *      so it needs its own build (spec 07).
 *   2. Bundle `e2e/harness/*.html` with Vite. Vite resolves the `?url` wasm
 *      imports and the glue's `new URL('...wasm', import.meta.url)`, emitting
 *      the wasm asset next to the page bundle.
 *
 * Output: `e2e/.dist/` (gitignored), served by `e2e/serve.mjs` and/or
 * fulfilled by the specs' fake-host routes.
 */
import { build } from "vite";
import {
  buildConformanceWasm,
  CUSTOM_TIME_SOURCE,
} from "../test/build-conformance-wasm.mjs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const HERE = dirname(fileURLToPath(import.meta.url));
const HARNESS_DIR = join(HERE, "harness");
const OUT_DIR = join(HERE, ".dist");
const force = process.argv.includes("--force");

buildConformanceWasm({ target: "web", strict: false, force });
buildConformanceWasm({ target: "web", strict: true, force });
// N1: a variant with a baked `MOSSEAL_TIME_SOURCES` override, so the browser
// suite can prove a custom source is actually consulted (spec 07).
buildConformanceWasm({
  variant: "web-custom",
  target: "web",
  timeSources: [CUSTOM_TIME_SOURCE],
  force,
});

await build({
  root: HARNESS_DIR,
  configFile: false,
  base: "./",
  logLevel: "warn",
  build: {
    outDir: OUT_DIR,
    emptyOutDir: true,
    target: "es2022",
    rollupOptions: {
      input: {
        index: join(HARNESS_DIR, "index.html"),
        strict: join(HARNESS_DIR, "strict.html"),
        custom: join(HARNESS_DIR, "custom.html"),
      },
    },
  },
});

console.log(`✔ browser harness built at ${OUT_DIR}`);
