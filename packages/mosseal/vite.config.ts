import { defineConfig } from "vite";

/**
 * Vite 8 build for the `mosseal` CLI.
 *
 * SSR build (Node target) keeps `node:*` builtins external and preserves the
 * `#!/usr/bin/env node` shebang from `src/bin/mosseal.ts`. The output is a
 * single ESM file at `dist/mosseal.js`, so `import.meta.url` resolves inside
 * `dist/` and `PKG_ROOT` (its parent) is the package root holding
 * `template/`.
 */
export default defineConfig({
  build: {
    lib: {
      entry: "src/bin/mosseal.ts",
      formats: ["es"],
      fileName: () => "mosseal.js",
    },
    ssr: true,
    target: "node20",
    minify: false,
    sourcemap: true,
    outDir: "dist",
    emptyOutDir: true,
  },
  test: {
    // Unit tests for env validation, .env merge/ignore, codegen escaping,
    // and CLI dry-run behavior (spec 05 / PLAN handoff item 3).
    include: ["test/**/*.test.ts"],
    environment: "node",
  },
});
