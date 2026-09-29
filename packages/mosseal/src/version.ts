/**
 * Package version lookup (spec 05).
 *
 * Reads `version` from the package's own `package.json`. The bundled entry is
 * `dist/mosseal.js`, so `import.meta.url` points into `dist/`; the parent is
 * the package root holding `package.json`.
 */
import { readFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const PKG_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");

/** The `@mosseal/cli` package version (falls back to `0.0.0`). */
export function version(): string {
  try {
    return (
      JSON.parse(readFileSync(join(PKG_ROOT, "package.json"), "utf8")).version ?? "0.0.0"
    );
  } catch {
    return "0.0.0";
  }
}
