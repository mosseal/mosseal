/**
 * Type declarations for `sync-admin-wasm.mjs` (spec 05).
 *
 * The helper is plain ESM (`.mjs`) so it can be run directly with `node` and
 * imported by the CLI's vitest suite; this `.d.mts` gives that suite a typed
 * surface without converting the file to TypeScript.
 */

/** True when the vendored admin wasm is present. */
export function hasVendoredAdminWasm(): boolean;

/** Build the admin wasm and copy it into the CLI package's `vendor/` dir. */
export function syncAdminWasm(opts?: { check?: boolean }): void;
