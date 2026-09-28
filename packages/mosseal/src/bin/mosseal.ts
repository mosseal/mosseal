#!/usr/bin/env node
/**
 * mosseal — CLI builder (spec 05).
 *
 * Commands:
 *   mosseal init     scaffold .env entries (random secrets) + next steps
 *   mosseal build    validate env → generate secrets.rs → wasm-pack → ./mosseal-out/
 *   mosseal rotate   append MOSSEAL_SECRET_<N+1>, keep old epochs for grace
 *   mosseal doctor   check node/cargo/rustc/wasm-pack/wasm32-target
 *
 * Node >= 20, ESM. Zero runtime dependencies (the .env parser is internal).
 */
import { run } from "../cli.js";

run(process.argv.slice(2)).catch((err: unknown) => {
  console.error((err as { message?: string })?.message ?? String(err));
  process.exit(1);
});
