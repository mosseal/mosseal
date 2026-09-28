# Spec 05 — CLI Builder (`mosseal`)

## Goal

An npm CLI that consumers run in `prebuild`. It validates the consumer's `.env`, generates/
injects secrets, invokes `wasm-pack`, and emits the per-consumer wasm build. This is the
compile-time-injection distribution model (decided).

## Command surface

```
mosseal build        # validate env → wasm-pack build → emit ./mosseal-out/
mosseal init         # scaffold .env entries (random secrets) + snippet
mosseal rotate       # append new epoch secret, keep old ones for grace
mosseal doctor       # check rust/wasm-pack presence, versions, warnings
```

## Environment variables (consumer `.env`)

| Var | Required | Notes |
|---|---|---|
| `MOSSEAL_SECRET_0` … `_N` | yes | base64url 32 B each. Slot-indexed and **sparse**: a gap (`_0` and `_2` but no `_1`) is a **retired epoch (hole)** and is preserved; trailing holes are trimmed. The highest **active** slot is the sealing epoch (spec 02 § Key epochs). |
| `MOSSEAL_ALLOWED_DOMAINS` | yes | comma list, exact-match hostnames (spec 03) |
| `MOSSEAL_STRICT_TIME` | no | `true`/`false`, default `false` (spec 07) |
| `MOSSEAL_ARGON2_PROFILE` | no | `minimum` (default) or `interactive` (spec 02) |
| `MOSSEAL_TIME_SOURCES` | no | comma-separated `https://` URLs used **instead of** the three defaults (spec 07). Validated by `mosseal build`, then baked into the generated `secrets.rs` (`time_sources_str()`); empty = defaults. |

> There is no `MOSSEAL_INTERNAL_SECRET`. An earlier draft used it for epoch 0; the epoch
> list (`MOSSEAL_SECRET_<n>`) fully supersedes it and no code reads the name.

## `mosseal init`

- Generates `MOSSEAL_SECRET_0` via `crypto.randomBytes(32).toString("base64url")`.
- Writes/merges `.env` entries **without overwriting** existing values; prints next steps.
- Refuses to write `.env` if the file is committed (checks `.gitignore`; prints a loud warning
  if not ignored — the #1 footgun for this distribution model).

## `mosseal build` flow

1. **Pre-validate env** (before spawning wasm-pack — fail fast with friendly diagnostic messages):
   - epoch list non-empty, each present secret ≥ 32 bytes entropy after base64url decode;
     **holes are allowed** (a missing `MOSSEAL_SECRET_<n>` between present ones is a retired
     epoch — preserved as a slot, not an error); trailing holes are trimmed;
   - `ALLOWED_DOMAINS` non-empty, entries are bare hostnames (no scheme/slash/port; regex
     `^[a-z0-9.-]+$` lowercase); warn if `localhost` present;
   - `STRICT_TIME`/`ARGON2_PROFILE` in allowed sets.
2. Resolve toolchain: fail fast with actionable message + link if `cargo`/`rustc` or
   `wasm-pack` missing (suggest `mosseal doctor`).
3. Prepare build environment:
   - Copy packaged Rust template (`template/`) to a temporary directory.
   - Unpack vendored `mosseal-core` package.
   - Generate `secrets.rs` containing `obfuse!(...)` encrypted literals for the epoch secrets
     and allowed domains (enforcing compile-time AEAD obfuscation without leaking raw secrets).
   - Spawn `wasm-pack build --target bundler --out-dir <cwd>/mosseal-out` in the temporary directory.
     `--target bundler` only — Node uses the same wasm through the wrapper's Node loader (single
     build, halves CI time vs dual-build).
4. Post-build: emit a generated `mosseal-out/meta.json` (epoch count, argon profile, strict
   flag, version, and config fingerprint — no raw secrets) so apps can display build provenance in devtools.
5. Exit non-zero on any failure with the wasm-pack output passed through.

### Why the template ships as source

Every consumer must compile with their own secrets (publishing a pre-built wasm would share one
key across all users of the library — the chat's central insight). The npm package therefore
contains the Rust crate source and vendored core crate; the CLI runs wasm-pack against it in a temp
checkout pinned to the package version (consumers never edit Rust directly; upgrades come from
the npm package). Real secrets are written to temporary `secrets.rs` files during compilation and
never committed.

## `mosseal rotate`

- Appends `MOSSEAL_SECRET_<N+1>` to `.env` (where `N` is the highest existing epoch index),
  leaves prior epochs in place (old links keep opening). Prints instructions for eventually
  **retiring** the oldest epoch after a grace period — deleting its `MOSSEAL_SECRET_<n>` line
  is the actual invalidation event (`EPOCH_RETIRED` at open time for links sealed under it).
- Retiring an epoch leaves a **hole** in the list; that is expected. The remaining secrets must
  **not** be renumbered (epoch indices are positional). Epochs may be retired in any order.

## `mosseal doctor`

Checks: node ≥ 20, cargo + rustc (prints `rustc -v`), wasm-pack presence/version, wasm32
target installed (`rustup target list --installed`). Network reachability is **opt-in** via
`--network` (probes the first default time source, spec 07) so the default run stays fast and
air-gapped-CI-safe; when enabled, an unreachable network fails the report with a hint that
strict-time builds will fail `open()`.

## Implementation

Node ≥ 20.19 (Vite 8 engine requirement: `^20.19.0 || >=22.12.0`), ESM, **zero runtime deps** —
the `.env` parser is internal (`src/dotenv.ts`), so `dotenv` is NOT a dependency (the earlier
"zero runtime deps beyond `dotenv`" note was inaccurate; nothing imported the npm package).

Sources are TypeScript under `src/` (`cli.ts`, `env.ts`, `build.ts`, `init.ts`, `dotenv.ts`,
`toolchain.ts`, `codegen.ts`, `bin/mosseal.ts`). The package builds with **Vite 8** (Rolldown,
SSR target) into a single `dist/mosseal.js` with the `#!/usr/bin/env node` shebang preserved
and `node:*` builtins external. The `bin` field points at `./dist/mosseal.js`; `PKG_ROOT`
resolves from `dist/` to the package root holding `template/`. All file writes go through a
`--dry-run`-able planner for testability.
