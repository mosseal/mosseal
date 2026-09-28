# Development Notes

Operational notes for working on MOSSEAL itself (not for consumers — see the
package READMEs for that). The normative specs live in [`specs/`](../specs/);
this file captures the build/dependency conventions that are not part of the
wire format or public API.

## Dependency policy

- Direct dependencies use current compatible major/minor releases; patch updates
  remain routine lockfile maintenance.
- Workspace MSRV is **Rust 1.85**, driven by the current crypto, obfuscation,
  rand, getrandom, and test releases.
- Primary randomness chain: `rand 0.10` + `getrandom 0.4` (`wasm_js`).
  Note that `obfuse` brings in legacy `crypto-common` / `rand_core 0.6`, which
  pulls `getrandom 0.2`; wasm builds must also activate `getrandom 0.2`'s `js`
  feature (declared as an aliased direct dep in the wasm crates and the template).
- **Dependency cleanup (2026-09-26):** removed unused direct deps found by manual
  audit (cargo-machete was not installed at the time): workspace `hmac`, `subtle`,
  `hex-literal`, `proptest`; core `chacha20poly1305`, `hmac`, `subtle`, `serde`,
  `hex`, `obfuse`, dev `hex-literal`/`proptest`; wasm `thiserror`, `base64`; CLI
  `serde`, `serde_json`, `hex`; template `base64`. `zeroize` now enables its
  `derive` feature explicitly (previously pulled in transitively). `obfuse` stays
  in the wasm crates because the **generated** `secrets.rs` references `obfuse!`.
- The `supply-chain` CI job enforces this with `cargo deny` (advisories, license
  allow-list, banned crates, crates.io-only sources) and `cargo machete` (no
  unused direct deps). See [`deny.toml`](../deny.toml).

## Vendored `mosseal-core` crate

`packages/mosseal/template/mosseal-core-<ver>.crate` is a **packaged snapshot** of
`crates/mosseal-core`, shipped inside the `mosseal` npm package so the CLI can
compile the template without publishing `mosseal-core` to crates.io.

It is a **derived artifact and is deliberately NOT committed** (see `.gitignore`).
It is regenerated automatically:

- by `npm pack` / `npm publish` in `packages/mosseal` (the `prepack` script),
- by the conformance-wasm builder (`packages/core/test/build-conformance-wasm.mjs`)
  when it is missing — so `npm test` / `npm run test:e2e` in `packages/core` work on a
  fresh clone, and
- on demand via `npm run sync:core` (from `packages/mosseal`), or
  `node scripts/sync-core-crate.mjs` from the repo root.

Because it is generated on demand, it **cannot drift** from `crates/mosseal-core`
— there is no manual refresh step. The `packages` CI job packs the CLI and asserts
the crate lands in the tarball.

`node scripts/release.mjs --version <X.Y.Z>` also regenerates it as part of a release
bump (see [`docs/versioning.md`](versioning.md)). The unpacked
`packages/mosseal/template/mosseal-core-*/` directory is gitignored — the CLI builder
unpacks the `.crate` into its temp build dir.

## Local verification

Run the same checks CI runs before pushing:

```bash
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cargo run -p mosseal-vectors -- --check   # conformance-vector drift tripwire
cargo deny --all-features check && cargo machete   # needs cargo-deny / cargo-machete
```

JS/TS packages and the browser suite are documented in the root
[`README.md`](../README.md#development--testing).
