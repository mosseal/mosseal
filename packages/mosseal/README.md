# mosseal

CLI builder for [MOSSEAL](../../README.md) — the compile-time-injection step that turns
your `.env` secrets into a per-consumer WebAssembly module.

Every consumer compiles the wasm with **their own** epoch secrets, so no two deployments
share a key. The CLI validates your environment, generates an obfuscated `secrets.rs`
(`obfuse!` literals), and runs `wasm-pack` for you.

> **Not** a runtime dependency. The runtime wrapper is
> [`@mosseal/core`](../core/README.md); this package is a devDependency with a Rust
> toolchain attached.

## Install

```bash
npm install -D mosseal
npm install @mosseal/core
```

Requires **Node ≥ 20.19** (or ≥ 22.12) and a Rust toolchain (see [Prerequisites](#prerequisites)).

## Commands

```
mosseal init      Scaffold .env with a fresh MOSSEAL_SECRET_0
mosseal build     Validate env → generate secrets.rs → wasm-pack → ./mosseal-out/
mosseal rotate    Append MOSSEAL_SECRET_<N+1> (keeps old epochs for grace)
mosseal doctor    Check node / cargo / rustc / wasm-pack / wasm32 target
```

Flags: `--dry-run` (validate/plan without writing or building), `--cwd <dir>`,
`--out-dir <dir>` (build only), `--network` (doctor: also probe time-source reachability).

## Quick start

```bash
npx mosseal init                      # writes MOSSEAL_SECRET_0 to .env
# then edit .env:
#   MOSSEAL_ALLOWED_DOMAINS=your-site.github.io
npx mosseal build                     # emits ./mosseal-out/
```

Add it to your build so it runs before your bundler:

```jsonc
// package.json
{
  "scripts": {
    "prebuild": "mosseal build",
    "build": "vite build"
  }
}
```

Then wire the compiled wasm into your app with `@mosseal/core`:

```ts
import { Mosseal } from "@mosseal/core";
import wasmInit from "./mosseal-out/mosseal_wasm.js";

const mosseal = await Mosseal.load(wasmInit);
```

`.gitignore` should contain `mosseal-out/` and `.env` — `mosseal init` warns loudly if
`.env` is not ignored (it holds the keys to every link you seal).

## Environment variables (`.env`)

| Var | Required | Notes |
|---|---|---|
| `MOSSEAL_SECRET_0` … `_N` | yes | base64url, 32 bytes each. Latest active epoch seals new links. |
| `MOSSEAL_ALLOWED_DOMAINS` | yes | comma list of bare lowercase hostnames (exact match). |
| `MOSSEAL_STRICT_TIME` | no | `true`/`false` (default `false`). Strict = fail `open()` without net time. |
| `MOSSEAL_ARGON2_PROFILE` | no | `minimum` (default) or `interactive`. |
| `MOSSEAL_TIME_SOURCES` | no | comma-separated `https://` URLs to use **instead of** the three defaults (spec 07). Custom URLs are parsed as JSON with a `"unixTime"` key. Empty = defaults. |

Real environment variables take precedence over `.env` — handy in CI (see below).

## Prerequisites

- **Node** ≥ 20.19 (or ≥ 22.12).
- **Rust** ≥ 1.85 and the `wasm32-unknown-unknown` target:
  ```bash
  rustup target add wasm32-unknown-unknown
  ```
- **wasm-pack**: https://rustwasm.github.io/wasm-pack/installer/

Run `npx mosseal doctor` to check all of the above and get actionable hints.

## Consumer CI (GitHub Actions)

Compile-time injection means the Rust toolchain runs in **your** CI. A warm cargo cache
keeps the template build under a minute.

```yaml
name: deploy
on:
  push: { branches: [main] }
  workflow_dispatch:

jobs:
  build:
    runs-on: ubuntu-latest
    permissions: { contents: read, pages: write, id-token: write }
    steps:
      - uses: actions/checkout@v4

      - uses: dtolnay/rust-toolchain@stable
        with:
          targets: wasm32-unknown-unknown

      # Caches ~/.cargo and target/ across runs.
      - uses: Swatinem/rust-cache@v2

      # Cross-platform wasm-pack install (do NOT use `curl | sh` on Windows runners).
      - uses: jetli/wasm-pack-action@v0.4.0
        with:
          version: latest

      - uses: actions/setup-node@v4
        with:
          node-version: 22
          cache: npm

      - run: npm ci

      # Fast failure before the (slower) wasm compile.
      - run: npx mosseal doctor

      # `prebuild` runs `mosseal build`; secrets come from the environment
      # (real env wins over .env), so no secret file is written to disk.
      - name: build
        run: npm run build
        env:
          MOSSEAL_SECRET_0: ${{ secrets.MOSSEAL_SECRET_0 }}
          MOSSEAL_ALLOWED_DOMAINS: ${{ vars.MOSSEAL_ALLOWED_DOMAINS }}

      - uses: actions/upload-pages-artifact@v3
        with:
          path: dist
```

**Windows runners:** always use `jetli/wasm-pack-action` (or `npx wasm-pack`), never
`curl … | sh`.

## Rotating secrets

See the [epoch-rotation runbook](../../docs/epoch-rotation.md). Short version:
`mosseal rotate` adds a new epoch; new links seal with it while old links keep opening.
Deleting an old epoch **retires** it — links under it then fail with `EPOCH_RETIRED`,
and every other epoch keeps working. Never renumber the remaining secrets.

## Limitations

MOSSEAL obfuscation is a **speed bump**, not cryptographic secrecy: anyone with your
compiled wasm and a link can extract the secret (spec 00). Links are bearer credentials
with no revocation authority — expiry and epoch retirement are the only mechanisms. Read
the [threat model](../../README.md#threat-model--security-guarantees) before relying on it.

## License

MIT OR Apache-2.0
