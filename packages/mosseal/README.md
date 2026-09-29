# @mosseal/cli

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
npm install -D @mosseal/cli
npm install @mosseal/core
```

Both packages are published to **GitHub Packages** (`npm.pkg.github.com`). Add an
`.npmrc` so npm resolves the `@mosseal` scope there:

```ini
@mosseal:registry=https://npm.pkg.github.com
//npm.pkg.github.com/:_authToken=${GITHUB_TOKEN}
```

`GITHUB_TOKEN` needs the `read:packages` scope (a classic PAT, or the automatic
`GITHUB_TOKEN` in Actions with `packages: read`).

New versions are published under the **`next` dist-tag** first, so `npm install
@mosseal/cli` keeps resolving to the previous stable release until the GitHub Release is
published (which promotes `next` → `latest`). To opt into a version under review:

```bash
npm install @mosseal/cli@next
```

Requires **Node ≥ 20.19** (or ≥ 22.12). The `build` command additionally needs a Rust
toolchain (see [Prerequisites](#prerequisites)); the admin commands (`gen-secret`,
`seal`, `open`) do **not** — they run a precompiled wasm shipped in this package.

### Installing from git (no registry)

Both packages also install straight from the repository. npm runs their `prepare`
script, which builds `dist/` and regenerates the vendored `mosseal-core` crate and
admin wasm — so a **Rust toolchain is required** for this path (the same one
`mosseal build` needs):

```bash
npm install -D github:mosseal/mosseal#v0.2.0
```

Pin a tag or commit for reproducibility. For a registry-free install that needs **no**
Rust toolchain, use the tarballs attached to the GitHub Release instead:

```bash
npm install -D ./mosseal-cli-0.2.0.tgz
```

## Commands

```
mosseal init      Scaffold .env with a fresh MOSSEAL_SECRET_0
mosseal build     Validate env → generate secrets.rs → wasm-pack → ./mosseal-out/
mosseal rotate    Append MOSSEAL_SECRET_<N+1> (keeps old epochs for grace)
mosseal doctor    Check node / cargo / rustc / wasm-pack / wasm32 target
```

Flags: `--dry-run` (validate/plan without writing or building), `--cwd <dir>`,
`--out-dir <dir>` (build only), `--network` (doctor: also probe time-source reachability).

### Admin commands

The trusted admin surface of the native `mosseal-cli` binary is also available here,
so you can seal/open links without a Rust toolchain. Sealing and opening run a
precompiled admin wasm module shipped in this package; `gen-secret` uses `node:crypto`.

```
mosseal gen-secret      Print a fresh 32-byte base64url epoch secret
mosseal seal <token>    Seal a token into a share-link fragment
mosseal open <fragment> Open and verify a fragment
```

Admin flags:

| Flag | Applies to | Notes |
|---|---|---|
| `--epochs <s;e;c>` | seal, open | base64url secrets, `;`-joined (or `MOSSEAL_EPOCHS`). Empty entry = retired hole. |
| `--domains <a,b>` | seal, open | comma-separated bare hostnames (or `MOSSEAL_ALLOWED_DOMAINS`). |
| `--password <pw>` | seal, open | bare `--password` prompts on a TTY (echo off). |
| `--exp <unix-secs>` | seal | omit/`0` = never expires. |
| `--kind <token\|binary_blob>` | seal | payload kind (default `token`). |
| `--ignore-expiry` | open | skip the expiry check (admin debugging). |

Epochs and domains resolve in this order: explicit flags → environment variables →
the `.env` file's `MOSSEAL_SECRET_<n>` slots + `MOSSEAL_ALLOWED_DOMAINS` (the same
config `init`/`rotate`/`build` use).

These commands are behaviourally interchangeable with the native `mosseal-cli`
binary: identical envelope bytes, identical stdout, and identical errors — both
print `Error: <CODE>: <detail>` (e.g. `Error: BAD_PASSWORD: gcm tag mismatch`)
and exit non-zero. A fragment sealed on one surface opens on the other.

```bash
# Generate a secret, seal a token, then open it back
SECRET=$(npx mosseal gen-secret)
FRAG=$(npx mosseal seal "ghp_..." --epochs "$SECRET" --domains user.github.io)
npx mosseal open "$FRAG" --epochs "$SECRET" --domains user.github.io
# → kind: 1 / exp:  0 / data: ghp_...

# Password + 1-hour expiry
npx mosseal seal "ghp_..." --password hunter2 --exp 1759000000 \
  --epochs "$SECRET" --domains user.github.io

# Admin debugging of an expired link (domain/epoch/password/tag still verified)
npx mosseal open "$FRAG" --epochs "$SECRET" --domains user.github.io --ignore-expiry
```

Errors print the stable machine-readable code (e.g. `BAD_PASSWORD`, `EXPIRED`) and
exit non-zero, matching the native CLI.

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
