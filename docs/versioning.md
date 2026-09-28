# Versioning & Compatibility Policy

MOSSEAL has **two independent version axes** that must not be conflated:

1. **Package version** — the npm (`mosseal`, `@mosseal/core`) and Cargo
   (`mosseal-core`, `mosseal-wasm`, `mosseal-cli`) release versions. Follows
   [Semantic Versioning](https://semver.org/spec/v2.0.0.html).
2. **Envelope format version** — the first byte of the binary envelope (spec 01).
   This is a **wire-format** version, not a package version.

## Package semver

| Change | Bump |
|---|---|
| Bug fix, docs, internal refactor, no observable behavior change | **patch** |
| New API, new optional flag, new error code, backward-compatible behavior | **minor** |
| Removed/renamed API, changed default behavior, changed error-code meaning | **major** |

All four crates and both npm packages are released in lockstep at the same version
for v1. The `mosseal` CLI and `@mosseal/core` wrapper are versioned together because
the wrapper's error taxonomy mirrors the wasm surface exactly (spec 02).

## Envelope format version (the `version` byte)

The envelope's first byte is `0x01` for the current format (spec 01). It is **separate**
from the payload `kind` byte and from the package version.

### Rules

- **Adding a new payload `kind`** (e.g. `binary_blob`) is **not** an envelope-version
  change. Unknown kinds on an older build fail with `UNSUPPORTED_KIND`; the envelope
  version stays `0x01`.
- **Adding a new flag bit** is **not** an envelope-version change *if* the bit is
  optional and older readers can ignore it. Reserved bits must be zero on seal; a
  non-zero reserved bit on open is `MALFORMED_ENVELOPE` (spec 01). Therefore a new
  *required* flag bit **is** a breaking change.
- **Changing the binary layout** (field order, sizes, AAD coverage, length-prefix
  width) **is** a breaking change → **bump the `version` byte**.
- **Changing the KDF construction** (e.g. the `info` string, the Argon2 input layout,
  the binding string) is a **breaking change to link compatibility** even though the
  envelope bytes are unchanged. Treat it as a **major** package bump and document it
  loudly; there is no in-envelope signal for it, so old links simply fail to decrypt.

### Forward incompatibility is intentional

An envelope whose `version` byte is greater than the build's current version fails with
`UNSUPPORTED_VERSION`. We bump the version byte rather than overloading flags, so a
reader never has to guess whether it understands a layout (spec 01).

### Backward compatibility

A build that supports version `N` **must** continue to open version `N-1` envelopes for
at least one major release cycle, unless a security fix requires otherwise. When support
for an old version is dropped, that is a **major** package bump and must be called out in
the [CHANGELOG](../CHANGELOG.md).

## What is *not* covered by semver

- **Link portability across deployments.** Links are bound to the deployment's sorted
  domain whitelist and its epoch secrets (spec 03). Changing either invalidates existing
  links — this is intended and is not a semver concern.
- **Obfuscation strength.** `obfuse` is a speed bump, not a security boundary (spec 00).
  Hardening it is a patch/minor change; it never changes the wire format.
- **Time-source availability.** The default time sources (spec 07) are external services;
  their availability is not a compatibility guarantee. `MOSSEAL_TIME_SOURCES` overrides
  the list.

## Release checklist

The root `Cargo.toml` `[workspace.package] version` is the **single source of
truth**. The npm manifests and the template `Cargo.toml` must agree with it; the
`version-lockstep` CI job enforces that, and
[`scripts/release.mjs`](../scripts/release.mjs) does the mechanical parts:

```bash
# Verify every manifest agrees on the authoritative version (run in CI / pre-tag):
node scripts/release.mjs --check

# Print the authoritative version (root Cargo.toml):
node scripts/release.mjs --print

# Propagate a Cargo.toml bump to the npm manifests + template (preview with --dry-run):
node scripts/release.mjs --sync
```

1. Update [`CHANGELOG.md`](../CHANGELOG.md) under a new version heading. *(manual)*
2. Bump `version` in the workspace `Cargo.toml` (`[workspace.package]`), then run
   `node scripts/release.mjs --sync` to propagate it to both `packages/*/package.json`
   files and the template `Cargo.toml` (+ its vendored `mosseal-core-<ver>` path).
   *(manual bump + scripted sync)*
3. If the envelope layout changed, bump the `version` byte in `mosseal-core` and update
   spec 01. *(manual — wire-format judgement)*
4. Regenerate `vectors.json` (`cargo run -p mosseal-vectors`) and commit it — the drift
   tripwire will fail CI otherwise. *(scripted — `--sync`)*
5. Regenerate the vendored `packages/mosseal/template/mosseal-core-<ver>.crate` after any
   core source/dependency change. It is a derived artifact and is **not committed** —
   it is regenerated at `npm pack` time (`prepack`) and by `--sync`. *(scripted)*
6. Tag the release and publish both packages to **GitHub Packages**
   (`npm.pkg.github.com`, configured via `publishConfig`). *(scripted — the `release`
   workflow publishes both packages under the `next` dist-tag, then creates the draft
   Release)*
7. Publish the draft Release — this promotes `next` → `latest` on GitHub Packages
   (`release-published.yml`). *(manual — review the draft first)*
8. Mirror the release to the **public npm registry** by running the `release-npmjs`
   workflow (`workflow_dispatch`, `mode=publish`). It is gated on step 7 having
   succeeded and re-publishes the Release's tarballs, so both registries serve
   byte-identical artifacts. *(manual — see
   [`development.md`](development.md#release-npmjsyml--mirror-to-the-public-npm-registry))*

The `release` GitHub workflow (`.github/workflows/release.yml`, `workflow_dispatch`)
reads the authoritative version, compares it to the latest `v*` git tag, and **skips
automatically** when it is not newer. Otherwise it builds + packs both packages,
publishes them to GitHub Packages under the **`next` dist-tag**, and creates a **draft**
GitHub Release with the tarballs attached.

### Dist-tag staging (`next` → `latest`)

GitHub Packages has no draft/staging state — `npm publish` is immediate. To keep the
default install path safe while a release is under review, the workflow publishes under
`next`, so `npm install @mosseal/cli` keeps resolving to the previous `latest`:

```bash
npm install @mosseal/cli          # previous latest
npm install @mosseal/cli@next     # the version under review
```

Publishing the draft Release fires `.github/workflows/release-published.yml`, which
promotes the released version to `latest`:

```bash
npm dist-tag add @mosseal/cli@<version> latest
```

So the full flow is: run `release` → packages land under `next` → review the draft →
publish the Release → `latest` moves automatically.

### Mirroring to the public npm registry

GitHub Packages is the source of truth, but it requires a token even for public
installs. To also serve the release from the public npm registry (npmjs), run the
`release-npmjs` workflow (`workflow_dispatch`, `mode=publish`) **after** the draft
Release has been published.

The workflow is gated: it refuses to run unless the version is already live on GitHub
Packages under `latest` (i.e. `release-published` succeeded), and it re-publishes the
**exact tarballs attached to the GitHub Release** rather than re-packing — so both
registries serve byte-identical artifacts.

Auth uses npm [trusted publishing](https://docs.npmjs.com/trusted-publishers) (OIDC),
so there is no long-lived token for normal releases. The first-ever publish of a
package falls back to the `NPM_TOKEN` secret, because a trusted publisher can only be
configured on a package that already exists on npmjs. See
[`development.md`](development.md#release-npmjsyml--mirror-to-the-public-npm-registry)
for the one-time trusted-publisher setup and the bootstrap sequence.
