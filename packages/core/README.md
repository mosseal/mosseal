# @mosseal/core

TypeScript runtime wrapper for [MOSSEAL](../../README.md) — loads your consumer-compiled
wasm, handles the `#ms=` URL fragment, and mirrors the wasm error taxonomy.

Zero runtime dependencies. The wasm binary is **not** in this package: the
[`mosseal`](../mosseal/README.md) CLI compiles it per-consumer into your project, and you
pass its init function to `Mosseal.load`.

## Install

```bash
npm install @mosseal/core
npm install -D mosseal      # the CLI that builds your per-consumer wasm
```

## Usage

```ts
import { Mosseal, MossealError, MossealErrorCode } from "@mosseal/core";
import wasmInit from "./mosseal-out/mosseal_wasm.js";

// One-time init (idempotent; concurrent calls coalesce).
const mosseal = await Mosseal.load(wasmInit);

// Seal a link.
const url = mosseal.generateShareUrl({
  data: "ghp_...",
  password: "optional",
  expSecs: 3600,          // omit/0 = never expires (offline-capable)
  kind: "token",          // or "app_state"
});

// Open a link on reception.
if (mosseal.isMossealUrl(window.location.href)) {
  try {
    const { data, exp, kind } = await mosseal.openFromUrl(window.location.href, {
      password: "optional",
    });
    // Scrub the fragment from the address bar once you've persisted `data`.
    window.history.replaceState(
      {},
      document.title,
      mosseal.scrubFragmentFromUrl(window.location.href)
    );
  } catch (err) {
    if (err instanceof MossealError) console.error(err.code); // e.g. "BAD_PASSWORD"
  }
}
```

## API

| Member | Purpose |
|---|---|
| `Mosseal.load(loader)` | Idempotent init. `loader` = wasm-pack bundler init fn, wasm URL, `Uint8Array`, or pre-initialized exports. |
| `generateShareUrl(opts)` | Seal into a full URL (replaces any existing fragment). |
| `sealFragment(opts)` | Seal into the bare fragment value (for QR/clipboard transport). |
| `openFromUrl(url, opts)` | Open a full URL containing a `#ms=` fragment. |
| `openFragment(fragment, opts)` | Open a bare fragment value. |
| `isMossealUrl(url)` | Silent detection (returns `boolean`). |
| `scrubFragmentFromUrl(url)` | Strip the mosseal fragment, preserving other fragments. |
| `MossealError` / `MossealErrorCode` | Typed errors; `code` is the stable machine-readable taxonomy. |

`openFromUrl` throws `MALFORMED_ENVELOPE` for URLs that have **no** mosseal fragment — use
`isMossealUrl` for silent detection first.

## Error codes

`code` is one of: `MALFORMED_ENVELOPE`, `UNSUPPORTED_VERSION`, `UNSUPPORTED_KIND`,
`PAYLOAD_TOO_LARGE`, `DOMAIN_MISMATCH`, `BAD_PASSWORD`, `EXPIRED`,
`STRICT_TIME_UNAVAILABLE`, `EPOCH_RETIRED`, `WASM_INIT_FAILED`.

Codes are stable and machine-readable — match on `err.code`, never on the message text.

## Notes

- **Expiring links** (`expSecs` set) may fetch internet time from CORS-enabled sources to
  resist system-clock tampering (spec 07). `expSecs` omitted/`0` never fetches — offline
  links stay offline. In strict mode a failed fetch is `STRICT_TIME_UNAVAILABLE`; lenient
  mode falls back to the local clock.
- **Domain binding** is checked against `window.location.hostname` in browser builds
  (exact match; no wildcards) and yields `DOMAIN_MISMATCH` elsewhere.
- **Never log** the envelope or the decrypted token. The library itself emits no
  `console.*` except the single share-URL size advisory in the URL helper.

## License

MIT OR Apache-2.0
