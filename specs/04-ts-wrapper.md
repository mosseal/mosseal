# Spec 04 — TypeScript Wrapper (`@mosseal/core`)

## Goal

A small, dependency-free TypeScript layer that loads the consumer-compiled wasm, exposes a clean
async API, handles URL parse/build, and hands the decrypted token to the app for IndexedDB
re-wrapping.

## Package layout (published)

```
@mosseal/core/
├── src/
│   ├── index.ts        # public API
│   ├── loader.ts       # Node/browser wasm init
│   ├── link.ts         # URL fragment parse/build
│   └── errors.ts       # error code enum + user-message mapping
└── dist/ (esm + types)
```

Note: the wasm binary itself is **not** in this package — it is generated per-consumer by the
CLI into the consumer's project (`spec 05`). The wrapper imports it via a path the consumer
configures.

## Public API

```ts
import { Mosseal } from "@mosseal/core";

const seal = await Mosseal.load(wasmUrlOrBuffer);   // one-time init
const link = await seal.generateShareUrl({
  data: "secret-token-or-small-state",
  password?: "purple-dinosaur",
  expSecs?: 3600,           // optional expiry
  kind: "token",
  baseUrl?: location.href   // default: current URL, stripped of existing fragment
});
// → "https://user.github.io/app/#ms=7gQbYD0jK2_AmZ0eFvH1iJ4kL9mN5oPqRsTuVwXyZ012"

const result = await seal.openFromUrl(location.href, { password? });
// → { data, exp, kind }   or throws MossealError with a stable code
```

### Payload kinds

`kind` is a string union mirroring the envelope `kind` byte (spec 01):

| `kind` | Byte | Meaning |
|---|---|---|
| `"token"` | `0x01` | A secret token / credential (default). |
| `"binary_blob"` | `0x02` | A small app-state blob (subject to the `MAX_PAYLOAD_BYTES` cap). |

Both are supported v1 kinds. An unknown kind byte on open → `UNSUPPORTED_KIND`.

### `MossealError` codes (mirrors wasm taxonomy exactly)

`MALFORMED_ENVELOPE`, `UNSUPPORTED_VERSION`, `UNSUPPORTED_KIND`, `PAYLOAD_TOO_LARGE`,
`DOMAIN_MISMATCH`, `BAD_PASSWORD`, `EXPIRED`, `STRICT_TIME_UNAVAILABLE`, `EPOCH_RETIRED`,
`WASM_INIT_FAILED`.

The wrapper adds user-presentable default messages per code so apps don't string-match.

## URL handling rules

- **Generate:** fragment is `#ms=<b64url(envelope)>` (the format `version` byte is the
  first byte *inside* the binary envelope — spec 01); any existing fragment on `baseUrl` is
  replaced. Warn (console) if final URL > 512 bytes (QR advisory, spec 01).
- **Open:** parse `#ms=` from a given URL string (works with `location.href`,
  `QR-scanned strings`, anywhere). Tolerates unrelated fragments (returns
  `null`-equivalent: `openFromUrl` throws `MALFORMED_ENVELOPE` only for *present but invalid*
  mosseal fragments; expose `seal.isMossealUrl(url): boolean` for silent detection).

## Receiver flow (the "sanitize URL" step, from the chat)

1. App detects `seal.isMossealUrl(location.href)` → show import UI.
2. If envelope flag says password-protected → prompt (input type=password).
3. `openFromUrl` → wasm validates domain, derives key, decrypts, checks exp.
4. On success, app immediately:
   - re-wraps plaintext with its own Web Crypto AES-GCM `CryptoKey` (`extractable: false`),
     stores ciphertext in IndexedDB — the chat's existing pattern, unchanged;
   - **scrubs the URL**: `history.replaceState({}, title, url-without-fragment)` so the
     transport link cannot be bookmarked/re-shared accidentally;
   - drops the JS-side plaintext reference (zeroed view where possible).
5. Wrong password (`BAD_PASSWORD`) → retry UI with attempt counter.

The wrapper exposes `scrubFragmentFromUrl(url)` as a helper but the app drives when to call it
(only after persistence succeeded).

## Zeroization / memory notes (honest limits)

- Plaintext crosses the wasm→JS boundary as a JS string; JS strings are immutable and cannot be
  reliably zeroed. Documented limitation. Mitigation: the app persists then drops references;
  wasm-side buffers are zeroized per spec 02.
- The wrapper never logs envelope or plaintext. Enforced by lint: **oxlint** rule
  `no-console: "error"` for `src/**` with a single override for `src/link.ts` (the one
  sanctioned QR-budget warning). No ESLint / `typescript-eslint` dependency — TypeScript 7
  (the native Go port) ships no JavaScript compiler API, which `typescript-eslint` requires.

## Loader details

- **Browser:** `init(wasmUrl)` — fetch + `WebAssembly.instantiateStreaming`. Requires
  `application/wasm` MIME type (GitHub Pages serves this correctly; documented in 06).
- **Node:** `init(readFileSync(pkgPath))` for CLI/admin scripts. Same wrapper API.
- `Mosseal.load` idempotent; concurrent calls coalesce to one init. Errors → `WASM_INIT_FAILED`.

## Service Worker integration (non-goal for v1, documented extension point)

The chat's SW header-injection pattern is **out of scope** for the library (consumer-specific),
but `openFromUrl` returning the token synchronously-enough is designed to not preclude it. A
`docs/` recipe stub will describe the pattern with the caveat from the assessment (Network tab
sees the final authenticated request regardless).
