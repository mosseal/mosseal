# Spec 07 — Expiry & Internet-Time Enforcement

## Goal

Stateless, JWT-`exp`-style expiry. Fix the two flaws from the chat: raw NTP is impossible in
browsers (UDP), and the proposed `fetch` of `cloudflare.com` root **fails CORS** — the `Date`
header is not exposed cross-origin without `Access-Control-Expose-Headers`, so the original
design would always error in strict mode.

## Time sources (CORS-enabled, body-parseable)

Default list (overridable via `MOSSEAL_TIME_SOURCES`):

1. `https://cloudflare.com/cdn-cgi/trace` — body line `ts=<unix>.<frac>`; ACAO: `*` ✅
2. `https://timeapi.io/api/Time/current/zone?timeZone=UTC` — JSON body ✅
3. `https://worldtimeapi.org/api/timezone/Etc/UTC` — JSON body ✅

`MOSSEAL_TIME_SOURCES` is a comma-separated list of `https://` URLs. `mosseal build`
validates it, then bakes it into the generated `secrets.rs` (`time_sources_str()`);
`mosseal-wasm`/the template parse it via `mosseal_core::time::parse_time_sources` and
pass the result to `SealContext.time_sources`, which the resolver uses **instead of**
`DEFAULT_TIME_SOURCES` when non-empty. An empty value keeps the defaults.

Custom URLs have no per-source parser hint, so they all use the safe JSON default
(`SourceFormat::UnixSecJson`, the `"unixTime"` key) — a body that does not match is
skipped exactly like any failed source.

Fetch strategy (`Promise.any` with a short overall timeout, default 4 s):

- `HEAD`-first optimization is abandoned (header exposure is unreliable); GET the small bodies.
- Parse each to a Unix seconds value; accept the **first successful** source.
- Optional (v1.1, not blocking): cross-source drift sanity — if two sources disagree by > 90 s,
  reject with `STRICT_TIME_UNAVAILABLE` (defends single-source spoofing via local proxy).

Threat honesty: a local MITM proxy or patched `fetch` can still spoof all sources; this raises
the bar above OS-clock tampering, it does not eliminate client-side time manipulation.

## Modes (compile-time: `MOSSEAL_STRICT_TIME`)

| Mode | Net time result | Behavior |
|---|---|---|
| lenient (default) | ok | use net time |
| lenient | fail | **fall back to system clock** `Date.now()` |
| strict | ok | use net time |
| strict | fail | `STRICT_TIME_UNAVAILABLE` — decryption halted, no fallback |

The chat's requirement, preserved verbatim: in strict mode, NTP-equivalent time must be
reachable or open fails with a network/ntp error rather than falling back.

## Envelope interaction

- `exp` lives inside the AEAD payload (tamper-proof, spec 01/02).
- `exp = 0` or absent (flag bit 1) → no time check, **no network fetch** (keeps no-expiry links
  fully offline-capable).
- Grace: none in v1 (no `nbf`/skew window). A 30 s accept-skew on `>` comparisons is applied to
  tolerate source clock jitter.

## API surface in wasm

```rust
async fn now_unix(mode, sources) -> Result<f64, TimeError>
// TimeError::Network (strict), TimeError::Unavailable — mapped into the shared taxonomy
```

`seal()` never fetches net time (only `open()` does), so link generation stays offline-friendly
for CLI admin scripts.

## Caching

Successful net time is cached in-memory for the page session (10 min TTL, plus
request-duration offset) to avoid refetching on every `open()` of multi-link imports.

## Test requirements

- exp in future → opens; exp in past → `EXPIRED` (both with mocked net time).
- Strict + blocked network → `STRICT_TIME_UNAVAILABLE`; lenient + blocked → opens via system clock.
- `exp = 0` never triggers fetch (offline smoke test).
- Source parser unit tests against pinned real response fixtures.
