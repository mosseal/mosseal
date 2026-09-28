//! Expiry enforcement + internet-time sources (spec 07).
//!
//! Raw NTP is impossible in browsers (UDP). The chat's `cloudflare.com` HEAD
//! `Date`-header idea fails CORS (`Date` is not exposed cross-origin), so this
//! module fetches small CORS-enabled bodies instead and parses timestamps
//! from them.
//!
//! Modes (compile-time `MOSSEAL_STRICT_TIME`):
//! - **lenient** (default): net time → system-clock fallback on failure.
//! - **strict**: net time or `STRICT_TIME_UNAVAILABLE` — no fallback, per the
//!   original requirement.
//!
//! `exp = 0` (no expiry) never triggers a fetch: links without expiry stay
//! fully offline-capable.
//!
//! This module defines the source list, parsing, mode logic, and a cache; the
//! actual network fetch is injected as a trait so native tests use fixtures
//! and wasm supplies the `fetch` implementation (spec 02 crate boundary).

use crate::{ErrorCode, MossealError, Result};
use std::borrow::Cow;

/// Default CORS-enabled, body-parseable time sources (D14, spec 07).
pub const DEFAULT_TIME_SOURCES: &[TimeSource] = &[
    TimeSource {
        id: Cow::Borrowed("cloudflare-trace"),
        url: Cow::Borrowed("https://cloudflare.com/cdn-cgi/trace"),
        format: SourceFormat::CloudflareTrace,
    },
    TimeSource {
        id: Cow::Borrowed("timeapi-io"),
        url: Cow::Borrowed("https://timeapi.io/api/Time/current/zone?timeZone=UTC"),
        format: SourceFormat::UnixSecJson,
    },
    TimeSource {
        id: Cow::Borrowed("worldtimeapi"),
        url: Cow::Borrowed("https://worldtimeapi.org/api/timezone/Etc/UTC"),
        format: SourceFormat::WorldTimeApi,
    },
];

/// Overall budget for the parallel fetch (spec 07: 4 s default).
pub const FETCH_TIMEOUT_SECS: f64 = 4.0;

/// Accept-skew on comparisons to tolerate source clock jitter (spec 07: 30 s).
pub const ACCEPT_SKEW_SECS: f64 = 30.0;

/// Strict-mode cross-source drift tolerance (spec 07 § optional v1.1): if two
/// reachable sources disagree by more than this, strict mode refuses to open
/// (`STRICT_TIME_UNAVAILABLE`) rather than trusting a possibly-spoofed source.
pub const DRIFT_TOLERANCE_SECS: f64 = 90.0;

/// Successful net time is cached for the page session (10 min TTL).
pub const CACHE_TTL_SECS: f64 = 600.0;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SourceFormat {
    /// `https://cloudflare.com/cdn-cgi/trace` — body line `ts=<unix>.<frac>`.
    CloudflareTrace,
    /// `timeapi.io` current/zone JSON — `"unixTime": <seconds>` (older API
    /// used `time`/`datetime`, we parse `unixTime`).
    UnixSecJson,
    /// `worldtimeapi.org` — `"unixtime": <seconds>`.
    WorldTimeApi,
}

/// A time source. `id`/`url` are `Cow` so the compile-time default list stays a
/// `const` slice of borrowed strings while consumer overrides
/// (`MOSSEAL_TIME_SOURCES`) live as owned strings in [`TimeResolver`]. Use
/// [`TimeSource::new`] to build an owned one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TimeSource {
    pub id: Cow<'static, str>,
    pub url: Cow<'static, str>,
    pub format: SourceFormat,
}

impl TimeSource {
    pub fn new(
        id: impl Into<Cow<'static, str>>,
        url: impl Into<Cow<'static, str>>,
        format: SourceFormat,
    ) -> Self {
        Self {
            id: id.into(),
            url: url.into(),
            format,
        }
    }
}

impl SourceFormat {
    /// Parse a fetched body to Unix seconds.
    pub fn parse_unix_secs(&self, body: &str) -> Option<f64> {
        match self {
            SourceFormat::CloudflareTrace => body
                .lines()
                .find(|l| l.starts_with("ts="))
                .and_then(|l| l[3..].trim().parse::<f64>().ok()),
            SourceFormat::UnixSecJson => {
                let v: serde_json::Value = serde_json::from_str(body).ok()?;
                v.get("unixTime")?.as_f64()
            }
            SourceFormat::WorldTimeApi => {
                let v: serde_json::Value = serde_json::from_str(body).ok()?;
                v.get("unixtime")?.as_f64()
            }
        }
    }
}

/// Parse a consumer-supplied `MOSSEAL_TIME_SOURCES` string (comma-separated
/// https URLs) into sources (spec 07 § Time sources).
///
/// Every custom URL uses [`SourceFormat::UnixSecJson`], the safe default: the
/// consumer cannot tell the builder which parser to use, so we pick the most
/// common JSON shape (`"unixTime"`). An entry that parses to no `unixTime` is
/// simply skipped by [`first_valid_time`] — the same as any failed source.
///
/// Returns `None` for an empty/whitespace-only string, meaning "use the
/// defaults". Non-https entries are dropped defensively (the builder already
/// rejects them; the core must never fetch a downgraded URL).
pub fn parse_time_sources(spec: &str) -> Option<Vec<TimeSource>> {
    let urls: Vec<&str> = spec
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .collect();
    if urls.is_empty() {
        return None;
    }
    let sources: Vec<TimeSource> = urls
        .into_iter()
        .filter(|u| u.starts_with("https://"))
        .enumerate()
        .map(|(i, url)| {
            TimeSource::new(
                format!("custom-{i}"),
                url.to_string(),
                SourceFormat::UnixSecJson,
            )
        })
        .collect();
    if sources.is_empty() {
        None
    } else {
        Some(sources)
    }
}

/// The default time-source list (spec 07), as owned values for [`TimeResolver`].
pub fn default_time_sources() -> Vec<TimeSource> {
    DEFAULT_TIME_SOURCES.to_vec()
}

/// Select the first successfully-parsed time across time sources.
///
/// `bodies[i]` is the fetched body for `sources[i]`, or `None` when that
/// source failed. Spec 07: the result is order-stable and **first success
/// wins across ALL sources** — a failed or unparseable source must be skipped,
/// never abort the loop. This is the bug fixed in the wasm fetch path
/// (`let Some(body) = ... else { continue }`); it lives here so it is
/// natively testable.
pub fn first_valid_time(sources: &[TimeSource], bodies: &[Option<&str>]) -> Option<f64> {
    for (source, body) in sources.iter().zip(bodies.iter()) {
        let Some(body) = body else { continue };
        if let Some(secs) = source.format.parse_unix_secs(body) {
            return Some(secs);
        }
    }
    None
}

/// Parse **every** successfully-fetched source to Unix seconds (order-stable,
/// failures dropped). Used by strict-mode cross-source drift sanity (spec 07
/// § optional v1.1): the caller compares the spread of the returned values.
pub fn all_valid_times(sources: &[TimeSource], bodies: &[Option<&str>]) -> Vec<f64> {
    sources
        .iter()
        .zip(bodies.iter())
        .filter_map(|(source, body)| {
            let body = body.as_ref()?;
            source.format.parse_unix_secs(body)
        })
        .collect()
}

/// Strict-mode drift check (spec 07 § optional v1.1): given the times parsed
/// from every reachable source, return `true` when they are consistent within
/// [`DRIFT_TOLERANCE_SECS`]. Fewer than two samples is trivially consistent
/// (nothing to cross-check). A wide spread suggests a single spoofed source.
pub fn drift_within_tolerance(times: &[f64]) -> bool {
    if times.len() < 2 {
        return true;
    }
    let min = times.iter().cloned().fold(f64::INFINITY, f64::min);
    let max = times.iter().cloned().fold(f64::NEG_INFINITY, f64::max);
    (max - min) <= DRIFT_TOLERANCE_SECS
}

/// Mode selected at compile time (spec 07 § Modes).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TimeMode {
    Lenient,
    Strict,
}

impl TimeMode {
    pub fn from_build() -> Self {
        match option_env!("MOSSEAL_STRICT_TIME") {
            Some("true") => Self::Strict,
            _ => Self::Lenient,
        }
    }
}

impl Default for TimeMode {
    fn default() -> Self {
        Self::from_build()
    }
}

/// The fetch strategy, injected so native tests use fixtures and wasm uses
/// the browser `fetch` (spec 02 crate boundary).
pub trait FetchTimes {
    /// Fetch all sources in parallel (or fail fast); return first success.
    fn fetch_unix_secs(&self, sources: &[TimeSource]) -> Option<f64>;

    /// Fetch all sources and return **every** successfully-parsed time (order
    /// stable, failures dropped). Used only for strict-mode cross-source drift
    /// sanity (spec 07 § optional v1.1). The default derives from
    /// [`FetchTimes::fetch_unix_secs`], so existing fetchers need no change and
    /// simply report a single sample (drift is then trivially consistent).
    fn fetch_all_unix_secs(&self, sources: &[TimeSource]) -> Vec<f64> {
        self.fetch_unix_secs(sources).into_iter().collect()
    }

    /// Platform system clock in Unix seconds.
    ///
    /// Defaults to [`system_clock_secs`] (std). The wasm layer MUST override
    /// this: `std::time::SystemTime::now()` panics on `wasm32-unknown-unknown`
    /// ("time not implemented on this platform"), which would abort every
    /// expiring-link open. wasm uses `js_sys::Date::now()` instead.
    fn system_now_secs(&self) -> f64 {
        system_clock_secs()
    }
}

impl<F: FetchTimes> FetchTimes for &F {
    fn fetch_unix_secs(&self, sources: &[TimeSource]) -> Option<f64> {
        (**self).fetch_unix_secs(sources)
    }

    fn fetch_all_unix_secs(&self, sources: &[TimeSource]) -> Vec<f64> {
        (**self).fetch_all_unix_secs(sources)
    }

    fn system_now_secs(&self) -> f64 {
        (**self).system_now_secs()
    }
}

/// System clock fallback (lenient mode only).
pub fn system_clock_secs() -> f64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs_f64())
        .unwrap_or_default()
}

/// Central time resolution honoring mode + cache (spec 07 § Caching).
pub struct TimeResolver<F: FetchTimes> {
    fetcher: F,
    mode: TimeMode,
    /// Sources to consult. Defaults to [`DEFAULT_TIME_SOURCES`]; a consumer
    /// `MOSSEAL_TIME_SOURCES` override replaces the list wholesale (spec 07).
    sources: Vec<TimeSource>,
    cached: Option<(f64, f64)>, // (resolved_at_epoch, unix_secs)
}

impl<F: FetchTimes> TimeResolver<F> {
    /// Resolver over the default sources (spec 07).
    pub fn new(fetcher: F, mode: TimeMode) -> Self {
        Self::with_sources(fetcher, mode, default_time_sources())
    }

    /// Resolver over an explicit source list. An empty list falls back to the
    /// defaults so a consumer can never disable net time entirely by accident.
    pub fn with_sources(fetcher: F, mode: TimeMode, sources: Vec<TimeSource>) -> Self {
        Self {
            fetcher,
            mode,
            sources: if sources.is_empty() {
                default_time_sources()
            } else {
                sources
            },
            cached: None,
        }
    }

    /// The sources this resolver consults (defaults unless overridden).
    pub fn sources(&self) -> &[TimeSource] {
        &self.sources
    }

    /// Resolve current time. `exp` of 0 (no expiry) must skip this entirely —
    /// callers gate on that before calling (spec 07 § Envelope interaction).
    pub fn resolve(&mut self) -> Result<f64> {
        if let Some((at, secs)) = self.cached {
            let now = self.fetcher.system_now_secs();
            if now - at < CACHE_TTL_SECS {
                return Ok(secs);
            }
        }
        // One fetch call yields every reachable source's time (order-stable).
        // The first entry is the spec-07 "first success wins" value; the whole
        // set feeds strict-mode drift sanity. Fetchers that only implement
        // `fetch_unix_secs` report a single sample via the trait default.
        let all = self.fetcher.fetch_all_unix_secs(&self.sources);
        match all.first().copied() {
            Some(secs) => {
                // Strict-mode cross-source drift sanity (spec 07 § optional
                // v1.1): if the reachable sources disagree by more than
                // DRIFT_TOLERANCE_SECS, refuse rather than trust a possibly
                // spoofed source. Lenient mode keeps first-success behavior.
                if self.mode == TimeMode::Strict && !drift_within_tolerance(&all) {
                    return Err(MossealError::new(
                        ErrorCode::StrictTimeUnavailable,
                        "time sources disagree beyond drift tolerance in strict mode",
                    ));
                }
                self.cached = Some((self.fetcher.system_now_secs(), secs));
                Ok(secs)
            }
            None => match self.mode {
                TimeMode::Lenient => Ok(self.fetcher.system_now_secs()),
                TimeMode::Strict => Err(MossealError::new(
                    ErrorCode::StrictTimeUnavailable,
                    "net time unreachable in strict mode; no fallback",
                )),
            },
        }
    }

    /// Enforce expiry with ACCEPT_SKEW_SECS tolerance; `exp == 0` = no check.
    pub fn check_expiry(&mut self, exp: u64) -> Result<()> {
        if exp == 0 {
            return Ok(());
        }
        let now = self.resolve()?;
        if now > exp as f64 + ACCEPT_SKEW_SECS {
            return Err(MossealError::new(
                ErrorCode::Expired,
                format!("exp {exp} < now {now:.0}"),
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct FixtureFetch(Option<f64>);
    impl FetchTimes for FixtureFetch {
        fn fetch_unix_secs(&self, _s: &[TimeSource]) -> Option<f64> {
            self.0
        }
    }

    #[test]
    fn parses_cloudflare_trace() {
        let body = "fl=x\nh=cloudflare.com\nts=1770000000.123\n";
        assert_eq!(
            SourceFormat::CloudflareTrace.parse_unix_secs(body),
            Some(1770000000.123)
        );
        assert_eq!(SourceFormat::CloudflareTrace.parse_unix_secs("fl=x"), None);
    }

    #[test]
    fn parses_timeapi() {
        let body = r#"{"dateTime":"2026-01-01T00:00:00Z","unixTime":1770000000}"#;
        assert_eq!(
            SourceFormat::UnixSecJson.parse_unix_secs(body),
            Some(1770000000.0)
        );
        assert_eq!(SourceFormat::UnixSecJson.parse_unix_secs("nope"), None);
    }

    #[test]
    fn parses_worldtimeapi() {
        let body = r#"{"unixtime":1770000000,"utc":"..."}"#;
        assert_eq!(
            SourceFormat::WorldTimeApi.parse_unix_secs(body),
            Some(1770000000.0)
        );
    }

    #[test]
    fn strict_mode_fails_without_net() {
        let mut r = TimeResolver::new(FixtureFetch(None), TimeMode::Strict);
        let err = r.resolve().unwrap_err();
        assert_eq!(err.code, ErrorCode::StrictTimeUnavailable);
    }

    #[test]
    fn lenient_mode_falls_back_to_system_clock() {
        let mut r = TimeResolver::new(FixtureFetch(None), TimeMode::Lenient);
        assert!(r.resolve().is_ok());
    }

    #[test]
    fn exp_zero_never_checks() {
        let mut r = TimeResolver::new(FixtureFetch(None), TimeMode::Strict);
        assert!(r.check_expiry(0).is_ok(), "exp=0 skips time entirely");
    }

    #[test]
    fn expiry_enforced_with_skew() {
        // fixture says now = 1000
        let mut r = TimeResolver::new(FixtureFetch(Some(1000.0)), TimeMode::Strict);
        assert!(r.check_expiry(1000).is_ok(), "exact boundary ok");
        assert!(r.check_expiry(999).is_ok(), "within skew window");
        assert!(
            r.check_expiry(1000 - ACCEPT_SKEW_SECS as u64 - 1).is_err(),
            "beyond skew"
        );
    }

    /// Fetcher with a controllable clock + fetch counter, so cache behaviour
    /// (including TTL expiry) is observable. `Cell` lets the `&self` trait
    /// methods mutate the test clock.
    struct ClockFetch {
        net: Option<f64>,
        now: std::cell::Cell<f64>,
        net_calls: std::cell::Cell<usize>,
    }

    impl ClockFetch {
        fn new(net: Option<f64>, now: f64) -> Self {
            Self {
                net,
                now: std::cell::Cell::new(now),
                net_calls: std::cell::Cell::new(0),
            }
        }
    }

    impl FetchTimes for ClockFetch {
        fn fetch_unix_secs(&self, _s: &[TimeSource]) -> Option<f64> {
            self.net_calls.set(self.net_calls.get() + 1);
            self.net
        }
        fn system_now_secs(&self) -> f64 {
            self.now.get()
        }
    }

    #[test]
    fn net_time_cached_within_ttl_then_refetched() {
        let mut r = TimeResolver::new(ClockFetch::new(Some(1000.0), 5000.0), TimeMode::Strict);
        assert_eq!(r.resolve().unwrap(), 1000.0);
        assert_eq!(r.fetcher.net_calls.get(), 1);

        // Within the TTL window: served from cache, no new fetch.
        r.fetcher.now.set(5000.0 + CACHE_TTL_SECS - 1.0);
        assert_eq!(r.resolve().unwrap(), 1000.0);
        assert_eq!(r.fetcher.net_calls.get(), 1, "cache hit must not refetch");

        // Past the TTL: cache is stale, so it fetches again.
        r.fetcher.now.set(5000.0 + CACHE_TTL_SECS + 1.0);
        assert_eq!(r.resolve().unwrap(), 1000.0);
        assert_eq!(r.fetcher.net_calls.get(), 2, "stale cache must refetch");
    }

    #[test]
    fn lenient_cache_survives_net_outage() {
        // A still-fresh cached value keeps working even if the net later fails.
        let mut r = TimeResolver::new(ClockFetch::new(Some(1000.0), 5000.0), TimeMode::Lenient);
        assert_eq!(r.resolve().unwrap(), 1000.0);
        r.fetcher.net = None;
        r.fetcher.now.set(5000.0 + 1.0);
        assert_eq!(r.resolve().unwrap(), 1000.0, "cache still fresh");
    }

    #[test]
    fn ref_fetcher_delegates() {
        fn fetch_via<F: FetchTimes>(f: F) -> Option<f64> {
            f.fetch_unix_secs(DEFAULT_TIME_SOURCES)
        }
        let f = FixtureFetch(Some(42.0));
        // `&FixtureFetch` uses the blanket `impl FetchTimes for &F`.
        assert_eq!(fetch_via(&f), Some(42.0));
    }

    #[test]
    fn system_clock_is_after_2020() {
        // Sanity: the real clock is plausible (guards a swapped/frozen clock).
        assert!(system_clock_secs() > 1_600_000_000.0);
    }

    #[test]
    fn first_valid_time_skips_failures_and_keeps_order() {
        // Source 0 failed (None), source 1 unparseable, source 2 valid.
        let bodies = [None, Some("garbage"), Some("{\"unixtime\":42}")];
        assert_eq!(first_valid_time(DEFAULT_TIME_SOURCES, &bodies), Some(42.0));

        // First success wins: source 0 valid, source 2 also valid.
        let bodies = [
            Some("ts=1000.0\n"),
            Some("garbage"),
            Some("{\"unixtime\":42}"),
        ];
        assert_eq!(
            first_valid_time(DEFAULT_TIME_SOURCES, &bodies),
            Some(1000.0),
            "a later valid source must not override an earlier one"
        );
    }

    #[test]
    fn first_valid_time_all_failed_is_none() {
        let bodies = [None, None, None];
        assert_eq!(first_valid_time(DEFAULT_TIME_SOURCES, &bodies), None);
        // The real spec-07 bug: a leading `None` must NOT abort the loop, so a
        // later valid body still resolves.
        let bodies = [None, None, Some("{\"unixtime\":7}")];
        assert_eq!(first_valid_time(DEFAULT_TIME_SOURCES, &bodies), Some(7.0));
    }

    #[test]
    fn all_valid_times_collects_every_success() {
        let bodies = [
            Some("ts=1000.0\n"),
            Some("garbage"),
            Some("{\"unixtime\":1040}"),
        ];
        assert_eq!(
            all_valid_times(DEFAULT_TIME_SOURCES, &bodies),
            vec![1000.0, 1040.0]
        );
        // All failed → empty (nothing to cross-check).
        assert!(all_valid_times(DEFAULT_TIME_SOURCES, &[None, None, None]).is_empty());
    }

    #[test]
    fn drift_within_tolerance_boundaries() {
        // Fewer than two samples: trivially consistent.
        assert!(drift_within_tolerance(&[]));
        assert!(drift_within_tolerance(&[1000.0]));
        // Exactly at the tolerance is accepted; just past it is not.
        assert!(drift_within_tolerance(&[
            1000.0,
            1000.0 + DRIFT_TOLERANCE_SECS
        ]));
        assert!(!drift_within_tolerance(&[
            1000.0,
            1000.0 + DRIFT_TOLERANCE_SECS + 1.0
        ]));
        // Order-independent (min/max, not first/last).
        assert!(!drift_within_tolerance(&[2000.0, 1000.0]));
    }

    /// Fetcher returning a fixed set of per-source times, so strict-mode drift
    /// handling is observable.
    struct DriftFetch(Vec<f64>);
    impl FetchTimes for DriftFetch {
        fn fetch_unix_secs(&self, _s: &[TimeSource]) -> Option<f64> {
            self.0.first().copied()
        }
        fn fetch_all_unix_secs(&self, _s: &[TimeSource]) -> Vec<f64> {
            self.0.clone()
        }
    }

    #[test]
    fn strict_mode_rejects_cross_source_drift() {
        // Two sources 200 s apart → beyond the 90 s tolerance.
        let mut r = TimeResolver::new(DriftFetch(vec![1000.0, 1200.0]), TimeMode::Strict);
        let err = r.resolve().unwrap_err();
        assert_eq!(err.code, ErrorCode::StrictTimeUnavailable);
    }

    #[test]
    fn strict_mode_accepts_consistent_sources() {
        let mut r = TimeResolver::new(DriftFetch(vec![1000.0, 1040.0]), TimeMode::Strict);
        assert_eq!(r.resolve().unwrap(), 1000.0);
    }

    #[test]
    fn lenient_mode_ignores_cross_source_drift() {
        // Lenient keeps first-success even when sources disagree wildly.
        let mut r = TimeResolver::new(DriftFetch(vec![1000.0, 9999.0]), TimeMode::Lenient);
        assert_eq!(r.resolve().unwrap(), 1000.0);
    }

    #[test]
    fn parse_time_sources_empty_means_defaults() {
        assert!(parse_time_sources("").is_none());
        assert!(parse_time_sources("   ").is_none());
        assert!(parse_time_sources(" , ,").is_none());
    }

    #[test]
    fn parse_time_sources_splits_trims_and_orders() {
        let sources = parse_time_sources("https://a.test/t, https://b.test/t ").unwrap();
        assert_eq!(sources.len(), 2);
        assert_eq!(sources[0].url, "https://a.test/t");
        assert_eq!(sources[1].url, "https://b.test/t");
        assert_eq!(sources[0].id, "custom-0");
        assert_eq!(sources[1].id, "custom-1");
        // Custom URLs use the safe JSON default parser.
        assert_eq!(sources[0].format, SourceFormat::UnixSecJson);
    }

    #[test]
    fn parse_time_sources_drops_non_https_entries() {
        // Defensive: the builder rejects http, but core must never fetch it.
        let sources = parse_time_sources("http://evil.test/t, https://ok.test/t").unwrap();
        assert_eq!(sources.len(), 1);
        assert_eq!(sources[0].url, "https://ok.test/t");
        // All-dropped → None (use defaults), never an empty source list.
        assert!(parse_time_sources("http://evil.test/t").is_none());
    }

    #[test]
    fn resolver_uses_custom_sources_when_provided() {
        // The fetcher records the URLs it was asked to fetch, so we can prove
        // the override actually reaches the fetch call.
        struct UrlSpy(std::cell::RefCell<Vec<String>>);
        impl FetchTimes for UrlSpy {
            fn fetch_unix_secs(&self, sources: &[TimeSource]) -> Option<f64> {
                *self.0.borrow_mut() = sources.iter().map(|s| s.url.to_string()).collect();
                Some(1000.0)
            }
        }
        let spy = UrlSpy(std::cell::RefCell::new(Vec::new()));
        let custom = parse_time_sources("https://a.test/t").unwrap();
        let mut r = TimeResolver::with_sources(spy, TimeMode::Strict, custom);
        assert_eq!(r.resolve().unwrap(), 1000.0);
        assert_eq!(
            *r.fetcher.0.borrow(),
            vec!["https://a.test/t".to_string()],
            "custom source must be the one consulted"
        );
    }

    #[test]
    fn resolver_empty_sources_fall_back_to_defaults() {
        let r = TimeResolver::with_sources(FixtureFetch(None), TimeMode::Lenient, Vec::new());
        assert_eq!(r.sources(), DEFAULT_TIME_SOURCES);
    }
}
