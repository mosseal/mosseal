//! Admin wasm surface for the MOSSEAL TS CLI (spec 05, trusted admin path).
//!
//! This crate exists so `npx mosseal gen-secret|seal|open` can run the SAME
//! crypto as the native `mosseal-cli` binary without requiring a Rust toolchain
//! on the consumer's machine. It is a thin `#[wasm_bindgen]` wrapper over
//! `mosseal-core` and mirrors `mosseal-cli`'s trusted-path semantics exactly:
//!
//!   * `runtime_hostname: None` — spec 03: the trusted Node/CLI path skips the
//!     runtime host gate.
//!   * `TimeMode::Lenient` + a no-network fetcher — the admin path never blocks
//!     on internet time (spec 07); expiry is checked against the local clock.
//!
//! Unlike `mosseal-wasm` (the consumer envelope surface), epochs and domains are
//! passed in at RUNTIME as constructor arguments rather than baked in via
//! `obfuse!` codegen. That is deliberate: the admin CLI is a trusted local tool,
//! so there is nothing to obfuscate from the operator, and it lets one shipped
//! wasm artifact serve every deployment.
//!
//! `gen-secret` is intentionally NOT exposed here — the TS CLI generates epoch
//! secrets with `node:crypto` (`randomBytes(32).toString("base64url")`), which
//! is byte-identical to the native implementation and needs no wasm.

use mosseal_core::{
    binding,
    epoch::EpochRegistry,
    kdf::Argon2Profile,
    seal::{
        CoverDecoy, CoverMode, DeniableSealInput, HiddenSpec, MultiSealInput, MultiSlot,
        OpenOutput, SealContext, SealInput, SizeClass,
    },
    time::{FetchTimes, TimeMode, TimeSource},
    ErrorCode, MossealError,
};
use wasm_bindgen::prelude::*;

/// Error taxonomy helper: JS sees a stable, machine-readable code (spec 02)
/// followed by the human-readable detail, e.g. `BAD_PASSWORD: gcm tag mismatch`.
///
/// This mirrors the native `mosseal-cli`'s `Error: <CODE>: <detail>` output so
/// the two admin surfaces are interchangeable. (The CONSUMER `mosseal-wasm`
/// surface deliberately keeps the message as the bare code, because
/// `@mosseal/core` matches on it verbatim — the admin surface has no such
/// constraint.)
fn js_err(e: MossealError) -> JsError {
    JsError::new(&format!("{}: {}", e.code.as_str(), e.detail))
}

/// No-network time fetcher for the trusted admin path.
///
/// `fetch_unix_secs` always returns `None` (the CLI never blocks on net time),
/// so expiry is evaluated against the local clock. `system_now_secs` MUST be
/// overridden: the trait default calls `std::time::SystemTime::now()`, which
/// panics on `wasm32-unknown-unknown`. `js_sys::Date::now()` is the wasm-safe
/// equivalent (milliseconds since the Unix epoch).
struct JsFetch;

impl FetchTimes for JsFetch {
    fn fetch_unix_secs(&self, _sources: &[TimeSource]) -> Option<f64> {
        None
    }

    fn system_now_secs(&self) -> f64 {
        js_sys::Date::now() / 1000.0
    }
}

/// Admin seal/open context bound to a deployment's epochs + domain whitelist.
#[wasm_bindgen]
pub struct Admin {
    ctx: SealContext,
}

#[wasm_bindgen]
impl Admin {
    /// Build an admin context.
    ///
    /// * `epochs` — base64url 32-byte epoch secrets joined by `;` (epoch 0
    ///   first; an empty entry is a retired hole). Same format as the native
    ///   CLI's `--epochs` / `MOSSEAL_EPOCHS`.
    /// * `domains` — comma-separated bare lowercase hostnames (spec 03). Same
    ///   format as the native CLI's `--domains` / `MOSSEAL_ALLOWED_DOMAINS`.
    ///
    /// Validation mirrors `mosseal-cli::context_from` so a bad `.env` fails the
    /// same way in both surfaces. Note the split preserves empty entries (like
    /// clap's `value_delimiter`), so `"a.test,"` is rejected rather than
    /// silently trimmed — matching the native CLI exactly.
    #[wasm_bindgen(constructor)]
    pub fn new(epochs: String, domains: String) -> Result<Admin, JsError> {
        console_error_panic_hook::set_once();

        let registry = EpochRegistry::parse(&epochs).map_err(js_err)?;
        let whitelist: Vec<String> = domains.split(',').map(str::to_string).collect();
        binding::validate_whitelist(&whitelist).map_err(js_err)?;

        Ok(Admin {
            ctx: SealContext {
                epochs: registry,
                whitelist,
                argon_profile: Argon2Profile::from_build(),
                time_mode: TimeMode::Lenient, // trusted; never blocks on net time
                runtime_hostname: None,       // spec 03: CLI path skips the gate
                time_sources: Vec::new(),     // defaults (spec 07)
            },
        })
    }

    /// Seal `data` into a fragment string (the part after `#ms=`).
    ///
    /// `exp_secs` of `null`/`0` means no expiry. `password` of `null`/`""`
    /// selects the default (no-password) mode. `kind` defaults to `TOKEN`.
    #[wasm_bindgen]
    pub fn seal(
        &self,
        data: String,
        password: Option<String>,
        exp_secs: Option<f64>,
        kind: Option<u8>,
    ) -> Result<String, JsError> {
        let pw = password.filter(|p| !p.is_empty()).map(String::into_bytes);
        let input = SealInput {
            data: data.into_bytes(),
            kind: kind.unwrap_or(mosseal_core::envelope::kind::TOKEN),
            exp: exp_secs.filter(|e| *e > 0.0).map(|e| e as u64),
            password: pw,
            deterministic_salt: None,
            deterministic_nonce: None,
            deterministic_epoch: None,
            deterministic_version: None,
        };
        self.ctx.seal(&input).map_err(js_err)
    }

    /// Seal N password-keyed secrets into one `MULTI` fragment (spec 01 §
    /// MULTI). `slots_json` is a JSON array of
    /// `{"password","data","kind"?,"expSecs"?}` objects.
    #[wasm_bindgen(js_name = sealMulti)]
    pub fn seal_multi(&self, slots_json: String, exp_secs: Option<f64>) -> Result<String, JsError> {
        let entries: Vec<SlotJson> = serde_json::from_str(&slots_json).map_err(|e| {
            JsError::new(&format!(
                "{}: invalid slots JSON: {e}",
                ErrorCode::MalformedEnvelope.as_str()
            ))
        })?;
        let default_exp = exp_from_f64(exp_secs).map_err(js_err)?;
        let input = MultiSealInput {
            slots: entries
                .into_iter()
                .map(|s| {
                    Ok(MultiSlot {
                        password: s.password.into_bytes(),
                        data: s.data.into_bytes(),
                        kind: s.kind.unwrap_or(mosseal_core::envelope::kind::TOKEN),
                        exp: exp_from_f64(s.exp_secs).map_err(js_err)?.or(default_exp),
                    })
                })
                .collect::<Result<Vec<_>, JsError>>()?,
            deterministic_slot_salts: None,
            deterministic_slot_nonces: None,
            deterministic_salt: None,
            deterministic_nonce: None,
            deterministic_epoch: None,
        };
        self.ctx.seal_multi(&input).map_err(js_err)
    }

    /// Seal a deniable link (spec 09). `cover_json` is
    /// `{"mode"?: "hidden"|"plain", "password"?, "decoy"?}`; `hidden_json` is
    /// `{"password", "data"?|"slots": [...]}`. `size_class` is 1, 2, or 4
    /// (KiB); omitted picks the smallest class that fits.
    #[wasm_bindgen(js_name = sealDeniable)]
    pub fn seal_deniable(
        &self,
        cover_json: String,
        hidden_json: String,
        size_class: Option<u8>,
    ) -> Result<String, JsError> {
        let cover: CoverJson = serde_json::from_str(&cover_json).map_err(|e| {
            JsError::new(&format!(
                "{}: invalid cover JSON: {e}",
                ErrorCode::MalformedEnvelope.as_str()
            ))
        })?;
        let hidden: HiddenJson = serde_json::from_str(&hidden_json).map_err(|e| {
            JsError::new(&format!(
                "{}: invalid hidden JSON: {e}",
                ErrorCode::MalformedEnvelope.as_str()
            ))
        })?;
        let input = deniable_input_from_json(cover, hidden, size_class).map_err(js_err)?;
        self.ctx.seal_deniable(&input).map_err(js_err)
    }

    /// Open a deniable link's hidden layer (spec 09). `cover_password` opens
    /// the cover (mode=hidden only); `hidden_password` recovers and opens the
    /// hidden layer. Recovery failures uniformly yield `BAD_PASSWORD`.
    #[wasm_bindgen(js_name = openHidden)]
    pub fn open_hidden(
        &self,
        fragment: String,
        cover_password: Option<String>,
        hidden_password: Option<String>,
        ignore_expiry: Option<bool>,
    ) -> Result<JsValue, JsError> {
        let cpw = cover_password
            .filter(|p| !p.is_empty())
            .map(String::into_bytes);
        let hpw = hidden_password
            .filter(|p| !p.is_empty())
            .map(String::into_bytes);
        let fetcher = JsFetch;
        let out: OpenOutput = if ignore_expiry.unwrap_or(false) {
            self.ctx.open_deniable_ignoring_expiry(
                &fragment,
                cpw.as_deref(),
                hpw.as_deref(),
                &fetcher,
            )
        } else {
            self.ctx
                .open_deniable(&fragment, cpw.as_deref(), hpw.as_deref(), &fetcher)
        }
        .map_err(js_err)?;
        open_js(out)
    }

    /// Open and verify a fragment.
    ///
    /// When `ignore_expiry` is set only the expiry check is skipped; domain
    /// binding, key epoch, password, and the AEAD tag are still verified
    /// (mirrors `mosseal-cli open --ignore-expiry`).
    ///
    /// Returns `{ data, exp, kind, version }`. Errors carry the stable code
    /// string. `version` is the CLI-only envelope-version exposure (D9).
    #[wasm_bindgen]
    pub fn open(
        &self,
        fragment: String,
        password: Option<String>,
        ignore_expiry: Option<bool>,
    ) -> Result<JsValue, JsError> {
        let pw = password.filter(|p| !p.is_empty()).map(String::into_bytes);
        let fetcher = JsFetch;
        let out: OpenOutput = if ignore_expiry.unwrap_or(false) {
            self.ctx
                .open_ignoring_expiry(&fragment, pw.as_deref(), &fetcher)
        } else {
            self.ctx.open(&fragment, pw.as_deref(), &fetcher)
        }
        .map_err(js_err)?;
        open_js(out)
    }
}

/// One slot entry of `sealMulti` / hidden-`MULTI` JSON.
#[derive(serde::Deserialize)]
struct SlotJson {
    password: String,
    data: String,
    #[serde(default)]
    kind: Option<u8>,
    #[serde(rename = "expSecs", default)]
    exp_secs: Option<f64>,
}

/// Cover configuration of `sealDeniable` JSON.
#[derive(serde::Deserialize)]
struct CoverJson {
    #[serde(default)]
    mode: Option<String>,
    #[serde(default)]
    password: Option<String>,
    #[serde(default)]
    decoy: Option<String>,
}

/// Hidden configuration of `sealDeniable` JSON.
#[derive(serde::Deserialize)]
struct HiddenJson {
    password: String,
    #[serde(default)]
    data: Option<String>,
    #[serde(default)]
    kind: Option<u8>,
    #[serde(rename = "expSecs", default)]
    exp_secs: Option<f64>,
    #[serde(default)]
    slots: Option<Vec<SlotJson>>,
}

/// Validate a JS-supplied expiry (spec 04/05 parity): JSON numbers arrive as
/// f64, but the native CLI's serde `u64` rejects fractional/negative values
/// — every surface must agree, so invalid values error here too instead of
/// silently truncating or falling back to a default expiry.
fn exp_from_f64(e: Option<f64>) -> Result<Option<u64>, MossealError> {
    match e {
        None => Ok(None),
        Some(v) if v < 0.0 || v.fract() != 0.0 => Err(MossealError::new(
            ErrorCode::MalformedEnvelope,
            "expSecs must be a non-negative integer number of seconds",
        )),
        Some(v) => Ok((v > 0.0).then_some(v as u64)),
    }
}

fn deniable_input_from_json(
    cover: CoverJson,
    hidden: HiddenJson,
    size_class: Option<u8>,
) -> Result<DeniableSealInput, MossealError> {
    let cover_mode = match cover.mode.as_deref() {
        None | Some("plain") => CoverMode::Plain,
        Some("hidden") => CoverMode::Hidden,
        Some(other) => {
            return Err(MossealError::new(
                ErrorCode::MalformedEnvelope,
                format!("cover mode must be \"hidden\" or \"plain\", got {other:?}"),
            ))
        }
    };
    let hidden_spec = match (hidden.slots, hidden.data) {
        (Some(slots), _) => HiddenSpec::Multi(MultiSealInput {
            slots: slots
                .into_iter()
                .map(|s| {
                    Ok(MultiSlot {
                        password: s.password.into_bytes(),
                        data: s.data.into_bytes(),
                        kind: s.kind.unwrap_or(mosseal_core::envelope::kind::TOKEN),
                        exp: exp_from_f64(s.exp_secs)?,
                    })
                })
                .collect::<Result<Vec<_>, MossealError>>()?,
            deterministic_slot_salts: None,
            deterministic_slot_nonces: None,
            deterministic_salt: None,
            deterministic_nonce: None,
            deterministic_epoch: None,
        }),
        (None, Some(data)) => HiddenSpec::Single {
            data: data.into_bytes(),
            kind: hidden.kind.unwrap_or(mosseal_core::envelope::kind::TOKEN),
            exp: exp_from_f64(hidden.exp_secs)?,
            deterministic_salt: None,
            deterministic_nonce: None,
            deterministic_epoch: None,
        },
        (None, None) => {
            return Err(MossealError::new(
                ErrorCode::MalformedEnvelope,
                "hidden must carry either data or slots",
            ))
        }
    };
    let class = match size_class {
        None => None,
        Some(1) => Some(SizeClass::Kib1),
        Some(2) => Some(SizeClass::Kib2),
        Some(4) => Some(SizeClass::Kib4),
        Some(other) => {
            return Err(MossealError::new(
                ErrorCode::MalformedEnvelope,
                format!("size class must be 1, 2, or 4 (KiB), got {other}"),
            ))
        }
    };
    Ok(DeniableSealInput {
        cover_mode,
        cover_password: cover.password.map(String::into_bytes),
        cover_decoy: match cover.decoy {
            Some(d) if !d.is_empty() => CoverDecoy::User(d.into_bytes()),
            _ => CoverDecoy::Random,
        },
        hidden_password: hidden.password.into_bytes(),
        hidden: hidden_spec,
        size_class: class,
        deterministic_salt: None,
        deterministic_nonce: None,
        deterministic_padding: None,
        deterministic_epoch: None,
    })
}

fn open_js(out: OpenOutput) -> Result<JsValue, JsError> {
    serde_wasm_bindgen::to_value(&OpenJs {
        data: String::from_utf8_lossy(&out.data).into_owned(),
        exp: out.exp,
        kind: out.kind,
        version: out.version,
    })
    .map_err(|e| JsError::new(&format!("serde: {e}")))
}

#[derive(serde::Serialize)]
struct OpenJs {
    data: String,
    exp: u64,
    kind: u8,
    version: u8,
}

#[cfg(test)]
mod tests {
    use super::*;
    use wasm_bindgen_test::wasm_bindgen_test;

    /// A deterministic 32-byte base64url secret (all bytes = `seed`).
    fn secret(seed: u8) -> String {
        use base64::Engine;
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([seed; 32])
    }

    /// Read the `.message` of a `JsError` (it is an `Error` object, not a
    /// string, so `as_string()` on the value itself returns `""`).
    fn js_error_message(err: JsError) -> String {
        let val: JsValue = err.into();
        js_sys::Reflect::get(&val, &JsValue::from_str("message"))
            .ok()
            .and_then(|m| m.as_string())
            .unwrap_or_default()
    }

    /// Read a string field from the `open()` result object.
    fn field(obj: &JsValue, name: &str) -> JsValue {
        js_sys::Reflect::get(obj, &JsValue::from_str(name)).unwrap()
    }

    #[wasm_bindgen_test]
    fn seal_then_open_roundtrip() {
        let admin = Admin::new(secret(7), "a.test".into()).unwrap();
        let frag = admin.seal("tok_abc123".into(), None, None, None).unwrap();
        let out = admin.open(frag, None, None).unwrap();
        assert_eq!(field(&out, "data").as_string().unwrap(), "tok_abc123");
        assert_eq!(field(&out, "kind").as_f64().unwrap(), 1.0);
        assert_eq!(field(&out, "exp").as_f64().unwrap(), 0.0);
    }

    #[wasm_bindgen_test]
    fn rejects_bad_epochs() {
        assert!(Admin::new("not-base64url!!".into(), "a.test".into()).is_err());
    }

    #[wasm_bindgen_test]
    fn rejects_bad_domains() {
        assert!(Admin::new(secret(1), "https://a.com".into()).is_err());
    }

    #[wasm_bindgen_test]
    fn wrong_password_is_stable_code() {
        let admin = Admin::new(secret(7), "a.test".into()).unwrap();
        let frag = admin
            .seal("tok".into(), Some("pw".into()), None, None)
            .unwrap();
        let err = admin.open(frag, Some("WRONG".into()), None).unwrap_err();
        // Message is `<CODE>: <detail>` (parity with the native CLI).
        assert!(js_error_message(err).starts_with("BAD_PASSWORD"));
    }

    #[wasm_bindgen_test]
    fn ignore_expiry_returns_payload() {
        let admin = Admin::new(secret(7), "a.test".into()).unwrap();
        // exp far in the past; the admin path uses the local clock.
        let frag = admin.seal("tok".into(), None, Some(1.0), None).unwrap();

        let err = admin.open(frag.clone(), None, None).unwrap_err();
        assert!(js_error_message(err).starts_with("EXPIRED"));

        let out = admin.open(frag, None, Some(true)).unwrap();
        assert_eq!(field(&out, "data").as_string().unwrap(), "tok");
        assert_eq!(field(&out, "exp").as_f64().unwrap(), 1.0);
    }
}
