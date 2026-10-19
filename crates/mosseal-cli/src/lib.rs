//! MOSSEAL CLI (spec 05, trusted admin path).
//!
//! The Node/browser path is untrusted; the CLI is the admin path (spec 03) and
//! therefore skips the runtime host gate. Logic lives here (rather than in the
//! binary) so it is unit- and integration-testable; `main.rs` is a thin shim.
//!
//! Commands:
//! - `seal` — seal a token into a share-link fragment
//! - `seal-multi` — seal N password-keyed secrets into one `MULTI` link
//! - `seal-deniable` — seal a cover link hiding a hidden layer (spec 09)
//! - `open` — open and verify a fragment (with `--ignore-expiry` for admin
//!   debugging and `--hidden-password` for the deniable path)
//! - `gen-secret` — emit a fresh 32-byte base64url epoch secret

use anyhow::Result;
use clap::{Parser, Subcommand, ValueEnum};
use mosseal_core::{
    binding,
    epoch::EpochRegistry,
    kdf::Argon2Profile,
    seal::{
        CoverDecoy, CoverMode, DeniableSealInput, HiddenSpec, MultiSealInput, MultiSlot,
        OpenOutput, SealContext, SealInput, SizeClass,
    },
    time::TimeMode,
};
use rand::TryRng;

/// Payload kind (spec 01). Mirrors the TS CLI's `--kind token|binary_blob`.
#[derive(Clone, Copy, Debug, ValueEnum, PartialEq, Eq)]
pub enum Kind {
    Token,
    BinaryBlob,
}

impl Kind {
    fn byte(self) -> u8 {
        match self {
            Kind::Token => mosseal_core::envelope::kind::TOKEN,
            Kind::BinaryBlob => mosseal_core::envelope::kind::BINARY_BLOB,
        }
    }
}

/// A slots-file `kind` value (spec 05): accepts the string form (`"token"`,
/// `"binary-blob"`/`"binary_blob"`/`"blob"`) or the wire kind byte (`1`/`2`)
/// so one slots-file works across every admin surface (native CLI, TS CLI).
#[derive(Debug, Clone, PartialEq, Eq, serde::Deserialize)]
#[serde(untagged)]
pub enum SlotKind {
    Name(String),
    Byte(u8),
}

impl SlotKind {
    pub fn to_byte(&self) -> Result<u8> {
        match self {
            SlotKind::Byte(b) => match b {
                1 => Ok(mosseal_core::envelope::kind::TOKEN),
                2 => Ok(mosseal_core::envelope::kind::BINARY_BLOB),
                other => anyhow::bail!("unknown slot kind byte {other}"),
            },
            SlotKind::Name(s) => match s.to_ascii_lowercase().as_str() {
                "token" => Ok(mosseal_core::envelope::kind::TOKEN),
                "binary-blob" | "binary_blob" | "blob" => {
                    Ok(mosseal_core::envelope::kind::BINARY_BLOB)
                }
                other => anyhow::bail!("unknown slot kind {other:?}"),
            },
        }
    }
}

/// Cover keying for `seal-deniable` (D4, spec 09).
#[derive(Clone, Copy, Debug, ValueEnum, PartialEq, Eq)]
pub enum CoverModeArg {
    /// Password-keyed cover; hidden receiver needs both passwords.
    Hidden,
    /// Password-less cover; hidden receiver needs only the hidden password.
    Plain,
}

impl CoverModeArg {
    fn mode(self) -> CoverMode {
        match self {
            CoverModeArg::Hidden => CoverMode::Hidden,
            CoverModeArg::Plain => CoverMode::Plain,
        }
    }
}

/// Fixed total envelope size for `seal-deniable --size-class` (D5).
#[derive(Clone, Copy, Debug, ValueEnum, PartialEq, Eq)]
pub enum SizeClassArg {
    /// 1 KiB total envelope size.
    Kib1,
    /// 2 KiB total envelope size.
    Kib2,
    /// 4 KiB total envelope size.
    Kib4,
}

impl SizeClassArg {
    fn class(self) -> SizeClass {
        match self {
            SizeClassArg::Kib1 => SizeClass::Kib1,
            SizeClassArg::Kib2 => SizeClass::Kib2,
            SizeClassArg::Kib4 => SizeClass::Kib4,
        }
    }
}

/// One slot of `seal-multi` / `seal-deniable`, from `--slot "pw=secret"` or a
/// slots-file JSON entry.
#[derive(Debug, Clone, serde::Deserialize)]
pub struct SlotEntry {
    pub password: String,
    pub data: String,
    #[serde(default)]
    pub kind: Option<SlotKind>,
    #[serde(rename = "expSecs", default)]
    pub exp_secs: Option<u64>,
}

/// MOSSEAL CLI: generate and verify envelopes from a trusted machine.
/// The Node/browser path is untrusted; the CLI is the admin path (spec 03).
#[derive(Parser)]
#[command(name = "mosseal", version, about)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Subcommand)]
pub enum Command {
    /// Seal a token into a share-link fragment
    Seal {
        /// Secret material (prompted if omitted)
        token: Option<String>,
        #[arg(long)]
        password: Option<String>,
        /// Expiry in unix seconds; omit for no expiry
        #[arg(long)]
        exp: Option<u64>,
        /// Payload kind (default: token)
        #[arg(long, value_enum, default_value_t = Kind::Token)]
        kind: Kind,
        /// Epoch secrets as base64url, `;`-joined (or set MOSSEAL_EPOCHS)
        #[arg(long, env = "MOSSEAL_EPOCHS")]
        epochs: String,
        #[arg(long, env = "MOSSEAL_ALLOWED_DOMAINS", value_delimiter = ',')]
        domains: Vec<String>,
    },
    /// Seal N password-keyed secrets into one MULTI link (spec 01 § MULTI)
    SealMulti {
        /// Slot as `PASSWORD=SECRET` (repeat for each slot)
        #[arg(long = "slot", value_name = "PASSWORD=SECRET")]
        slots: Vec<String>,
        /// JSON file with a slot array: [{"password","data","kind"?,"expSecs"?}]
        #[arg(long = "slots-file", value_name = "PATH")]
        slots_file: Option<std::path::PathBuf>,
        /// Default expiry (unix seconds) for slots without their own
        #[arg(long)]
        exp: Option<u64>,
        /// Epoch secrets as base64url, `;`-joined (or set MOSSEAL_EPOCHS)
        #[arg(long, env = "MOSSEAL_EPOCHS")]
        epochs: String,
        #[arg(long, env = "MOSSEAL_ALLOWED_DOMAINS", value_delimiter = ',')]
        domains: Vec<String>,
    },
    /// Seal a deniable cover link hiding a hidden layer (spec 09)
    SealDeniable {
        /// Cover keying (default: hidden — strongest deniability)
        #[arg(long, value_enum, default_value_t = CoverModeArg::Hidden)]
        cover_mode: CoverModeArg,
        /// Cover password (prompted if omitted and mode is hidden)
        #[arg(long)]
        cover_password: Option<String>,
        /// User decoy content cycled into the cover padding
        #[arg(long, conflicts_with = "cover_decoy_random")]
        cover_decoy: Option<String>,
        /// Fill the cover padding with CSPRNG bytes (default)
        #[arg(long)]
        cover_decoy_random: bool,
        /// Hidden slot as `PASSWORD=SECRET` (repeat; the first slot's
        /// password locates the hidden layer)
        #[arg(long = "hidden-slot", value_name = "PASSWORD=SECRET")]
        hidden_slot: Vec<String>,
        /// JSON file with the hidden slot array (alternative to --hidden-slot)
        #[arg(long = "hidden-slots-file", value_name = "PATH")]
        hidden_slots_file: Option<std::path::PathBuf>,
        /// Locating password (default: first hidden slot's password)
        #[arg(long)]
        hidden_password: Option<String>,
        /// Fixed total envelope size; omit for the smallest class that fits
        #[arg(long, value_enum)]
        size_class: Option<SizeClassArg>,
        /// Epoch secrets as base64url, `;`-joined (or set MOSSEAL_EPOCHS)
        #[arg(long, env = "MOSSEAL_EPOCHS")]
        epochs: String,
        #[arg(long, env = "MOSSEAL_ALLOWED_DOMAINS", value_delimiter = ',')]
        domains: Vec<String>,
    },
    /// Open and verify a fragment
    Open {
        fragment: String,
        #[arg(long)]
        password: Option<String>,
        /// Hidden-layer password (spec 09): present → deniable open after the
        /// cover open; `--password` (if any) opens the cover
        #[arg(long)]
        hidden_password: Option<String>,
        #[arg(long, env = "MOSSEAL_EPOCHS")]
        epochs: String,
        #[arg(long, env = "MOSSEAL_ALLOWED_DOMAINS", value_delimiter = ',')]
        domains: Vec<String>,
        /// Do not enforce expiry (admin debugging); domain/epoch/password and
        /// the AEAD tag are still verified
        #[arg(long)]
        ignore_expiry: bool,
    },
    /// Generate a fresh 32-byte epoch secret (for `mosseal rotate` flows)
    GenSecret,
}

/// No-op net-time fetcher: the CLI is trusted and never blocks on net time
/// (`TimeMode::Lenient` in [`context_from`]).
pub struct NoFetch;

impl mosseal_core::time::FetchTimes for NoFetch {
    fn fetch_unix_secs(&self, _s: &[mosseal_core::time::TimeSource]) -> Option<f64> {
        None
    }
}

/// Build a [`SealContext`] from the CLI's epoch/domain inputs.
///
/// Validation mirrors the wasm `Mosseal::new` path so a bad `.env` fails the
/// same way in both places. The CLI sets `runtime_hostname: None` — spec 03
/// says the trusted Node/CLI path skips the runtime host gate.
pub fn context_from(epochs: &str, domains: Vec<String>) -> Result<SealContext> {
    let registry = EpochRegistry::parse(epochs)
        .map_err(|e| anyhow::anyhow!("{}: {}", e.code.as_str(), e.detail))?;
    binding::validate_whitelist(&domains)
        .map_err(|e| anyhow::anyhow!("{}: {}", e.code.as_str(), e.detail))?;
    Ok(SealContext {
        epochs: registry,
        whitelist: domains,
        argon_profile: Argon2Profile::from_build(),
        time_mode: TimeMode::Lenient, // CLI is trusted; never blocks on net time
        runtime_hostname: None,       // spec 03: Node/CLI path skips the gate
        time_sources: Vec::new(),     // defaults (spec 07)
    })
}

/// Seal `token` and return the fragment string (no trailing newline).
///
/// Split out from the command handler so tests can call it directly.
pub fn seal_fragment(
    ctx: &SealContext,
    token: String,
    password: Option<String>,
    exp: Option<u64>,
) -> Result<String> {
    seal_fragment_kind(
        ctx,
        token,
        password,
        exp,
        mosseal_core::envelope::kind::TOKEN,
    )
}

/// Seal `token` with an explicit payload kind (spec 01).
pub fn seal_fragment_kind(
    ctx: &SealContext,
    token: String,
    password: Option<String>,
    exp: Option<u64>,
    kind: u8,
) -> Result<String> {
    let input = SealInput {
        data: token.into_bytes(),
        kind,
        exp,
        password: password.map(String::into_bytes),
        deterministic_salt: None,
        deterministic_nonce: None,
        deterministic_epoch: None,
        deterministic_version: None,
    };
    ctx.seal(&input)
        .map_err(|e| anyhow::anyhow!("{}: {}", e.code.as_str(), e.detail))
}

/// Parse a `PASSWORD=SECRET` slot argument (the first `=` separates; the
/// secret may contain further `=` characters, the password may not). The
/// error never echoes the raw argument: it typically contains the password
/// and secret, which must not land in logs.
pub fn parse_slot_arg(spec: &str) -> Result<SlotEntry> {
    let (password, data) = spec
        .split_once('=')
        .ok_or_else(|| anyhow::anyhow!("slot must be PASSWORD=SECRET (missing '=')"))?;
    if password.is_empty() {
        anyhow::bail!("slot password must not be empty");
    }
    Ok(SlotEntry {
        password: password.to_string(),
        data: data.to_string(),
        kind: None,
        exp_secs: None,
    })
}

/// Load slots from a `--slots-file` JSON array.
pub fn parse_slots_file(path: &std::path::Path) -> Result<Vec<SlotEntry>> {
    let text = std::fs::read_to_string(path)
        .map_err(|e| anyhow::anyhow!("cannot read {}: {e}", path.display()))?;
    let entries: Vec<SlotEntry> = serde_json::from_str(&text)
        .map_err(|e| anyhow::anyhow!("invalid slots file {}: {e}", path.display()))?;
    Ok(entries)
}

fn slot_entries_to_input(
    entries: &[SlotEntry],
    default_exp: Option<u64>,
) -> Result<MultiSealInput> {
    if entries.is_empty() {
        anyhow::bail!("at least one slot is required (--slot or --slots-file)");
    }
    Ok(MultiSealInput {
        slots: entries
            .iter()
            .map(|e| {
                Ok(MultiSlot {
                    password: e.password.clone().into_bytes(),
                    data: e.data.clone().into_bytes(),
                    kind: e
                        .kind
                        .as_ref()
                        .map(SlotKind::to_byte)
                        .transpose()?
                        .unwrap_or(mosseal_core::envelope::kind::TOKEN),
                    exp: e.exp_secs.or(default_exp),
                })
            })
            .collect::<Result<Vec<_>>>()?,
        deterministic_slot_salts: None,
        deterministic_slot_nonces: None,
        deterministic_salt: None,
        deterministic_nonce: None,
        deterministic_epoch: None,
    })
}

/// Seal a multi-slot fragment (unit-testable core of `mosseal seal-multi`).
pub fn seal_multi_fragment(
    ctx: &SealContext,
    entries: &[SlotEntry],
    default_exp: Option<u64>,
) -> Result<String> {
    let input = slot_entries_to_input(entries, default_exp)?;
    ctx.seal_multi(&input)
        .map_err(|e| anyhow::anyhow!("{}: {}", e.code.as_str(), e.detail))
}

/// Seal a deniable fragment (unit-testable core of `mosseal seal-deniable`).
#[allow(clippy::too_many_arguments)]
pub fn seal_deniable_fragment(
    ctx: &SealContext,
    cover_mode: CoverMode,
    cover_password: Option<String>,
    decoy: CoverDecoy,
    hidden_entries: &[SlotEntry],
    hidden_password: Option<String>,
    size_class: Option<SizeClass>,
) -> Result<String> {
    if hidden_entries.is_empty() {
        anyhow::bail!(
            "at least one hidden slot is required (--hidden-slot or --hidden-slots-file)"
        );
    }
    // The first slot's password locates the hidden layer unless overridden.
    let hidden_password = hidden_password.unwrap_or_else(|| hidden_entries[0].password.clone());
    let input = DeniableSealInput {
        cover_mode,
        cover_password: cover_password.map(String::into_bytes),
        cover_decoy: decoy,
        hidden_password: hidden_password.into_bytes(),
        hidden: HiddenSpec::Multi(slot_entries_to_input(hidden_entries, None)?),
        size_class,
        deterministic_salt: None,
        deterministic_nonce: None,
        deterministic_padding: None,
        deterministic_epoch: None,
    };
    ctx.seal_deniable(&input)
        .map_err(|e| anyhow::anyhow!("{}: {}", e.code.as_str(), e.detail))
}

/// Open a fragment's hidden layer (unit-testable core of `mosseal open
/// --hidden-password`).
pub fn open_hidden_fragment(
    ctx: &SealContext,
    fragment: &str,
    cover_password: Option<&str>,
    hidden_password: &str,
    ignore_expiry: bool,
) -> Result<OpenOutput> {
    let fetcher = NoFetch;
    let result = if ignore_expiry {
        ctx.open_deniable_ignoring_expiry(
            fragment,
            cover_password.map(str::as_bytes),
            Some(hidden_password.as_bytes()),
            &fetcher,
        )
    } else {
        ctx.open_deniable(
            fragment,
            cover_password.map(str::as_bytes),
            Some(hidden_password.as_bytes()),
            &fetcher,
        )
    };
    result.map_err(|e| anyhow::anyhow!("{}: {}", e.code.as_str(), e.detail))
}

/// Open `fragment`, optionally ignoring expiry (admin debugging).
///
/// When `ignore_expiry` is set only the expiry check is skipped; domain, epoch,
/// password, and the AEAD tag are still verified (see
/// [`SealContext::open_ignoring_expiry`]).
pub fn open_fragment(
    ctx: &SealContext,
    fragment: &str,
    password: Option<&str>,
    ignore_expiry: bool,
) -> Result<OpenOutput> {
    let fetcher = NoFetch;
    let pw = password.map(str::as_bytes);
    let result = if ignore_expiry {
        ctx.open_ignoring_expiry(fragment, pw, &fetcher)
    } else {
        ctx.open(fragment, pw, &fetcher)
    };
    result.map_err(|e| anyhow::anyhow!("{}: {}", e.code.as_str(), e.detail))
}

/// Generate a fresh 32-byte epoch secret as base64url (no padding).
pub fn gen_secret() -> String {
    use base64::Engine;
    let mut buf = [0u8; 32];
    rand::rngs::SysRng
        .try_fill_bytes(&mut buf)
        .expect("OS RNG unavailable");
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(buf)
}

/// Parse argv and dispatch. Thin entry point used by `main.rs`.
pub fn run() -> Result<()> {
    let cli = Cli::parse();
    run_cli(cli)
}

/// Execute a parsed [`Cli`]. Separated from [`run`] so it is testable without
/// spawning a process.
pub fn run_cli(cli: Cli) -> Result<()> {
    match cli.command {
        Command::Seal {
            token,
            password,
            exp,
            kind,
            epochs,
            domains,
        } => {
            let token = match token {
                Some(t) => t,
                None => rpassword::prompt_password("Token to seal: ")?,
            };
            let ctx = context_from(&epochs, domains)?;
            let frag = seal_fragment_kind(&ctx, token, password, exp, kind.byte())?;
            println!("{frag}");
            Ok(())
        }
        Command::SealMulti {
            slots,
            slots_file,
            exp,
            epochs,
            domains,
        } => {
            let mut entries: Vec<SlotEntry> = slots
                .iter()
                .map(|s| parse_slot_arg(s))
                .collect::<Result<_>>()?;
            if let Some(path) = &slots_file {
                entries.extend(parse_slots_file(path)?);
            }
            let ctx = context_from(&epochs, domains)?;
            let frag = seal_multi_fragment(&ctx, &entries, exp)?;
            println!("{frag}");
            Ok(())
        }
        Command::SealDeniable {
            cover_mode,
            cover_password,
            cover_decoy,
            cover_decoy_random: _,
            hidden_slot,
            hidden_slots_file,
            hidden_password,
            size_class,
            epochs,
            domains,
        } => {
            let cover_password = match (cover_mode, cover_password) {
                (CoverModeArg::Hidden, None) => {
                    Some(rpassword::prompt_password("Cover password: ")?)
                }
                (_, pw) => pw,
            };
            let decoy = match cover_decoy {
                Some(d) if !d.is_empty() => CoverDecoy::User(d.into_bytes()),
                _ => CoverDecoy::Random,
            };
            let mut hidden: Vec<SlotEntry> = hidden_slot
                .iter()
                .map(|s| parse_slot_arg(s))
                .collect::<Result<_>>()?;
            if let Some(path) = &hidden_slots_file {
                hidden.extend(parse_slots_file(path)?);
            }
            let ctx = context_from(&epochs, domains)?;
            let frag = seal_deniable_fragment(
                &ctx,
                cover_mode.mode(),
                cover_password,
                decoy,
                &hidden,
                hidden_password,
                size_class.map(SizeClassArg::class),
            )?;
            println!("{frag}");
            Ok(())
        }
        Command::Open {
            fragment,
            password,
            hidden_password,
            epochs,
            domains,
            ignore_expiry,
        } => {
            let ctx = context_from(&epochs, domains)?;
            let out = match hidden_password {
                // Deniable path (spec 09): --password (if any) opens the
                // cover; --hidden-password recovers and opens the layer.
                Some(hp) => {
                    open_hidden_fragment(&ctx, &fragment, password.as_deref(), &hp, ignore_expiry)?
                }
                None => open_fragment(&ctx, &fragment, password.as_deref(), ignore_expiry)?,
            };
            println!(
                "version: {}\nkind: {}\nexp:  {}\ndata: {}",
                out.version,
                out.kind,
                out.exp,
                String::from_utf8_lossy(&out.data)
            );
            Ok(())
        }
        Command::GenSecret => {
            println!("{}", gen_secret());
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mosseal_core::envelope::{self, flags, kind};

    fn b64_secret(byte: u8) -> String {
        use base64::Engine;
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([byte; 32])
    }

    #[test]
    fn context_from_accepts_valid_inputs() {
        let ctx = context_from(&b64_secret(1), vec!["a.test".into()]).unwrap();
        assert_eq!(ctx.epochs.len(), 1);
        assert_eq!(ctx.whitelist, vec!["a.test".to_string()]);
        assert_eq!(ctx.runtime_hostname, None, "CLI skips the host gate");
        assert_eq!(ctx.time_mode, TimeMode::Lenient);
    }

    #[test]
    fn context_from_preserves_sparse_holes() {
        let s = format!("{};;{}", b64_secret(1), b64_secret(3));
        let ctx = context_from(&s, vec!["a.test".into()]).unwrap();
        assert_eq!(ctx.epochs.slots(), 3);
        assert_eq!(ctx.epochs.len(), 2);
        assert_eq!(ctx.epochs.latest_epoch().unwrap(), 2);
    }

    #[test]
    fn context_from_rejects_bad_epochs() {
        assert!(context_from("", vec!["a.test".into()]).is_err());
        assert!(context_from("AAAA", vec!["a.test".into()]).is_err());
    }

    #[test]
    fn context_from_rejects_bad_domains() {
        assert!(context_from(&b64_secret(1), vec![]).is_err());
        assert!(context_from(&b64_secret(1), vec!["https://a.com".into()]).is_err());
    }

    #[test]
    fn gen_secret_is_32_bytes_base64url() {
        use base64::Engine;
        let s = gen_secret();
        assert!(!s.contains(['+', '/', '=']), "url-safe, unpadded");
        let raw = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(&s)
            .unwrap();
        assert_eq!(raw.len(), 32);
        // Two draws must differ (real RNG, not a constant).
        assert_ne!(gen_secret(), gen_secret());
    }

    #[test]
    fn seal_then_open_roundtrip() {
        let ctx = context_from(&b64_secret(7), vec!["a.test".into()]).unwrap();
        let frag = seal_fragment(&ctx, "tok_abc123".into(), None, None).unwrap();
        let out = open_fragment(&ctx, &frag, None, false).unwrap();
        assert_eq!(out.data, b"tok_abc123");
        assert_eq!(out.kind, kind::TOKEN);
        assert_eq!(out.exp, 0);
    }

    #[test]
    fn seal_sets_password_and_expiry_flags() {
        let ctx = context_from(&b64_secret(7), vec!["a.test".into()]).unwrap();
        let frag = seal_fragment(&ctx, "tok".into(), Some("pw".into()), Some(2_000)).unwrap();
        let bytes = envelope::b64::decode(&frag).unwrap();
        assert_eq!(bytes[1] & flags::PASSWORD, flags::PASSWORD);
        assert_eq!(bytes[1] & flags::EXPIRY, flags::EXPIRY);
    }

    #[test]
    fn open_ignores_expiry_only_when_asked() {
        let ctx = context_from(&b64_secret(7), vec!["a.test".into()]).unwrap();
        // exp far in the past; CLI lenient mode uses the real system clock.
        let frag = seal_fragment(&ctx, "tok".into(), None, Some(1)).unwrap();

        // Normal open rejects it as EXPIRED (stable code prefix).
        let err = open_fragment(&ctx, &frag, None, false).unwrap_err();
        assert!(
            err.to_string().contains("EXPIRED"),
            "expected an expiry error, got {err}"
        );

        // Admin path returns the payload.
        let out = open_fragment(&ctx, &frag, None, true).unwrap();
        assert_eq!(out.data, b"tok");
        assert_eq!(out.exp, 1);
    }

    #[test]
    fn open_rejects_wrong_password() {
        let ctx = context_from(&b64_secret(7), vec!["a.test".into()]).unwrap();
        let frag = seal_fragment(&ctx, "tok".into(), Some("pw".into()), None).unwrap();
        let err = open_fragment(&ctx, &frag, Some("WRONG"), false).unwrap_err();
        assert!(
            err.to_string().contains("BAD_PASSWORD"),
            "expected a bad-password code, got {err}"
        );
    }

    #[test]
    fn seal_rejects_payload_over_cap() {
        let ctx = context_from(&b64_secret(7), vec!["a.test".into()]).unwrap();
        let big = "x".repeat(mosseal_core::MAX_PAYLOAD_BYTES + 1);
        assert!(seal_fragment(&ctx, big, None, None).is_err());
    }

    // --- v2: seal-multi / seal-deniable / open --hidden-password ---

    fn two_slots() -> Vec<SlotEntry> {
        vec![
            SlotEntry {
                password: "pw-one".into(),
                data: "secret_one".into(),
                kind: None,
                exp_secs: None,
            },
            SlotEntry {
                password: "pw-two".into(),
                data: "secret_two".into(),
                kind: Some(SlotKind::Byte(mosseal_core::envelope::kind::BINARY_BLOB)),
                exp_secs: None,
            },
        ]
    }

    #[test]
    fn multi_fragment_roundtrip() {
        let ctx = context_from(&b64_secret(8), vec!["a.test".into()]).unwrap();
        let frag = seal_multi_fragment(&ctx, &two_slots(), None).unwrap();
        let out = open_fragment(&ctx, &frag, Some("pw-two"), false).unwrap();
        assert_eq!(out.data, b"secret_two");
        assert_eq!(out.kind, mosseal_core::envelope::kind::BINARY_BLOB);
        assert_eq!(out.version, 2);
        let err = open_fragment(&ctx, &frag, Some("WRONG"), false).unwrap_err();
        assert!(err.to_string().contains("BAD_PASSWORD"));
    }

    #[test]
    fn parse_slot_arg_splits_on_first_equals() {
        let e = parse_slot_arg("pw=secret=with=equals").unwrap();
        assert_eq!(e.password, "pw");
        assert_eq!(e.data, "secret=with=equals");
        assert!(parse_slot_arg("no-equals").is_err());
        assert!(parse_slot_arg("=empty-pw").is_err());
    }

    #[test]
    fn slots_file_parses_and_validates() {
        let dir = std::env::temp_dir().join(format!("mosseal-cli-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("slots.json");
        std::fs::write(
            &path,
            r#"[
                {"password":"p1","data":"d1"},
                {"password":"p2","data":"d2","kind":"binary-blob","expSecs":2000},
                {"password":"p3","data":"d3","kind":2}
            ]"#,
        )
        .unwrap();
        let entries = parse_slots_file(&path).unwrap();
        assert_eq!(entries.len(), 3);
        // String and numeric kind forms both resolve to the wire byte.
        assert_eq!(
            entries[1].kind.as_ref().unwrap().to_byte().unwrap(),
            mosseal_core::envelope::kind::BINARY_BLOB
        );
        assert_eq!(
            entries[2].kind.as_ref().unwrap().to_byte().unwrap(),
            mosseal_core::envelope::kind::BINARY_BLOB
        );
        assert_eq!(entries[1].exp_secs, Some(2000));
        // Unknown kind fails cleanly.
        std::fs::write(&path, r#"[{"password":"p","data":"d","kind":"weird"}]"#).unwrap();
        let entries = parse_slots_file(&path).unwrap();
        assert!(entries[0].kind.as_ref().unwrap().to_byte().is_err());
        // Broken JSON fails cleanly.
        std::fs::write(&path, "{not json").unwrap();
        assert!(parse_slots_file(&path).is_err());
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn parse_slot_arg_never_echoes_the_argument() {
        // Malformed values contain credentials; the error must not repeat them.
        let err = parse_slot_arg("hunter2:secret").unwrap_err().to_string();
        assert!(!err.contains("hunter2"), "error leaked the password: {err}");
        assert!(!err.contains("secret"), "error leaked the secret: {err}");
    }

    #[test]
    fn deniable_fragment_roundtrip_both_cover_modes() {
        let ctx = context_from(&b64_secret(9), vec!["a.test".into()]).unwrap();
        for (mode, cover_pw) in [
            (CoverMode::Plain, None),
            (CoverMode::Hidden, Some("cover-pw".to_string())),
        ] {
            let frag = seal_deniable_fragment(
                &ctx,
                mode,
                cover_pw.clone(),
                CoverDecoy::Random,
                &two_slots(),
                None,
                None,
            )
            .unwrap();
            let out = open_hidden_fragment(
                &ctx,
                &frag,
                cover_pw.as_deref(),
                "pw-one", // first slot's password locates by default
                false,
            )
            .unwrap();
            assert_eq!(out.data, b"secret_one");
            assert_eq!(out.version, 2);
            // Wrong hidden password.
            let err =
                open_hidden_fragment(&ctx, &frag, cover_pw.as_deref(), "WRONG", false).unwrap_err();
            assert!(err.to_string().contains("BAD_PASSWORD"));
        }
    }

    #[test]
    fn deniable_fragment_enforces_slot_cap() {
        let ctx = context_from(&b64_secret(10), vec!["a.test".into()]).unwrap();
        let mut slots = two_slots();
        while slots.len() <= mosseal_core::envelope::multi::MAX_SLOTS {
            slots.push(slots[0].clone());
        }
        let err = seal_deniable_fragment(
            &ctx,
            CoverMode::Plain,
            None,
            CoverDecoy::Random,
            &slots,
            None,
            None,
        )
        .unwrap_err();
        assert!(err.to_string().contains("TOO_MANY_SLOTS"));
    }
}
