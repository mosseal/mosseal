//! MOSSEAL CLI (spec 05, trusted admin path).
//!
//! The Node/browser path is untrusted; the CLI is the admin path (spec 03) and
//! therefore skips the runtime host gate. Logic lives here (rather than in the
//! binary) so it is unit- and integration-testable; `main.rs` is a thin shim.
//!
//! Commands:
//! - `seal` — seal a token into a share-link fragment
//! - `open` — open and verify a fragment (with `--ignore-expiry` for admin
//!   debugging; see [`Command::Open`])
//! - `gen-secret` — emit a fresh 32-byte base64url epoch secret

use anyhow::Result;
use clap::{Parser, Subcommand};
use mosseal_core::{
    binding,
    epoch::EpochRegistry,
    kdf::Argon2Profile,
    seal::{OpenOutput, SealContext, SealInput},
    time::TimeMode,
};
use rand::TryRng;

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
        .map_err(|e| anyhow::anyhow!("epoch registry: {}", e.detail))?;
    binding::validate_whitelist(&domains)
        .map_err(|e| anyhow::anyhow!("whitelist: {}", e.detail))?;
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
    let input = SealInput {
        data: token.into_bytes(),
        kind: mosseal_core::envelope::kind::TOKEN,
        exp,
        password: password.map(String::into_bytes),
        deterministic_salt: None,
        deterministic_nonce: None,
        deterministic_epoch: None,
    };
    ctx.seal(&input)
        .map_err(|e| anyhow::anyhow!("{}", e.detail))
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
    result.map_err(|e| anyhow::anyhow!("{}: {}", e.code, e.detail))
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
            epochs,
            domains,
        } => {
            let token = match token {
                Some(t) => t,
                None => rpassword::prompt_password("Token to seal: ")?,
            };
            let ctx = context_from(&epochs, domains)?;
            let frag = seal_fragment(&ctx, token, password, exp)?;
            println!("{frag}");
            Ok(())
        }
        Command::Open {
            fragment,
            password,
            epochs,
            domains,
            ignore_expiry,
        } => {
            let ctx = context_from(&epochs, domains)?;
            let out = open_fragment(&ctx, &fragment, password.as_deref(), ignore_expiry)?;
            println!(
                "kind: {}\nexp:  {}\ndata: {}",
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

        // Normal open rejects it as EXPIRED (thiserror prose, lowercase).
        let err = open_fragment(&ctx, &frag, None, false).unwrap_err();
        assert!(
            err.to_string().to_lowercase().contains("expired"),
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
            err.to_string().to_lowercase().contains("bad password"),
            "expected a bad-password error, got {err}"
        );
    }

    #[test]
    fn seal_rejects_payload_over_cap() {
        let ctx = context_from(&b64_secret(7), vec!["a.test".into()]).unwrap();
        let big = "x".repeat(256);
        assert!(seal_fragment(&ctx, big, None, None).is_err());
    }
}
