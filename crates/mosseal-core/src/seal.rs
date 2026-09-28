//! Top-level seal/open orchestration (spec 02 § wasm-bindgen surface, native
//! form). The wasm crate wraps these; the CLI calls them directly.

use crate::{
    binding,
    envelope::{self, flags, kind, Envelope, Payload},
    epoch::EpochRegistry,
    kdf::{self, Argon2Profile, DerivedKey},
    time::{FetchTimes, TimeMode, TimeResolver, TimeSource},
    ErrorCode, MossealError, Result, MAX_PAYLOAD_BYTES,
};
use aes_gcm::{
    aead::{Aead, KeyInit, Payload as GcmPayload},
    Aes256Gcm,
};
use rand::TryRng;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Everything needed to seal a link (mirrors `SealOptions` from spec 02).
#[derive(Debug, Clone, Default)]
pub struct SealInput {
    /// Secret material (token or small app-state blob).
    pub data: Vec<u8>,
    /// Payload kind byte (spec 01; use [`kind::TOKEN`] / [`kind::BINARY_BLOB`]).
    pub kind: u8,
    /// Unix seconds; `None`/0 = no expiry (offline-capable link).
    pub exp: Option<u64>,
    /// Optional password — switches KDF to Argon2id (D1/D10).
    pub password: Option<Vec<u8>>,
    /// Randomness override for deterministic conformance vectors (tests only).
    pub deterministic_salt: Option<[u8; 16]>,
    pub deterministic_nonce: Option<[u8; 12]>,
    /// Epoch override for deterministic conformance vectors (tests only).
    /// `None` = seal with the latest epoch (normal behavior).
    pub deterministic_epoch: Option<u8>,
}

/// Verified open output (mirrors `OpenResult`).
#[derive(Debug, Clone, Zeroize, ZeroizeOnDrop)]
pub struct OpenOutput {
    pub data: Vec<u8>,
    pub exp: u64,
    pub kind: u8,
}

/// Context bound to a deployment: epoch registry, whitelist, profiles.
pub struct SealContext {
    pub epochs: EpochRegistry,
    pub whitelist: Vec<String>,
    pub argon_profile: Argon2Profile,
    pub time_mode: TimeMode,
    /// Runtime hostname for the allow-list gate (None = trusted/Node path).
    pub runtime_hostname: Option<String>,
    /// Time sources for expiry checks (spec 07). Empty = [`time::DEFAULT_TIME_SOURCES`].
    /// The wasm/template layer fills this from the generated
    /// `time_sources_str()` slot (`MOSSEAL_TIME_SOURCES` override).
    pub time_sources: Vec<TimeSource>,
}

impl SealContext {
    /// Binding string from the canonical whitelist (spec 03).
    fn binding(&self) -> Vec<u8> {
        binding::binding_string(&self.whitelist)
    }

    /// Runtime allow-list gate (browser builds only; spec 03 § 2).
    fn enforce_runtime_host(&self) -> Result<()> {
        match &self.runtime_hostname {
            Some(host) if !binding::runtime_host_allowed(host, &self.whitelist) => {
                Err(MossealError::new(
                    ErrorCode::DomainMismatch,
                    format!("hostname {host:?} not in whitelist"),
                ))
            }
            _ => Ok(()),
        }
    }

    fn derive_key_for_epoch(
        &self,
        epoch: u8,
        password: Option<&[u8]>,
        salt: &[u8; 16],
    ) -> Result<DerivedKey> {
        let b = self.binding();
        let secret = self.epochs.secret(epoch)?;
        match password {
            None | Some(&[]) => Ok(kdf::derive_hkdf(secret, salt, &b)),
            Some(pw) => kdf::derive_argon2(secret, pw, salt, &b, self.argon_profile)
                .map_err(|e| MossealError::new(ErrorCode::BadPassword, e)),
        }
    }

    /// Seal into a full `#ms=` fragment string (without the leading `#`).
    pub fn seal(&self, input: &SealInput) -> Result<String> {
        if input.data.len() > MAX_PAYLOAD_BYTES {
            return Err(MossealError::new(
                ErrorCode::PayloadTooLarge,
                format!(
                    "{} bytes exceeds v1 cap of {}",
                    input.data.len(),
                    MAX_PAYLOAD_BYTES
                ),
            ));
        }
        self.enforce_runtime_host()?;

        let salt: [u8; 16] = input.deterministic_salt.unwrap_or_else(|| {
            let mut s = [0u8; 16];
            rand::rngs::SysRng
                .try_fill_bytes(&mut s)
                .expect("OS RNG unavailable");
            s
        });
        let nonce: [u8; 12] = input.deterministic_nonce.unwrap_or_else(|| {
            let mut n = [0u8; 12];
            rand::rngs::SysRng
                .try_fill_bytes(&mut n)
                .expect("OS RNG unavailable");
            n
        });

        let pw = input.password.as_deref();
        // Sealing epoch: latest active by default; overridable for conformance
        // vectors that exercise non-zero epochs (tests only).
        let epoch = match input.deterministic_epoch {
            Some(e) => e,
            None => self.epochs.latest_epoch()?,
        };
        let key = self.derive_key_for_epoch(epoch, pw, &salt)?;

        let mut flag_bits = 0u8;
        let exp = input.exp.unwrap_or(0);
        if pw.is_some() && !pw.unwrap_or(&[]).is_empty() {
            flag_bits |= flags::PASSWORD;
        }
        if exp != 0 {
            flag_bits |= flags::EXPIRY;
        }

        let header_env = Envelope {
            version: crate::ENVELOPE_VERSION,
            flags: flag_bits,
            key_epoch: epoch,
            salt,
            nonce,
            ciphertext: Vec::new(),
        };

        let payload = Payload {
            kind: input.kind,
            exp,
            data: input.data.clone(),
        }
        .encode()?;
        let aad = header_env.aad();

        let cipher = Aes256Gcm::new((&key.0).into());
        let ct = cipher
            .encrypt(
                &nonce.into(),
                GcmPayload {
                    msg: &payload,
                    aad: &aad,
                },
            )
            .map_err(|_| MossealError::new(ErrorCode::BadPassword, "seal encrypt failed"))?;

        let mut env = header_env;
        env.ciphertext = ct;
        Ok(envelope::b64::encode(&envelope::encode(&env)))
    }

    /// Open a fragment string (the part after `ms=`), enforcing domain,
    /// epoch, password, and expiry (spec 04 receiver flow).
    pub fn open<F: FetchTimes>(
        &self,
        link: &str,
        password: Option<&[u8]>,
        fetcher: &F,
    ) -> Result<OpenOutput> {
        self.open_inner(link, password, fetcher, true)
    }

    /// Open a fragment **without enforcing expiry** — the trusted admin /
    /// debugging path (`mosseal open --ignore-expiry`, spec 05).
    ///
    /// Domain binding, key-epoch, password, and the AEAD tag are still fully
    /// verified; only the `exp` check is skipped. This is safe because the CLI
    /// is the trusted admin path and already skips the runtime host gate
    /// (spec 03).
    pub fn open_ignoring_expiry<F: FetchTimes>(
        &self,
        link: &str,
        password: Option<&[u8]>,
        fetcher: &F,
    ) -> Result<OpenOutput> {
        self.open_inner(link, password, fetcher, false)
    }

    fn open_inner<F: FetchTimes>(
        &self,
        link: &str,
        password: Option<&[u8]>,
        fetcher: &F,
        enforce_expiry: bool,
    ) -> Result<OpenOutput> {
        self.enforce_runtime_host()?;
        let bytes = envelope::b64::decode(link)
            .map_err(|e| MossealError::new(ErrorCode::MalformedEnvelope, e.to_string()))?;
        let env = envelope::decode(&bytes)?;

        let pw: Option<&[u8]> = if env.flags & flags::PASSWORD != 0 {
            Some(password.unwrap_or(&[]))
        } else {
            None
        };

        let key = self.derive_key_for_epoch(env.key_epoch, pw, &env.salt)?;
        let cipher = Aes256Gcm::new((&key.0).into());
        let aad = env.aad();
        let pt = cipher
            .decrypt(
                &env.nonce.into(),
                GcmPayload {
                    msg: env.ciphertext.as_ref(),
                    aad: &aad,
                },
            )
            .map_err(|_| {
                // GCM tag failure doubles as wrong-password detection (spec 02)
                if env.flags & flags::PASSWORD != 0 {
                    MossealError::new(ErrorCode::BadPassword, "gcm tag mismatch")
                } else {
                    MossealError::new(ErrorCode::MalformedEnvelope, "gcm tag mismatch")
                }
            })?;

        let payload = Payload::decode(&pt)?;
        match payload.kind {
            kind::TOKEN | kind::BINARY_BLOB => {}
            other => {
                return Err(MossealError::new(
                    ErrorCode::UnsupportedKind,
                    format!("kind byte {other:#x}"),
                ))
            }
        }

        // Expiry: exp=0 never fetches (offline-capable); resolver caches.
        // `open_ignoring_expiry` skips this entirely (trusted admin path).
        if enforce_expiry {
            let mut resolver =
                TimeResolver::with_sources(fetcher, self.time_mode, self.time_sources.clone());
            resolver.check_expiry(payload.exp)?;
        }

        Ok(OpenOutput {
            data: payload.data.clone(),
            exp: payload.exp,
            kind: payload.kind,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::time::FetchTimes;

    struct NoFetch;
    impl FetchTimes for NoFetch {
        fn fetch_unix_secs(&self, _s: &[crate::time::TimeSource]) -> Option<f64> {
            None
        }
    }
    struct FixedFetch(f64);
    impl FetchTimes for FixedFetch {
        fn fetch_unix_secs(&self, _s: &[crate::time::TimeSource]) -> Option<f64> {
            Some(self.0)
        }
    }

    fn ctx() -> SealContext {
        SealContext {
            epochs: EpochRegistry::new(vec![[7u8; 32]]),
            whitelist: vec!["a.test".to_string(), "b.test".to_string()],
            argon_profile: Argon2Profile::Minimum,
            time_mode: TimeMode::Lenient,
            runtime_hostname: None,
            time_sources: Vec::new(),
        }
    }

    fn sample(kind_byte: u8, exp: Option<u64>, pw: Option<Vec<u8>>) -> SealInput {
        SealInput {
            data: b"tok_abc123".to_vec(),
            kind: kind_byte,
            exp,
            password: pw,
            deterministic_salt: Some([1; 16]),
            deterministic_nonce: Some([2; 12]),
            deterministic_epoch: None,
        }
    }

    #[test]
    fn seal_open_roundtrip_no_password() {
        let c = ctx();
        let frag = c.seal(&sample(kind::TOKEN, None, None)).unwrap();
        let out = c.open(&frag, None, &NoFetch).unwrap();
        assert_eq!(out.data, b"tok_abc123");
        assert_eq!(out.kind, kind::TOKEN);
        assert_eq!(out.exp, 0);
    }

    #[test]
    fn seal_open_roundtrip_password() {
        let c = ctx();
        let frag = c
            .seal(&sample(kind::TOKEN, None, Some(b"pw123".to_vec())))
            .unwrap();
        let out = c.open(&frag, Some(b"pw123"), &NoFetch).unwrap();
        assert_eq!(out.data, b"tok_abc123");

        let err = c.open(&frag, Some(b"WRONG"), &NoFetch).unwrap_err();
        assert_eq!(err.code, ErrorCode::BadPassword);
        // missing password entirely on a protected link
        let err = c.open(&frag, None, &NoFetch).unwrap_err();
        assert_eq!(err.code, ErrorCode::BadPassword);
    }

    #[test]
    fn domain_gate_blocks_unlisted_host() {
        let mut c = ctx();
        c.runtime_hostname = Some("c.test".to_string());
        let err = c.seal(&sample(kind::TOKEN, None, None)).unwrap_err();
        assert_eq!(err.code, ErrorCode::DomainMismatch);
        let err = c.open("whatever", None, &NoFetch).unwrap_err();
        assert_eq!(err.code, ErrorCode::DomainMismatch);
    }

    #[test]
    fn portability_across_whitelist() {
        let c = ctx();
        let frag = c.seal(&sample(kind::TOKEN, None, None)).unwrap();
        for host in ["a.test", "b.test"] {
            let mut c2 = ctx();
            c2.runtime_hostname = Some(host.to_string());
            assert!(c2.open(&frag, None, &NoFetch).is_ok(), "portable to {host}");
        }
    }

    #[test]
    fn expiry_enforced_and_skipped() {
        let c = ctx();
        // future exp passes with fixed net time = 1000
        let frag = c.seal(&sample(kind::TOKEN, Some(2000), None)).unwrap();
        assert!(c.open(&frag, None, &FixedFetch(1000.0)).is_ok());
        // past exp fails even in lenient mode (net time authoritative)
        let frag = c.seal(&sample(kind::TOKEN, Some(500), None)).unwrap();
        let err = c.open(&frag, None, &FixedFetch(1000.0)).unwrap_err();
        assert_eq!(err.code, ErrorCode::Expired);
        // exp=0 never checks
        let frag = c.seal(&sample(kind::TOKEN, None, None)).unwrap();
        assert!(c.open(&frag, None, &NoFetch).is_ok());
    }

    #[test]
    fn strict_mode_requires_net_time_only_when_expiring() {
        let mut c = ctx();
        c.time_mode = TimeMode::Strict;
        let frag = c.seal(&sample(kind::TOKEN, Some(2000), None)).unwrap();
        let err = c.open(&frag, None, &NoFetch).unwrap_err();
        assert_eq!(err.code, ErrorCode::StrictTimeUnavailable);
        // no-expiry link opens fine offline in strict mode
        let frag = c.seal(&sample(kind::TOKEN, None, None)).unwrap();
        assert!(c.open(&frag, None, &NoFetch).is_ok());
    }

    #[test]
    fn tampered_header_fails_tag() {
        let c = ctx();
        let frag = c.seal(&sample(kind::TOKEN, None, None)).unwrap();
        let bytes = envelope::b64::decode(&frag).unwrap();
        // flip one header byte (epoch byte, index 2)
        let mut tampered = bytes.clone();
        tampered[2] ^= 0xFF;
        let err = c
            .open(&envelope::b64::encode(&tampered), None, &NoFetch)
            .unwrap_err();
        assert_eq!(err.code, ErrorCode::EpochRetired);
        // flip one ciphertext byte
        let mut tampered = bytes.clone();
        let last = tampered.len() - 1;
        tampered[last] ^= 0x01;
        let err = c
            .open(&envelope::b64::encode(&tampered), None, &NoFetch)
            .unwrap_err();
        assert_eq!(err.code, ErrorCode::MalformedEnvelope);
    }

    #[test]
    fn payload_cap_enforced_at_seal() {
        let c = ctx();
        let input = SealInput {
            data: vec![0u8; 256],
            ..sample(kind::TOKEN, None, None)
        };
        let err = c.seal(&input).unwrap_err();
        assert_eq!(err.code, ErrorCode::PayloadTooLarge);
    }

    #[test]
    fn binary_blob_kind_roundtrip() {
        let c = ctx();
        let frag = c.seal(&sample(kind::BINARY_BLOB, None, None)).unwrap();
        let out = c.open(&frag, None, &NoFetch).unwrap();
        assert_eq!(out.kind, kind::BINARY_BLOB);
    }

    #[test]
    fn retired_epoch_keeps_other_epochs_valid() {
        // Sparse registry: epoch 1 retired, epochs 0 and 2 active.
        let s0 = [0x11u8; 32];
        let s2 = [0x33u8; 32];
        let c = SealContext {
            epochs: EpochRegistry::from_slots(vec![Some(s0), None, Some(s2)]),
            whitelist: vec!["a.test".to_string()],
            argon_profile: Argon2Profile::Minimum,
            time_mode: TimeMode::Lenient,
            runtime_hostname: None,
            time_sources: Vec::new(),
        };
        // Seal under epoch 0 and epoch 2 (deterministic override).
        let frag0 = c
            .seal(&SealInput {
                deterministic_epoch: Some(0),
                ..sample(kind::TOKEN, None, None)
            })
            .unwrap();
        let frag2 = c
            .seal(&SealInput {
                deterministic_epoch: Some(2),
                ..sample(kind::TOKEN, None, None)
            })
            .unwrap();
        // Both still open — retirement of epoch 1 did not disturb them.
        assert!(c.open(&frag0, None, &NoFetch).is_ok());
        assert!(c.open(&frag2, None, &NoFetch).is_ok());
        // A link sealed under the retired epoch 1 fails with EPOCH_RETIRED.
        let mut bytes = envelope::b64::decode(&frag0).unwrap();
        bytes[2] = 1; // point the epoch byte at the retired hole
        let err = c
            .open(&envelope::b64::encode(&bytes), None, &NoFetch)
            .unwrap_err();
        assert_eq!(err.code, ErrorCode::EpochRetired);
        // Sealing defaults to the highest active epoch (2).
        let frag_default = c.seal(&sample(kind::TOKEN, None, None)).unwrap();
        let bytes = envelope::b64::decode(&frag_default).unwrap();
        assert_eq!(bytes[2], 2);
    }

    #[test]
    fn unsupported_kind_is_rejected_on_open() {
        // Seal does not validate `kind`; open must reject unknown kinds.
        let c = ctx();
        let frag = c.seal(&sample(0x09, None, None)).unwrap();
        let err = c.open(&frag, None, &NoFetch).unwrap_err();
        assert_eq!(err.code, ErrorCode::UnsupportedKind);
    }

    #[test]
    fn empty_password_is_treated_as_no_password() {
        let c = ctx();
        let frag = c
            .seal(&sample(kind::TOKEN, None, Some(Vec::new())))
            .unwrap();
        // No PASSWORD flag is set, so absent/empty passwords still open it.
        let bytes = envelope::b64::decode(&frag).unwrap();
        assert_eq!(bytes[1] & flags::PASSWORD, 0);
        assert!(c.open(&frag, None, &NoFetch).is_ok());
        assert!(c.open(&frag, Some(b""), &NoFetch).is_ok());
    }

    #[test]
    fn deterministic_epoch_out_of_range_fails_at_seal() {
        let c = ctx(); // single slot: epoch 0 only
        let input = SealInput {
            deterministic_epoch: Some(9),
            ..sample(kind::TOKEN, None, None)
        };
        let err = c.seal(&input).unwrap_err();
        assert_eq!(err.code, ErrorCode::EpochRetired);
    }

    #[test]
    fn salt_and_nonce_are_random_by_default() {
        let c = ctx();
        // No injected salt/nonce → the OS RNG path (contrast with `sample()`,
        // which pins deterministic values for vectors).
        let input = SealInput {
            data: b"tok_abc123".to_vec(),
            kind: kind::TOKEN,
            deterministic_salt: None,
            deterministic_nonce: None,
            ..sample(kind::TOKEN, None, None)
        };
        let a = c.seal(&input).unwrap();
        let b = c.seal(&input).unwrap();
        assert_ne!(a, b, "random salt/nonce must vary the fragment");
    }

    #[test]
    fn binary_blob_password_and_expiry_combined() {
        let c = ctx();
        let frag = c
            .seal(&sample(kind::BINARY_BLOB, Some(2000), Some(b"pw".to_vec())))
            .unwrap();
        let bytes = envelope::b64::decode(&frag).unwrap();
        assert_eq!(bytes[1] & flags::PASSWORD, flags::PASSWORD);
        assert_eq!(bytes[1] & flags::EXPIRY, flags::EXPIRY);
        let out = c.open(&frag, Some(b"pw"), &FixedFetch(1000.0)).unwrap();
        assert_eq!(out.kind, kind::BINARY_BLOB);
        assert_eq!(out.exp, 2000);
    }

    #[test]
    fn open_rejects_non_base64_fragment() {
        let c = ctx();
        let err = c.open("not!base64!!", None, &NoFetch).unwrap_err();
        assert_eq!(err.code, ErrorCode::MalformedEnvelope);
    }

    #[test]
    fn open_ignoring_expiry_skips_only_expiry() {
        let c = ctx();
        // A link that expired long ago.
        let frag = c.seal(&sample(kind::TOKEN, Some(500), None)).unwrap();
        // Normal open fails...
        assert_eq!(
            c.open(&frag, None, &FixedFetch(1_000.0)).unwrap_err().code,
            ErrorCode::Expired
        );
        // ...but the admin path returns the payload (no net fetch needed).
        let out = c
            .open_ignoring_expiry(&frag, None, &NoFetch)
            .expect("admin path must bypass expiry");
        assert_eq!(out.data, b"tok_abc123");
        assert_eq!(out.exp, 500);

        // Everything else is still enforced: password...
        let pw = c
            .seal(&sample(kind::TOKEN, Some(500), Some(b"pw".to_vec())))
            .unwrap();
        assert_eq!(
            c.open_ignoring_expiry(&pw, Some(b"WRONG"), &NoFetch)
                .unwrap_err()
                .code,
            ErrorCode::BadPassword
        );
        // ...and the domain gate.
        let mut offhost = ctx();
        offhost.runtime_hostname = Some("evil.test".to_string());
        assert_eq!(
            offhost
                .open_ignoring_expiry(&frag, None, &NoFetch)
                .unwrap_err()
                .code,
            ErrorCode::DomainMismatch
        );
    }
}
