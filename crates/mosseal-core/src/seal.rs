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
    /// Optional password — switches KDF to Argon2id (spec 02).
    pub password: Option<Vec<u8>>,
    /// Randomness override for deterministic conformance vectors (tests only).
    pub deterministic_salt: Option<[u8; 16]>,
    pub deterministic_nonce: Option<[u8; 12]>,
    /// Epoch override for deterministic conformance vectors (tests only).
    /// `None` = seal with the latest epoch (normal behavior).
    pub deterministic_epoch: Option<u8>,
    /// Version override for deterministic conformance vectors (tests only).
    /// `None` = seal as v2 (the only normal path); `Some(1)` pins a v1 seal so
    /// the v1 wire bytes stay reproducible for the regression vectors.
    pub deterministic_version: Option<u8>,
}

/// One independently password-keyed secret of a multi-slot seal (spec 01 §
/// MULTI kind). Each slot runs its own Argon2id derivation over its own fresh
/// salt/nonce; slot payloads reuse the ordinary payload struct (kind, exp,
/// data) verbatim.
#[derive(Debug, Clone, Zeroize, ZeroizeOnDrop)]
pub struct MultiSlot {
    /// Slot password (required and non-empty: slots have no password-less
    /// mode — isolation is the point of `MULTI`).
    pub password: Vec<u8>,
    pub data: Vec<u8>,
    /// Slot payload kind byte (`TOKEN` or `BINARY_BLOB`; `MULTI` nesting is
    /// rejected at open).
    pub kind: u8,
    /// Per-slot expiry (0/None = never; enforced after this slot's decrypt).
    pub exp: Option<u64>,
}

/// Everything needed to seal a multi-slot link (spec 02 § sealMulti).
#[derive(Debug, Clone, Default, Zeroize, ZeroizeOnDrop)]
pub struct MultiSealInput {
    pub slots: Vec<MultiSlot>,
    /// Randomness overrides for deterministic conformance vectors (tests
    /// only). When set, must cover every slot.
    pub deterministic_slot_salts: Option<Vec<[u8; 16]>>,
    pub deterministic_slot_nonces: Option<Vec<[u8; 12]>>,
    /// Outer-envelope randomness overrides (tests only).
    pub deterministic_salt: Option<[u8; 16]>,
    pub deterministic_nonce: Option<[u8; 12]>,
    /// Epoch override for deterministic conformance vectors (tests only).
    pub deterministic_epoch: Option<u8>,
}

/// Cover keying for deniable links (D4, spec 09).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Zeroize)]
pub enum CoverMode {
    /// Password-keyed cover (Argon2id, PASSWORD flag set). Strongest
    /// deniability — nobody without the cover password sees anything; the
    /// hidden receiver must know **both** passwords (VeraCrypt model).
    Hidden,
    /// Password-less cover (HKDF). Binary holders decrypt the cover and see
    /// opaque high-entropy bytes — the hidden envelope's *existence* is
    /// visible, its content is not. The hidden receiver needs only the
    /// hidden password.
    Plain,
}

/// Fixed total envelope size for deniable links (D5): all deniable links in
/// a class are byte-length-identical regardless of secret count.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Zeroize)]
pub enum SizeClass {
    Kib1,
    Kib2,
    Kib4,
}

/// Smallest plausible hidden envelope (header 33 + tag 16 + minimal payload);
/// doubles as the recovery validation floor.
pub const HIDDEN_MIN: usize = 64;

/// Header(33) + GCM tag(16) + commitment(16) + payload header(13): the fixed
/// envelope overhead between a size class and its cover `data_len`.
const ENVELOPE_OVERHEAD: usize = 33 + 16 + 16 + 13;

impl SizeClass {
    /// Exact total wire size of the finished envelope.
    pub fn total_bytes(self) -> usize {
        match self {
            SizeClass::Kib1 => 1024,
            SizeClass::Kib2 => 2048,
            SizeClass::Kib4 => 4096,
        }
    }

    /// Cover `payload.data` length for this class.
    pub fn data_len(self) -> usize {
        self.total_bytes() - ENVELOPE_OVERHEAD
    }

    /// Does a hidden envelope of `hidden_len` wire bytes fit (modulus ≥ 1)?
    pub fn fits(self, hidden_len: usize) -> bool {
        self.data_len() > 4 + hidden_len
    }
}

/// Cover decoy content (D10): user-supplied bytes cycled into the padding,
/// or CSPRNG filler.
#[derive(Debug, Clone, Zeroize, ZeroizeOnDrop)]
pub enum CoverDecoy {
    Random,
    User(Vec<u8>),
}

/// What the hidden layer of a deniable link carries (spec 09).
#[derive(Debug, Clone, Zeroize, ZeroizeOnDrop)]
pub enum HiddenSpec {
    /// A single password-keyed v2 envelope under
    /// [`DeniableSealInput::hidden_password`].
    Single {
        data: Vec<u8>,
        /// `TOKEN` or `BINARY_BLOB`.
        kind: u8,
        exp: Option<u64>,
        deterministic_salt: Option<[u8; 16]>,
        deterministic_nonce: Option<[u8; 12]>,
        deterministic_epoch: Option<u8>,
    },
    /// A `MULTI` envelope (N secrets). `hidden_password` must equal one
    /// slot's password — that password both locates the hidden envelope and
    /// opens its slot; other slot holders cannot locate the layer without
    /// it (documented limitation, spec 09).
    Multi(MultiSealInput),
}

/// Everything needed to seal a deniable link (spec 09).
#[derive(Debug, Clone, Zeroize, ZeroizeOnDrop)]
pub struct DeniableSealInput {
    pub cover_mode: CoverMode,
    /// Required (non-empty) iff `cover_mode` is [`CoverMode::Hidden`].
    pub cover_password: Option<Vec<u8>>,
    pub cover_decoy: CoverDecoy,
    /// Locates (offset + masked length) and opens the hidden layer.
    pub hidden_password: Vec<u8>,
    pub hidden: HiddenSpec,
    /// `None` = smallest class that fits (D5).
    pub size_class: Option<SizeClass>,
    /// Cover-envelope randomness overrides (tests only).
    pub deterministic_salt: Option<[u8; 16]>,
    pub deterministic_nonce: Option<[u8; 12]>,
    /// Padding RNG seed (tests only): makes CSPRNG filler reproducible for
    /// conformance vectors. Ignored when a user decoy covers the padding.
    pub deterministic_padding: Option<[u8; 32]>,
    /// Cover epoch override (tests only); the hidden envelope carries its
    /// own epoch hooks in [`HiddenSpec`].
    pub deterministic_epoch: Option<u8>,
}

/// Verified open output (mirrors `OpenResult`).
#[derive(Debug, Clone, Zeroize, ZeroizeOnDrop)]
pub struct OpenOutput {
    pub data: Vec<u8>,
    pub exp: u64,
    pub kind: u8,
    /// Envelope version that served the open (1 or 2). Internal: the wasm
    /// layer does not serialize it and only the CLI prints it (D9).
    pub version: u8,
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
        Ok(envelope::b64::encode(&self.seal_wire(input)?))
    }

    /// Wire-bytes core of [`SealContext::seal`] (the deniable embed path
    /// consumes raw envelope bytes, not the b64 fragment).
    fn seal_wire(&self, input: &SealInput) -> Result<Vec<u8>> {
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
        // Sealing version: v2 by default (D8: seals always v2); v1 pinning is
        // a conformance-vector hook only.
        let version = match input.deterministic_version {
            None => crate::ENVELOPE_VERSION,
            Some(v @ 1..=2) => v,
            Some(other) => {
                return Err(MossealError::new(
                    ErrorCode::MalformedEnvelope,
                    format!("deterministic_version must be 1 or 2, got {other}"),
                ))
            }
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
            version,
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
        // v2 plaintext carries the key-commitment prefix (spec 01 § v2).
        let mut plaintext = Vec::with_capacity(
            payload.len()
                + if version >= 2 {
                    envelope::key_commit::LEN
                } else {
                    0
                },
        );
        if version >= 2 {
            plaintext.extend_from_slice(&kdf::key_commit(&key));
        }
        plaintext.extend_from_slice(&payload);
        let aad = header_env.aad();

        let cipher = Aes256Gcm::new((&key.0).into());
        let ct = cipher
            .encrypt(
                &nonce.into(),
                GcmPayload {
                    msg: &plaintext,
                    aad: &aad,
                },
            )
            .map_err(|_| MossealError::new(ErrorCode::BadPassword, "seal encrypt failed"))?;

        let mut env = header_env;
        env.ciphertext = ct;
        Ok(envelope::encode(&env))
    }

    /// Seal N independently password-keyed secrets into one `MULTI` link
    /// (spec 01 § MULTI kind). The outer envelope is a password-less v2
    /// envelope (epoch secret + binding key it, exactly like any
    /// password-less link); each slot's content is independently protected
    /// by its own Argon2id key.
    ///
    /// Open tries slots in order with the caller's password; the first slot
    /// whose AEAD tag and key commitment verify wins. All slots failing
    /// yields `BAD_PASSWORD` with no oracle about which slot almost matched.
    pub fn seal_multi(&self, input: &MultiSealInput) -> Result<String> {
        Ok(envelope::b64::encode(&self.seal_multi_wire(input)?))
    }

    /// Wire-bytes core of [`SealContext::seal_multi`] (the deniable embed
    /// path consumes raw envelope bytes).
    fn seal_multi_wire(&self, input: &MultiSealInput) -> Result<Vec<u8>> {
        self.enforce_runtime_host()?;

        let count = input.slots.len();
        if count == 0 {
            return Err(MossealError::new(
                ErrorCode::MalformedEnvelope,
                "multi seal requires at least one slot",
            ));
        }
        if count > envelope::multi::MAX_SLOTS {
            return Err(MossealError::new(
                ErrorCode::TooManySlots,
                format!(
                    "{} slots exceeds cap of {}",
                    count,
                    envelope::multi::MAX_SLOTS
                ),
            ));
        }
        for (i, slot) in input.slots.iter().enumerate() {
            if slot.password.is_empty() {
                return Err(MossealError::new(
                    ErrorCode::BadPassword,
                    format!(
                        "slot {i} password must not be empty (slots have no password-less mode)"
                    ),
                ));
            }
        }
        for (label, len) in [
            (
                "deterministic_slot_salts",
                input.deterministic_slot_salts.as_ref().map(Vec::len),
            ),
            (
                "deterministic_slot_nonces",
                input.deterministic_slot_nonces.as_ref().map(Vec::len),
            ),
        ] {
            if let Some(l) = len {
                if l != count {
                    return Err(MossealError::new(
                        ErrorCode::MalformedEnvelope,
                        format!("{label} must cover all {count} slots, got {l}"),
                    ));
                }
            }
        }

        let epoch = match input.deterministic_epoch {
            Some(e) => e,
            None => self.epochs.latest_epoch()?,
        };
        let secret = self.epochs.secret(epoch)?;
        let b = self.binding();

        let mut slots: Vec<envelope::multi::SlotRecord> = Vec::with_capacity(count);
        for (i, slot) in input.slots.iter().enumerate() {
            let salt: [u8; 16] = match &input.deterministic_slot_salts {
                Some(v) => v[i],
                None => rand_bytes(),
            };
            let nonce: [u8; 12] = match &input.deterministic_slot_nonces {
                Some(v) => v[i],
                None => rand_bytes(),
            };
            // Critical: each slot runs its OWN Argon2id derivation. Never one
            // run sliced into N keys — slicing would let any single password
            // holder derive all slot keys and destroy isolation.
            let key = kdf::derive_argon2(secret, &slot.password, &salt, &b, self.argon_profile)
                .map_err(|e| MossealError::new(ErrorCode::BadPassword, e))?;
            let mut payload = Payload {
                kind: slot.kind,
                exp: slot.exp.unwrap_or(0),
                data: slot.data.clone(),
            }
            .encode()?;
            let mut pt = Vec::with_capacity(envelope::key_commit::LEN + payload.len());
            pt.extend_from_slice(&kdf::key_commit(&key));
            pt.extend_from_slice(&payload);

            let mut rec = envelope::multi::SlotRecord {
                salt,
                nonce,
                ciphertext: Vec::new(),
            };
            let aad = envelope::multi::slot_aad(
                envelope::multi::MULTI_VERSION,
                count as u8,
                i as u8,
                &rec,
            );
            let cipher = Aes256Gcm::new((&key.0).into());
            rec.ciphertext = cipher
                .encrypt(
                    &nonce.into(),
                    GcmPayload {
                        msg: &pt,
                        aad: &aad,
                    },
                )
                .map_err(|_| MossealError::new(ErrorCode::BadPassword, "slot encrypt failed"))?;
            // Scrub the per-slot plaintext (commitment + payload) now that
            // the ciphertext exists (spec 02 § zeroization).
            pt.zeroize();
            payload.zeroize();
            slots.push(rec);
        }

        let blob = envelope::multi::MultiBlob {
            version: envelope::multi::MULTI_VERSION,
            slots,
        }
        .encode()?;

        // Outer: password-less v2 envelope, kind MULTI, exp 0 (per-slot exp
        // is authoritative). Keyed like any password-less link.
        let salt: [u8; 16] = input.deterministic_salt.unwrap_or_else(rand_bytes);
        let nonce: [u8; 12] = input.deterministic_nonce.unwrap_or_else(rand_bytes);
        let key = kdf::derive_hkdf(secret, &salt, &b);
        let header_env = Envelope {
            version: crate::ENVELOPE_VERSION,
            flags: 0,
            key_epoch: epoch,
            salt,
            nonce,
            ciphertext: Vec::new(),
        };
        let payload = Payload {
            kind: kind::MULTI,
            exp: 0,
            data: blob,
        }
        .encode()?;
        let mut plaintext = Vec::with_capacity(envelope::key_commit::LEN + payload.len());
        plaintext.extend_from_slice(&kdf::key_commit(&key));
        plaintext.extend_from_slice(&payload);

        let cipher = Aes256Gcm::new((&key.0).into());
        let ct = cipher
            .encrypt(
                &nonce.into(),
                GcmPayload {
                    msg: &plaintext,
                    aad: &header_env.aad(),
                },
            )
            .map_err(|_| MossealError::new(ErrorCode::BadPassword, "seal encrypt failed"))?;

        let mut env = header_env;
        env.ciphertext = ct;
        Ok(envelope::encode(&env))
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
        // A verification failure (tag or commitment) maps by password mode:
        // BAD_PASSWORD when the link claims a password, MALFORMED_ENVELOPE
        // otherwise (spec 02: GCM tag failure doubles as wrong-password
        // detection; v2 commitment mismatches take the same path).
        let auth_fail = |detail: &'static str| {
            if env.flags & flags::PASSWORD != 0 {
                MossealError::new(ErrorCode::BadPassword, detail)
            } else {
                MossealError::new(ErrorCode::MalformedEnvelope, detail)
            }
        };
        let pt = cipher
            .decrypt(
                &env.nonce.into(),
                GcmPayload {
                    msg: env.ciphertext.as_ref(),
                    aad: &aad,
                },
            )
            .map_err(|_| auth_fail("gcm tag mismatch"))?;

        // Version dispatch (spec 01 § versions): v2 verifies the key
        // commitment before payload parsing; v1 has none. Everything
        // downstream (payload, expiry, binding, epochs) is shared.
        let payload_bytes: &[u8] = if env.version >= 2 {
            if pt.len() < envelope::key_commit::LEN {
                return Err(auth_fail("key commitment missing"));
            }
            let (prefix, rest) = pt.split_at(envelope::key_commit::LEN);
            if !envelope::key_commit::matches(prefix, &key.0) {
                return Err(auth_fail("key commitment mismatch"));
            }
            rest
        } else {
            &pt[..]
        };

        let payload = Payload::decode(payload_bytes)?;
        match (env.version, payload.kind) {
            // MULTI (0x03) is v2-only; a v1 MULTI is an unsupported kind.
            (1, kind::TOKEN) | (1, kind::BINARY_BLOB) => {}
            (2, kind::TOKEN) | (2, kind::BINARY_BLOB) => {}
            (2, kind::MULTI) => {
                // Try-slots loop with the caller's password; per-slot exp is
                // authoritative (outer exp is structural 0 and ignored).
                return self.open_multi(
                    &payload.data,
                    password,
                    fetcher,
                    enforce_expiry,
                    env.key_epoch,
                );
            }
            (_, other) => {
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
            version: env.version,
        })
    }

    /// Try-slots open for `MULTI` envelopes (spec 01 § MULTI kind). Derives
    /// each slot's Argon2id key from the caller's password; the first slot
    /// whose AEAD tag and key commitment verify wins. Structural failures
    /// after a verified decrypt (payload, kind, expiry) propagate their own
    /// codes — the password already matched. All slots failing yields
    /// `BAD_PASSWORD` with no oracle about which slot almost matched.
    fn open_multi<F: FetchTimes>(
        &self,
        blob_bytes: &[u8],
        password: Option<&[u8]>,
        fetcher: &F,
        enforce_expiry: bool,
        epoch: u8,
    ) -> Result<OpenOutput> {
        let blob = envelope::multi::MultiBlob::decode(blob_bytes)?;
        let secret = self.epochs.secret(epoch)?;
        let b = self.binding();
        let pw = password.unwrap_or(&[]);

        for (i, slot) in blob.slots.iter().enumerate() {
            let key = kdf::derive_argon2(secret, pw, &slot.salt, &b, self.argon_profile)
                .map_err(|e| MossealError::new(ErrorCode::BadPassword, e))?;
            let cipher = Aes256Gcm::new((&key.0).into());
            let aad =
                envelope::multi::slot_aad(blob.version, blob.slots.len() as u8, i as u8, slot);
            let Ok(pt) = cipher.decrypt(
                &slot.nonce.into(),
                GcmPayload {
                    msg: slot.ciphertext.as_ref(),
                    aad: &aad,
                },
            ) else {
                // Wrong password for this slot — keep trying. Try-in-order
                // stops at the first hit, bounding the Argon2 cost.
                continue;
            };
            // AEAD verified under this slot's key: the password matched.
            // Commitment presence/mismatch past this point is structural.
            if pt.len() < envelope::key_commit::LEN {
                return Err(MossealError::new(
                    ErrorCode::MalformedEnvelope,
                    "slot commitment missing",
                ));
            }
            let (prefix, rest) = pt.split_at(envelope::key_commit::LEN);
            if !envelope::key_commit::matches(prefix, &key.0) {
                return Err(MossealError::new(
                    ErrorCode::MalformedEnvelope,
                    "slot commitment mismatch",
                ));
            }
            let payload = Payload::decode(rest)?;
            match payload.kind {
                kind::TOKEN | kind::BINARY_BLOB => {}
                other => {
                    return Err(MossealError::new(
                        ErrorCode::UnsupportedKind,
                        format!("kind byte {other:#x}"),
                    ))
                }
            }
            // Per-slot expiry (spec 07 semantics per slot; exp=0 slots stay
            // offline-capable). `open_ignoring_expiry` skips this entirely.
            if enforce_expiry {
                let mut resolver =
                    TimeResolver::with_sources(fetcher, self.time_mode, self.time_sources.clone());
                resolver.check_expiry(payload.exp)?;
            }
            return Ok(OpenOutput {
                data: payload.data.clone(),
                exp: payload.exp,
                kind: payload.kind,
                version: crate::ENVELOPE_VERSION,
            });
        }

        Err(MossealError::new(
            ErrorCode::BadPassword,
            "password matched no secret",
        ))
    }

    /// Seal a deniable link (spec 09): a normal v2 `BINARY_BLOB` envelope
    /// whose payload embeds a complete hidden envelope at a
    /// password-derived offset, padded to a fixed size class so all links in
    /// a class are byte-length-identical.
    ///
    /// Layout of `cover payload.data` (deviation from PLAN §3.3, documented):
    /// the 4-byte masked length lives at `[0..4)` — not at `offset−4` — and
    /// the offset modulus uses the actual `hidden_len`, not `HIDDEN_MIN`.
    /// The plan's formula `offset = 4 + (arg32 mod (data_len − 4 −
    /// HIDDEN_MIN))` cannot guarantee `offset + hidden_len ≤ data_len` for
    /// hidden envelopes larger than `HIDDEN_MIN + 1` bytes (a ~49 % failure
    /// rate for 2 KiB envelopes in the 4 KiB class), while open-side recovery
    /// needs `hidden_len` *before* computing the offset. Front-placing the
    /// masked length fixes both with identical security: the masked bytes
    /// are Argon2-XOR output, uniform at any position, and the offset stays
    /// password-derived.
    pub fn seal_deniable(&self, input: &DeniableSealInput) -> Result<String> {
        self.enforce_runtime_host()?;

        if input.hidden_password.is_empty() {
            return Err(MossealError::new(
                ErrorCode::BadPassword,
                "hidden password must not be empty",
            ));
        }
        let cover_password: Option<Vec<u8>> = match input.cover_mode {
            CoverMode::Plain => {
                if input.cover_password.is_some() {
                    return Err(MossealError::new(
                        ErrorCode::MalformedEnvelope,
                        "cover=plain must not carry a cover password",
                    ));
                }
                None
            }
            CoverMode::Hidden => {
                let pw = input.cover_password.clone().ok_or_else(|| {
                    MossealError::new(
                        ErrorCode::BadPassword,
                        "cover=hidden requires a cover password",
                    )
                })?;
                if pw.is_empty() {
                    return Err(MossealError::new(
                        ErrorCode::BadPassword,
                        "cover password must not be empty",
                    ));
                }
                Some(pw)
            }
        };

        // 1. Build the hidden envelope (its own salt/nonce/epoch; a full v2
        //    envelope — single password-keyed or MULTI).
        let hidden_wire: Vec<u8> = match &input.hidden {
            HiddenSpec::Single {
                data,
                kind: hidden_kind,
                exp,
                deterministic_salt,
                deterministic_nonce,
                deterministic_epoch,
            } => {
                if *hidden_kind == kind::MULTI {
                    return Err(MossealError::new(
                        ErrorCode::UnsupportedKind,
                        "hidden single envelope must be TOKEN or BINARY_BLOB (use HiddenSpec::Multi)",
                    ));
                }
                self.seal_wire(&SealInput {
                    data: data.clone(),
                    kind: *hidden_kind,
                    exp: *exp,
                    password: Some(input.hidden_password.clone()),
                    deterministic_salt: *deterministic_salt,
                    deterministic_nonce: *deterministic_nonce,
                    deterministic_epoch: *deterministic_epoch,
                    deterministic_version: None,
                })?
            }
            HiddenSpec::Multi(mi) => {
                if !mi.slots.iter().any(|s| s.password == input.hidden_password) {
                    return Err(MossealError::new(
                        ErrorCode::BadPassword,
                        "hidden password must equal a slot password for the hidden layer to be openable",
                    ));
                }
                self.seal_multi_wire(mi)?
            }
        };
        let hidden_len = hidden_wire.len();

        // 2. Size class: pinned or smallest that fits.
        let class = match input.size_class {
            Some(c) => {
                if !c.fits(hidden_len) {
                    return Err(MossealError::new(
                        ErrorCode::PayloadTooLarge,
                        format!(
                            "hidden envelope ({hidden_len} B) does not fit size class {} ({} B budget)",
                            c.total_bytes(),
                            c.data_len() - 5
                        ),
                    ));
                }
                c
            }
            None => *[SizeClass::Kib1, SizeClass::Kib2, SizeClass::Kib4]
                .iter()
                .find(|c| c.fits(hidden_len))
                .ok_or_else(|| {
                    MossealError::new(
                        ErrorCode::PayloadTooLarge,
                        format!("hidden envelope ({hidden_len} B) exceeds the largest size class"),
                    )
                })?,
        };
        let data_len = class.data_len();

        // 3. Cover salt/nonce, then the password-derived offset + mask.
        let cover_salt: [u8; 16] = input.deterministic_salt.unwrap_or_else(rand_bytes);
        let cover_nonce: [u8; 12] = input.deterministic_nonce.unwrap_or_else(rand_bytes);
        let arg = kdf::derive_argon2_offset(
            &self.binding(),
            &input.hidden_password,
            &cover_salt,
            self.argon_profile,
        )
        .map_err(|e| MossealError::new(ErrorCode::BadPassword, e))?;
        // offset = 4 + (LE32(arg[0..4]) mod (data_len − 4 − hidden_len)):
        // by construction offset + hidden_len ≤ data_len − 1, always fits.
        let modulus = data_len - 4 - hidden_len;
        let offset = 4 + (u32::from_le_bytes(arg[0..4].try_into().unwrap()) as usize % modulus);
        let masked_len = u32::from_le_bytes(arg[4..8].try_into().unwrap()) ^ (hidden_len as u32);

        // 4. Padding (decoy-distributed), then overlay masked length + the
        //    hidden envelope.
        let mut data = padding_bytes(data_len, &input.cover_decoy, input.deterministic_padding);
        data[0..4].copy_from_slice(&masked_len.to_le_bytes());
        data[offset..offset + hidden_len].copy_from_slice(&hidden_wire);

        // 5. Seal the cover: v2 BINARY_BLOB, exp 0 (cover is structural),
        //    PASSWORD flag iff cover=hidden.
        let wire = self.seal_wire(&SealInput {
            data,
            kind: kind::BINARY_BLOB,
            exp: None,
            password: cover_password,
            deterministic_salt: Some(cover_salt),
            deterministic_nonce: Some(cover_nonce),
            deterministic_epoch: input.deterministic_epoch,
            deterministic_version: None,
        })?;
        debug_assert_eq!(wire.len(), class.total_bytes(), "size class is exact");
        Ok(envelope::b64::encode(&wire))
    }

    /// Open a deniable link's hidden layer (spec 09): open the cover, then
    /// recover the hidden envelope from the password-derived offset and run
    /// the normal v2 open path on it (recursion depth cap = 1 — a normal
    /// open never probes for hidden layers; hidden access is explicit-only).
    ///
    /// Recovery failures (wrong hidden password, corrupt layout) uniformly
    /// yield `BAD_PASSWORD`: plausible deniability means the format cannot
    /// distinguish "no hidden layer" from "wrong password".
    pub fn open_deniable<F: FetchTimes>(
        &self,
        link: &str,
        cover_password: Option<&[u8]>,
        hidden_password: Option<&[u8]>,
        fetcher: &F,
    ) -> Result<OpenOutput> {
        self.open_deniable_inner(link, cover_password, hidden_password, fetcher, true)
    }

    /// Admin variant: skip the hidden layer's expiry too (the cover's exp is
    /// structural 0 and never enforced).
    pub fn open_deniable_ignoring_expiry<F: FetchTimes>(
        &self,
        link: &str,
        cover_password: Option<&[u8]>,
        hidden_password: Option<&[u8]>,
        fetcher: &F,
    ) -> Result<OpenOutput> {
        self.open_deniable_inner(link, cover_password, hidden_password, fetcher, false)
    }

    fn open_deniable_inner<F: FetchTimes>(
        &self,
        link: &str,
        cover_password: Option<&[u8]>,
        hidden_password: Option<&[u8]>,
        fetcher: &F,
        enforce_expiry: bool,
    ) -> Result<OpenOutput> {
        // The cover salt drives the offset derivation; decode the envelope
        // here, then let the shared path do the full cover verification.
        let bytes = envelope::b64::decode(link)
            .map_err(|e| MossealError::new(ErrorCode::MalformedEnvelope, e.to_string()))?;
        let env = envelope::decode(&bytes)?;

        let cover = self.open_inner(link, cover_password, fetcher, false)?;
        if cover.kind != kind::BINARY_BLOB {
            return Err(MossealError::new(
                ErrorCode::MalformedEnvelope,
                "deniable cover must be a binary blob",
            ));
        }
        let data = &cover.data;

        let hp = hidden_password.unwrap_or(&[]);
        let recovery_fail = || MossealError::new(ErrorCode::BadPassword, "hidden layer not found");
        if data.len() < 4 + HIDDEN_MIN + 1 {
            return Err(recovery_fail());
        }
        let arg = kdf::derive_argon2_offset(&self.binding(), hp, &env.salt, self.argon_profile)
            .map_err(|e| MossealError::new(ErrorCode::BadPassword, e))?;
        let hidden_len = (u32::from_le_bytes(data[0..4].try_into().unwrap())
            ^ u32::from_le_bytes(arg[4..8].try_into().unwrap())) as usize;
        if !(HIDDEN_MIN..=data.len() - 5).contains(&hidden_len) {
            return Err(recovery_fail());
        }
        let modulus = data.len() - 4 - hidden_len;
        let offset = 4 + (u32::from_le_bytes(arg[0..4].try_into().unwrap()) as usize % modulus);
        if offset + hidden_len > data.len() {
            return Err(recovery_fail());
        }
        let hidden_wire = &data[offset..offset + hidden_len];

        // Normal v2 open on the slice (single or MULTI; per-slot expiry
        // enforced inside unless this is the admin path).
        self.open_inner(
            &envelope::b64::encode(hidden_wire),
            Some(hp),
            fetcher,
            enforce_expiry,
        )
    }
}

/// OS-RNG fill for fixed-size salt/nonce arrays.
fn rand_bytes<const N: usize>() -> [u8; N] {
    let mut buf = [0u8; N];
    rand::rngs::SysRng
        .try_fill_bytes(&mut buf)
        .expect("OS RNG unavailable");
    buf
}

/// Cover padding bytes (spec 09 § decoy): user decoy cycled to length, or
/// CSPRNG filler (seeded deterministically for conformance vectors only).
fn padding_bytes(len: usize, decoy: &CoverDecoy, seed: Option<[u8; 32]>) -> Vec<u8> {
    if let CoverDecoy::User(d) = decoy {
        if !d.is_empty() {
            return (0..len).map(|i| d[i % d.len()]).collect();
        }
    }
    match seed {
        // Test-only deterministic filler (xorshift64*, folded from the seed).
        Some(s) => {
            let mut state = s.iter().fold(0x9E37_79B9_7F4A_7C15u64, |acc, b| {
                acc.rotate_left(17) ^ (*b as u64).wrapping_mul(0xBF58_476D_1CE4_E5B9)
            });
            let mut out = Vec::with_capacity(len);
            while out.len() < len {
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                out.extend_from_slice(&state.to_le_bytes());
            }
            out.truncate(len);
            out
        }
        None => {
            let mut out = vec![0u8; len];
            rand::rngs::SysRng
                .try_fill_bytes(&mut out)
                .expect("OS RNG unavailable");
            out
        }
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
            deterministic_version: None,
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
            data: vec![0u8; MAX_PAYLOAD_BYTES + 1],
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

    // --- v2 foundation (WS1) ---

    /// The exact v1 wire bytes for this ctx's canonical no-password sample
    /// (epoch 0, secret `[7;32]`, pinned salt/nonce). Seals are v2 now, but
    /// the pinned-v1 path must keep producing these bytes forever (v1
    /// regression proof; the cross-crate golden lives in `seal_open.rs`).
    const GOLDEN_V1_TOKEN_NOPASS: &str =
        "AQAAEAEBAQEBAQEBAQEBAQEBAQEMAgICAgICAgICAgICkuQzk_LRsH6fc_l7DoWmgu3swke_Ru0A7KieCPLA9ZCFB1G1-YeG";

    #[test]
    fn v1_pinned_seal_is_byte_identical_and_opens() {
        let c = ctx();
        let input = SealInput {
            deterministic_version: Some(1),
            ..sample(kind::TOKEN, None, None)
        };
        let frag = c.seal(&input).unwrap();
        assert_eq!(frag, GOLDEN_V1_TOKEN_NOPASS, "v1 bytes must never drift");
        let bytes = envelope::b64::decode(&frag).unwrap();
        assert_eq!(bytes[0], 1);
        let out = c.open(&frag, None, &NoFetch).unwrap();
        assert_eq!(out.data, b"tok_abc123");
        assert_eq!(out.version, 1);
    }

    #[test]
    fn seals_default_to_v2_with_commitment_overhead() {
        let c = ctx();
        let frag = c.seal(&sample(kind::TOKEN, None, None)).unwrap();
        let bytes = envelope::b64::decode(&frag).unwrap();
        assert_eq!(bytes[0], crate::ENVELOPE_VERSION);
        // Same inputs otherwise: v2 = v1 bytes + 16 B commitment (inside the
        // AEAD plaintext → ciphertext grows by exactly the prefix).
        let v1 = SealInput {
            deterministic_version: Some(1),
            ..sample(kind::TOKEN, None, None)
        };
        let v1_bytes = envelope::b64::decode(&c.seal(&v1).unwrap()).unwrap();
        assert_eq!(bytes.len(), v1_bytes.len() + envelope::key_commit::LEN);
        let out = c.open(&frag, None, &NoFetch).unwrap();
        assert_eq!(out.data, b"tok_abc123");
        assert_eq!(out.version, 2);
    }

    #[test]
    fn deterministic_version_validated() {
        let c = ctx();
        let input = SealInput {
            deterministic_version: Some(3),
            ..sample(kind::TOKEN, None, None)
        };
        assert_eq!(
            c.seal(&input).unwrap_err().code,
            ErrorCode::MalformedEnvelope
        );
    }

    /// Hand-build a v2 envelope whose AEAD is valid (encrypted under the true
    /// epoch key) but whose plaintext omits or corrupts the commitment prefix
    /// — the AES-GCM partitioning/forgery shape the commitment closes.
    fn forge_v2_without_commitment(password: Option<&[u8]>) -> String {
        let c = ctx();
        let salt = [0x21; 16];
        let nonce = [0x22; 12];
        let epoch = c.epochs.latest_epoch().unwrap();
        let key = c.derive_key_for_epoch(epoch, password, &salt).unwrap();
        let header = Envelope {
            version: 2,
            flags: if password.is_some() {
                flags::PASSWORD
            } else {
                0
            },
            key_epoch: epoch,
            salt,
            nonce,
            ciphertext: Vec::new(),
        };
        let payload = Payload {
            kind: kind::TOKEN,
            exp: 0,
            data: b"tok_abc123".to_vec(),
        }
        .encode()
        .unwrap();
        let cipher = Aes256Gcm::new((&key.0).into());
        let ct = cipher
            .encrypt(
                &nonce.into(),
                GcmPayload {
                    msg: &payload,
                    aad: &header.aad(),
                },
            )
            .unwrap();
        let mut env = header;
        env.ciphertext = ct;
        envelope::b64::encode(&envelope::encode(&env))
    }

    #[test]
    fn v2_missing_commitment_is_rejected() {
        let c = ctx();
        // Password-less: tag verifies but prefix is absent → MALFORMED_ENVELOPE.
        let frag = forge_v2_without_commitment(None);
        let err = c.open(&frag, None, &NoFetch).unwrap_err();
        assert_eq!(err.code, ErrorCode::MalformedEnvelope);
        // Password mode: same shape maps to BAD_PASSWORD.
        let frag = forge_v2_without_commitment(Some(b"pw"));
        let err = c.open(&frag, Some(b"pw"), &NoFetch).unwrap_err();
        assert_eq!(err.code, ErrorCode::BadPassword);
    }

    #[test]
    fn v2_wrong_key_commitment_is_rejected() {
        // Valid AEAD under the true key, but the prefix commits to a
        // different key (simulates the cross-key forgery).
        let c = ctx();
        let salt = [0x31; 16];
        let nonce = [0x32; 12];
        let epoch = c.epochs.latest_epoch().unwrap();
        let key = c.derive_key_for_epoch(epoch, None, &salt).unwrap();
        let header = Envelope {
            version: 2,
            flags: 0,
            key_epoch: epoch,
            salt,
            nonce,
            ciphertext: Vec::new(),
        };
        let payload = Payload {
            kind: kind::TOKEN,
            exp: 0,
            data: b"x".to_vec(),
        }
        .encode()
        .unwrap();
        let mut plaintext = Vec::new();
        plaintext.extend_from_slice(&crate::envelope::key_commit::build(&[0xEE; 32]));
        plaintext.extend_from_slice(&payload);
        let cipher = Aes256Gcm::new((&key.0).into());
        let ct = cipher
            .encrypt(
                &nonce.into(),
                GcmPayload {
                    msg: &plaintext,
                    aad: &header.aad(),
                },
            )
            .unwrap();
        let mut env = header;
        env.ciphertext = ct;
        let frag = envelope::b64::encode(&envelope::encode(&env));
        assert_eq!(
            c.open(&frag, None, &NoFetch).unwrap_err().code,
            ErrorCode::MalformedEnvelope
        );
    }

    #[test]
    fn v1_multi_kind_is_unsupported() {
        // A v1 envelope can never carry kind 0x03 (seal-side pin + hand-forge
        // is enough: kind validation happens after decrypt).
        let frag = forge_v1_with_kind(kind::MULTI);
        let c = ctx();
        assert_eq!(
            c.open(&frag, None, &NoFetch).unwrap_err().code,
            ErrorCode::UnsupportedKind
        );
    }

    /// v1 envelope with an arbitrary kind byte, valid AEAD (unit-test forge).
    fn forge_v1_with_kind(kind_byte: u8) -> String {
        let c = ctx();
        let salt = [0x41; 16];
        let nonce = [0x42; 12];
        let epoch = c.epochs.latest_epoch().unwrap();
        let key = c.derive_key_for_epoch(epoch, None, &salt).unwrap();
        let header = Envelope {
            version: 1,
            flags: 0,
            key_epoch: epoch,
            salt,
            nonce,
            ciphertext: Vec::new(),
        };
        let payload = Payload {
            kind: kind_byte,
            exp: 0,
            data: b"x".to_vec(),
        }
        .encode()
        .unwrap();
        let cipher = Aes256Gcm::new((&key.0).into());
        let ct = cipher
            .encrypt(
                &nonce.into(),
                GcmPayload {
                    msg: &payload,
                    aad: &header.aad(),
                },
            )
            .unwrap();
        let mut env = header;
        env.ciphertext = ct;
        envelope::b64::encode(&envelope::encode(&env))
    }

    // --- MULTI kind (WS2) ---

    fn two_slot_input() -> MultiSealInput {
        MultiSealInput {
            slots: vec![
                MultiSlot {
                    password: b"pw-one".to_vec(),
                    data: b"secret_one".to_vec(),
                    kind: kind::TOKEN,
                    exp: None,
                },
                MultiSlot {
                    password: b"pw-two".to_vec(),
                    data: b"secret_two".to_vec(),
                    kind: kind::BINARY_BLOB,
                    exp: Some(2000),
                },
            ],
            deterministic_slot_salts: Some(vec![[0x51; 16], [0x52; 16]]),
            deterministic_slot_nonces: Some(vec![[0x61; 12], [0x62; 12]]),
            deterministic_salt: Some([0x71; 16]),
            deterministic_nonce: Some([0x72; 12]),
            deterministic_epoch: None,
        }
    }

    #[test]
    fn multi_two_slot_roundtrip_and_isolation() {
        let c = ctx();
        let frag = c.seal_multi(&two_slot_input()).unwrap();

        // Outer shape: v2, password-less (flags 0), kind MULTI inside.
        let bytes = envelope::b64::decode(&frag).unwrap();
        assert_eq!(bytes[0], crate::ENVELOPE_VERSION);
        assert_eq!(bytes[1], 0, "outer is password-less with exp 0");

        // Password one opens exactly slot one's secret (never slot two's —
        // the no-sliced-KDF property: pw-one cannot derive slot two's key).
        let out1 = c.open(&frag, Some(b"pw-one"), &NoFetch).unwrap();
        assert_eq!(out1.data, b"secret_one");
        assert_eq!(out1.kind, kind::TOKEN);
        assert_eq!(out1.exp, 0);
        assert_eq!(out1.version, 2);

        // Password two opens exactly slot two's secret, with its own exp.
        let out2 = c.open(&frag, Some(b"pw-two"), &FixedFetch(1000.0)).unwrap();
        assert_eq!(out2.data, b"secret_two");
        assert_eq!(out2.kind, kind::BINARY_BLOB);
        assert_eq!(out2.exp, 2000);

        // Deterministic inputs reproduce the fragment byte-for-byte.
        assert_eq!(frag, c.seal_multi(&two_slot_input()).unwrap());
    }

    #[test]
    fn multi_wrong_or_missing_password() {
        let c = ctx();
        let frag = c.seal_multi(&two_slot_input()).unwrap();
        let err = c.open(&frag, Some(b"nope"), &NoFetch).unwrap_err();
        assert_eq!(err.code, ErrorCode::BadPassword);
        // No oracle about which slot almost matched.
        assert!(!err.detail.contains("slot"));
        // Missing password entirely: every slot fails with the empty key.
        let err = c.open(&frag, None, &NoFetch).unwrap_err();
        assert_eq!(err.code, ErrorCode::BadPassword);
    }

    #[test]
    fn multi_seal_validates_slots() {
        let c = ctx();
        // Zero slots.
        let mut zero_slots = two_slot_input();
        zero_slots.slots = Vec::new();
        let err = c.seal_multi(&zero_slots).unwrap_err();
        assert_eq!(err.code, ErrorCode::MalformedEnvelope);
        // Over the cap (default build: 4).
        let mut over = two_slot_input();
        while over.slots.len() <= envelope::multi::MAX_SLOTS {
            over.slots.push(over.slots[0].clone());
        }
        let err = c.seal_multi(&over).unwrap_err();
        assert_eq!(err.code, ErrorCode::TooManySlots);
        // Empty slot password.
        let mut empty_pw = two_slot_input();
        empty_pw.slots[0].password = Vec::new();
        let err = c.seal_multi(&empty_pw).unwrap_err();
        assert_eq!(err.code, ErrorCode::BadPassword);
        // Deterministic slot arrays must cover all slots.
        let mut bad_det = two_slot_input();
        bad_det.deterministic_slot_salts = Some(vec![[0x01; 16]]);
        assert_eq!(
            c.seal_multi(&bad_det).unwrap_err().code,
            ErrorCode::MalformedEnvelope
        );
    }

    #[test]
    fn multi_per_slot_expiry_enforced() {
        let c = ctx();
        let mut input = two_slot_input();
        input.slots[0].exp = Some(500); // past relative to mocked now
        let frag = c.seal_multi(&input).unwrap();
        // Slot 1's password now hits EXPIRED (net time authoritative)...
        let err = c
            .open(&frag, Some(b"pw-one"), &FixedFetch(1000.0))
            .unwrap_err();
        assert_eq!(err.code, ErrorCode::Expired);
        // ...while slot 2 (exp 2000) still opens. Admin path skips expiry.
        assert!(c.open(&frag, Some(b"pw-two"), &FixedFetch(1000.0)).is_ok());
        let out = c
            .open_ignoring_expiry(&frag, Some(b"pw-one"), &NoFetch)
            .unwrap();
        assert_eq!(out.data, b"secret_one");
        assert_eq!(out.exp, 500);
    }

    #[test]
    fn multi_slot_tamper_breaks_only_that_slot() {
        let c = ctx();
        let frag = c.seal_multi(&two_slot_input()).unwrap();
        // Tamper INSIDE the outer AEAD (a wire-level flip would fail the
        // outer tag first): decrypt the password-less outer, corrupt slot 2's
        // ciphertext, re-seal the outer with the same key/salt/nonce.
        let env = envelope::decode(&envelope::b64::decode(&frag).unwrap()).unwrap();
        let key = c
            .derive_key_for_epoch(env.key_epoch, None, &env.salt)
            .unwrap();
        let pt = Aes256Gcm::new((&key.0).into())
            .decrypt(
                &env.nonce.into(),
                GcmPayload {
                    msg: env.ciphertext.as_ref(),
                    aad: &env.aad(),
                },
            )
            .unwrap();
        let payload = Payload::decode(&pt[envelope::key_commit::LEN..]).unwrap();
        let mut blob = envelope::multi::MultiBlob::decode(&payload.data).unwrap();
        let last = blob.slots[1].ciphertext.len() - 1;
        blob.slots[1].ciphertext[last] ^= 0x01;
        let mut new_pt = Vec::new();
        new_pt.extend_from_slice(&envelope::key_commit::build(&key.0));
        new_pt.extend_from_slice(
            &Payload {
                kind: kind::MULTI,
                exp: 0,
                data: blob.encode().unwrap(),
            }
            .encode()
            .unwrap(),
        );
        let mut new_env = env.clone();
        new_env.ciphertext = Aes256Gcm::new((&key.0).into())
            .encrypt(
                &env.nonce.into(),
                GcmPayload {
                    msg: &new_pt,
                    aad: &env.aad(),
                },
            )
            .unwrap();
        let tampered_frag = envelope::b64::encode(&envelope::encode(&new_env));

        // Slot 2's password now fails everywhere (its AEAD is broken)...
        let err = c
            .open(&tampered_frag, Some(b"pw-two"), &NoFetch)
            .unwrap_err();
        assert_eq!(err.code, ErrorCode::BadPassword);
        // ...but slot 1 is untouched and still opens.
        let out = c.open(&tampered_frag, Some(b"pw-one"), &NoFetch).unwrap();
        assert_eq!(out.data, b"secret_one");
    }

    #[test]
    fn multi_epoch_retirement_kills_link() {
        let c = ctx(); // single epoch 0
        let frag = c.seal_multi(&two_slot_input()).unwrap();
        let mut wire = envelope::b64::decode(&frag).unwrap();
        wire[2] = 0x05; // epoch not in registry
        let err = c
            .open(&envelope::b64::encode(&wire), Some(b"pw-one"), &NoFetch)
            .unwrap_err();
        assert_eq!(err.code, ErrorCode::EpochRetired);
    }

    #[test]
    fn multi_domain_gate_applies() {
        let c = ctx();
        let frag = c.seal_multi(&two_slot_input()).unwrap();
        let mut offhost = ctx();
        offhost.runtime_hostname = Some("evil.test".to_string());
        let err = offhost.open(&frag, Some(b"pw-one"), &NoFetch).unwrap_err();
        assert_eq!(err.code, ErrorCode::DomainMismatch);
    }

    #[test]
    fn multi_slot_keys_are_independent_derives() {
        // Property backing the isolation claim: the same password over two
        // different slot salts yields different keys (fresh Argon2id per
        // slot, never a sliced derive).
        let k1 = kdf::derive_argon2(
            &[7u8; 32],
            b"pw-one",
            &[0x51; 16],
            b"mosseal/v1\x1Fa.test,b.test",
            Argon2Profile::Minimum,
        )
        .unwrap();
        let k2 = kdf::derive_argon2(
            &[7u8; 32],
            b"pw-one",
            &[0x52; 16],
            b"mosseal/v1\x1Fa.test,b.test",
            Argon2Profile::Minimum,
        )
        .unwrap();
        assert_ne!(k1.0, k2.0);
    }

    // --- Deniable mode (WS3) ---

    fn deniable_input(cover_mode: CoverMode) -> DeniableSealInput {
        DeniableSealInput {
            cover_mode,
            cover_password: match cover_mode {
                CoverMode::Hidden => Some(b"cover-pw".to_vec()),
                CoverMode::Plain => None,
            },
            cover_decoy: CoverDecoy::User(b"decoy-pad ".to_vec()),
            hidden_password: b"hidden-pw".to_vec(),
            hidden: HiddenSpec::Single {
                data: b"hidden_secret_123".to_vec(),
                kind: kind::TOKEN,
                exp: None,
                deterministic_salt: Some([0x81; 16]),
                deterministic_nonce: Some([0x82; 12]),
                deterministic_epoch: None,
            },
            size_class: None,
            deterministic_salt: Some([0x91; 16]),
            deterministic_nonce: Some([0x92; 12]),
            deterministic_padding: Some([0x93; 32]),
            deterministic_epoch: None,
        }
    }

    #[test]
    fn deniable_roundtrip_both_cover_modes() {
        for mode in [CoverMode::Plain, CoverMode::Hidden] {
            let c = ctx();
            let input = deniable_input(mode);
            let frag = c.seal_deniable(&input).unwrap();

            // Exact size class: a single small hidden envelope fits 1 KiB.
            let wire = envelope::b64::decode(&frag).unwrap();
            assert_eq!(wire.len(), SizeClass::Kib1.total_bytes(), "mode {mode:?}");
            assert_eq!(wire[0], 2, "cover is v2");

            // Cover password semantics per mode (D4).
            let cover_pw: Option<&[u8]> = match mode {
                CoverMode::Hidden => Some(b"cover-pw"),
                CoverMode::Plain => None,
            };
            let out = c
                .open_deniable(&frag, cover_pw, Some(b"hidden-pw"), &NoFetch)
                .unwrap();
            assert_eq!(out.data, b"hidden_secret_123", "mode {mode:?}");
            assert_eq!(out.kind, kind::TOKEN);
            assert_eq!(out.version, 2);

            // Deterministic inputs reproduce the fragment byte-for-byte.
            assert_eq!(frag, c.seal_deniable(&input).unwrap());
        }
    }

    #[test]
    fn deniable_cover_open_shows_only_decoy() {
        let c = ctx();
        let frag = c.seal_deniable(&deniable_input(CoverMode::Plain)).unwrap();
        // A NORMAL open (not openHidden) returns the cover payload: the
        // decoy pattern plus masked/hidden bytes — never the hidden plaintext.
        let cover = c.open(&frag, None, &NoFetch).unwrap();
        assert_eq!(cover.kind, kind::BINARY_BLOB);
        assert_eq!(cover.data.len(), SizeClass::Kib1.data_len());
        let decoy = b"decoy-pad ".as_slice();
        let decoy_hits = cover
            .data
            .windows(decoy.len())
            .filter(|w| *w == decoy)
            .count();
        assert!(
            decoy_hits > 10,
            "decoy fills the padding (hits: {decoy_hits})"
        );
        assert!(!contains(&cover.data, b"hidden_secret_123"));
        // The hidden envelope never leaks in the fragment either.
        let frag_bytes = frag.as_bytes();
        assert!(!contains(frag_bytes, b"hidden_secret_123"));
    }

    #[test]
    fn deniable_wrong_passwords() {
        let c = ctx();
        // Plain cover: wrong hidden password.
        let frag = c.seal_deniable(&deniable_input(CoverMode::Plain)).unwrap();
        let err = c
            .open_deniable(&frag, None, Some(b"WRONG"), &NoFetch)
            .unwrap_err();
        assert_eq!(err.code, ErrorCode::BadPassword);
        // Missing hidden password entirely.
        let err = c.open_deniable(&frag, None, None, &NoFetch).unwrap_err();
        assert_eq!(err.code, ErrorCode::BadPassword);
        // Hidden cover: wrong cover password fails at the cover layer.
        let frag = c.seal_deniable(&deniable_input(CoverMode::Hidden)).unwrap();
        let err = c
            .open_deniable(&frag, Some(b"WRONG"), Some(b"hidden-pw"), &NoFetch)
            .unwrap_err();
        assert_eq!(err.code, ErrorCode::BadPassword);
        // Hidden cover opened without a cover password.
        let err = c
            .open_deniable(&frag, None, Some(b"hidden-pw"), &NoFetch)
            .unwrap_err();
        assert_eq!(err.code, ErrorCode::BadPassword);
    }

    #[test]
    fn deniable_hidden_multi() {
        let c = ctx();
        let mut input = deniable_input(CoverMode::Plain);
        let hidden_multi = HiddenSpec::Multi(MultiSealInput {
            slots: vec![
                MultiSlot {
                    password: b"hidden-pw".to_vec(),
                    data: b"slot_zero_secret".to_vec(),
                    kind: kind::TOKEN,
                    exp: None,
                },
                MultiSlot {
                    password: b"other-slot-pw".to_vec(),
                    data: b"slot_one_secret".to_vec(),
                    kind: kind::BINARY_BLOB,
                    exp: None,
                },
            ],
            deterministic_slot_salts: Some(vec![[0xA1; 16], [0xA2; 16]]),
            deterministic_slot_nonces: Some(vec![[0xB1; 12], [0xB2; 12]]),
            deterministic_salt: Some([0xC1; 16]),
            deterministic_nonce: Some([0xC2; 12]),
            deterministic_epoch: None,
        });
        input.hidden = hidden_multi;
        let frag = c.seal_deniable(&input).unwrap();
        // The hidden password (= slot 0's) locates the layer AND opens its slot.
        let out = c
            .open_deniable(&frag, None, Some(b"hidden-pw"), &NoFetch)
            .unwrap();
        assert_eq!(out.data, b"slot_zero_secret");
        // Another slot's password cannot LOCATE the hidden envelope (the
        // offset derives from the hidden password) — documented limitation.
        let err = c
            .open_deniable(&frag, None, Some(b"other-slot-pw"), &NoFetch)
            .unwrap_err();
        assert_eq!(err.code, ErrorCode::BadPassword);
        // Guard: hidden password that matches no slot is rejected at seal.
        let mut bad = input.clone();
        bad.hidden_password = b"unmatched".to_vec();
        assert_eq!(
            c.seal_deniable(&bad).unwrap_err().code,
            ErrorCode::BadPassword
        );
    }

    #[test]
    fn deniable_size_classes_exact() {
        let c = ctx();
        for class in [SizeClass::Kib1, SizeClass::Kib2, SizeClass::Kib4] {
            let mut input = deniable_input(CoverMode::Plain);
            input.size_class = Some(class);
            let frag = c.seal_deniable(&input).unwrap();
            let wire = envelope::b64::decode(&frag).unwrap();
            assert_eq!(wire.len(), class.total_bytes(), "{class:?}");
            assert_eq!(
                envelope::b64::decode(&frag).unwrap().len(),
                class.total_bytes()
            );
            // All links in a class are byte-length-identical (D5): a second,
            // different seal lands on the same exact length.
            let mut other = deniable_input(CoverMode::Plain);
            other.size_class = Some(class);
            other.hidden = HiddenSpec::Single {
                data: b"a-different-and-longer-hidden-secret!".to_vec(),
                kind: kind::BINARY_BLOB,
                exp: Some(2_000_000_000),
                deterministic_salt: Some([0x11; 16]),
                deterministic_nonce: Some([0x12; 12]),
                deterministic_epoch: None,
            };
            let frag2 = c.seal_deniable(&other).unwrap();
            assert_eq!(
                envelope::b64::decode(&frag2).unwrap().len(),
                class.total_bytes()
            );
        }
        // Auto class picks the smallest that fits: small secret → 1 KiB.
        let frag = c.seal_deniable(&deniable_input(CoverMode::Plain)).unwrap();
        assert_eq!(
            envelope::b64::decode(&frag).unwrap().len(),
            SizeClass::Kib1.total_bytes()
        );
        // Pinned class too small for the hidden envelope → PAYLOAD_TOO_LARGE.
        let mut big = deniable_input(CoverMode::Plain);
        big.hidden = HiddenSpec::Single {
            data: vec![0x55; 1_500], // hidden envelope ≈ 1578 B: past 1 KiB, within 2 KiB
            kind: kind::BINARY_BLOB,
            exp: None,
            deterministic_salt: Some([0x21; 16]),
            deterministic_nonce: Some([0x22; 12]),
            deterministic_epoch: None,
        };
        big.size_class = Some(SizeClass::Kib1);
        assert_eq!(
            c.seal_deniable(&big).unwrap_err().code,
            ErrorCode::PayloadTooLarge
        );
        // Auto-escalated it fits the next class.
        big.size_class = None;
        let frag = c.seal_deniable(&big).unwrap();
        assert_eq!(
            envelope::b64::decode(&frag).unwrap().len(),
            SizeClass::Kib2.total_bytes()
        );
    }

    #[test]
    fn deniable_offset_varies_with_password() {
        // Same cover salt, different hidden passwords → different offset
        // material (smoke check of D6 uniformity).
        let b = b"mosseal/v1\x1Fa.test,b.test";
        let salt = [0x91; 16];
        let data_len = SizeClass::Kib1.data_len();
        let hidden_len = 200usize; // any plausible envelope size
        let modulus = data_len - 4 - hidden_len;
        let mut offsets = std::collections::HashSet::new();
        for pw in [
            &b"alpha"[..],
            &b"beta"[..],
            &b"gamma"[..],
            &b"delta"[..],
            &b"epsilon"[..],
        ] {
            let arg = kdf::derive_argon2_offset(b, pw, &salt, Argon2Profile::Minimum).unwrap();
            let off = 4 + (u32::from_le_bytes(arg[0..4].try_into().unwrap()) as usize % modulus);
            offsets.insert(off);
        }
        assert!(
            offsets.len() >= 4,
            "offsets should mostly differ: {offsets:?}"
        );
    }

    #[test]
    fn deniable_epoch_retirement_kills_both_layers() {
        let c = ctx();
        let frag = c.seal_deniable(&deniable_input(CoverMode::Plain)).unwrap();
        let mut wire = envelope::b64::decode(&frag).unwrap();
        wire[2] = 0x07; // cover epoch out of registry → cover itself dies
        let err = c
            .open_deniable(
                &envelope::b64::encode(&wire),
                None,
                Some(b"hidden-pw"),
                &NoFetch,
            )
            .unwrap_err();
        assert_eq!(err.code, ErrorCode::EpochRetired);
    }

    #[test]
    fn deniable_seal_input_validation() {
        let c = ctx();
        // Empty hidden password.
        let mut bad = deniable_input(CoverMode::Plain);
        bad.hidden_password = Vec::new();
        assert_eq!(
            c.seal_deniable(&bad).unwrap_err().code,
            ErrorCode::BadPassword
        );
        // cover=hidden without a cover password.
        let mut bad = deniable_input(CoverMode::Hidden);
        bad.cover_password = None;
        assert_eq!(
            c.seal_deniable(&bad).unwrap_err().code,
            ErrorCode::BadPassword
        );
        // cover=plain with a cover password.
        let mut bad = deniable_input(CoverMode::Plain);
        bad.cover_password = Some(b"x".to_vec());
        assert_eq!(
            c.seal_deniable(&bad).unwrap_err().code,
            ErrorCode::MalformedEnvelope
        );
        // Hidden single with MULTI kind is rejected.
        let mut bad = deniable_input(CoverMode::Plain);
        bad.hidden = HiddenSpec::Single {
            data: b"x".to_vec(),
            kind: kind::MULTI,
            exp: None,
            deterministic_salt: None,
            deterministic_nonce: None,
            deterministic_epoch: None,
        };
        assert_eq!(
            c.seal_deniable(&bad).unwrap_err().code,
            ErrorCode::UnsupportedKind
        );
    }

    #[test]
    fn deniable_hidden_expiry_and_admin_path() {
        let c = ctx();
        let mut input = deniable_input(CoverMode::Plain);
        input.hidden = HiddenSpec::Single {
            data: b"expiring_secret".to_vec(),
            kind: kind::TOKEN,
            exp: Some(500), // past relative to mocked now
            deterministic_salt: Some([0x31; 16]),
            deterministic_nonce: Some([0x32; 12]),
            deterministic_epoch: None,
        };
        let frag = c.seal_deniable(&input).unwrap();
        let err = c
            .open_deniable(&frag, None, Some(b"hidden-pw"), &FixedFetch(1000.0))
            .unwrap_err();
        assert_eq!(err.code, ErrorCode::Expired);
        // Admin path recovers it regardless of expiry.
        let out = c
            .open_deniable_ignoring_expiry(&frag, None, Some(b"hidden-pw"), &NoFetch)
            .unwrap();
        assert_eq!(out.data, b"expiring_secret");
        assert_eq!(out.exp, 500);
    }

    fn contains(haystack: &[u8], needle: &[u8]) -> bool {
        needle.is_empty() || haystack.windows(needle.len()).any(|w| w == needle)
    }
}
