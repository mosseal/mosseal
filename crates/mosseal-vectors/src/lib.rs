//! Conformance-vector generation (spec 08).
//!
//! Native Rust is the source of truth: it seals with **fixed** test secrets,
//! injected salt/nonce, and a mocked clock, so every vector is byte-exact.
//! The Node/browser suites must reproduce both seal and open byte-for-byte.
//!
//! `generate()` returns the canonical `vectors.json` text; the `mosseal-vectors`
//! binary writes it, and the `drift` test diffs a fresh generation against the
//! checked-in file (format-drift tripwire, spec 08 § CI).

use mosseal_core::{
    binding,
    epoch::EpochRegistry,
    kdf::{self, Argon2Profile},
    seal::{
        CoverDecoy, CoverMode, DeniableSealInput, HiddenSpec, MultiSealInput, MultiSlot,
        SealContext, SealInput,
    },
    time::{FetchTimes, TimeMode, TimeSource},
};
use serde_json::{json, Value};

/// Mocked "now" for expiry vectors (spec 08: time is mocked).
pub const NOW: f64 = 1_700_000_000.0;

/// Fixed test secrets — NOT the consumer's (spec 08). Three slots with epoch
/// 1 **retired** (a hole), so sparse-registry behavior is exercised: epoch 0
/// and epoch 2 stay valid while epoch 1 yields `EPOCH_RETIRED`.
const SECRET_0: [u8; 32] = [0x11; 32];
const SECRET_2: [u8; 32] = [0x33; 32];

/// Fixed test whitelist (spec 08).
const DOMAINS: [&str; 2] = ["a.test", "b.test"];

struct FixedFetch(f64);
impl FetchTimes for FixedFetch {
    fn fetch_unix_secs(&self, _s: &[TimeSource]) -> Option<f64> {
        Some(self.0)
    }
}

struct NoFetch;
impl FetchTimes for NoFetch {
    fn fetch_unix_secs(&self, _s: &[TimeSource]) -> Option<f64> {
        None
    }
}

fn b64(bytes: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

fn ctx() -> SealContext {
    SealContext {
        // Sparse: epoch 1 is a retired hole.
        epochs: EpochRegistry::from_slots(vec![Some(SECRET_0), None, Some(SECRET_2)]),
        whitelist: DOMAINS.iter().map(|s| s.to_string()).collect(),
        argon_profile: Argon2Profile::Minimum,
        time_mode: TimeMode::Lenient,
        runtime_hostname: None,
        time_sources: Vec::new(),
    }
}

/// A roundtrip vector: seal deterministically, then open (optionally with a
/// mocked clock) and assert the exact fragment + output.
struct Roundtrip {
    name: &'static str,
    data: &'static str,
    kind: u8,
    exp: Option<u64>,
    password: Option<&'static str>,
    salt: [u8; 16],
    nonce: [u8; 12],
    epoch: Option<u8>,
    /// Envelope version pin (1 = legacy regression vectors, 2 = v2 vectors).
    version: u8,
    /// Mocked net time for open; `None` = no fetch (exp=0 path).
    open_time: Option<f64>,
}

fn seal_input(v: &Roundtrip) -> SealInput {
    SealInput {
        data: v.data.as_bytes().to_vec(),
        kind: v.kind,
        exp: v.exp,
        password: v.password.map(|p| p.as_bytes().to_vec()),
        deterministic_salt: Some(v.salt),
        deterministic_nonce: Some(v.nonce),
        deterministic_epoch: v.epoch,
        deterministic_version: Some(v.version),
    }
}

fn roundtrip_vector(c: &SealContext, v: &Roundtrip) -> Value {
    let fragment = c.seal(&seal_input(v)).expect("seal vector");
    let out = match v.open_time {
        Some(t) => c
            .open(&fragment, v.password.map(|p| p.as_bytes()), &FixedFetch(t))
            .expect("open vector"),
        None => c
            .open(&fragment, v.password.map(|p| p.as_bytes()), &NoFetch)
            .expect("open vector"),
    };
    json!({
        "name": v.name,
        "type": "roundtrip",
        "input": {
            "data": v.data,
            "kind": v.kind,
            "expSecs": v.exp,
            "password": v.password,
        },
        "deterministic": {
            "salt": hex::encode(v.salt),
            "nonce": hex::encode(v.nonce),
            "epoch": v.epoch,
            "version": v.version,
        },
        "expectFragment": fragment,
        "expectOpen": {
            "data": String::from_utf8_lossy(&out.data),
            "exp": out.exp,
            "kind": out.kind,
        },
        "openWithTime": v.open_time,
    })
}

/// An open-error vector: a fragment plus open params that must yield a code.
fn open_error_vector(
    name: &'static str,
    fragment: String,
    password: Option<&'static str>,
    now: Option<f64>,
    expect: &'static str,
) -> Value {
    json!({
        "name": name,
        "type": "open-error",
        "open": { "fragment": fragment, "password": password, "nowSecs": now },
        "expectError": expect,
    })
}

/// A deniable open-error vector: a fragment plus cover/hidden passwords that
/// must yield a code through the hidden-open path.
fn open_hidden_error_vector(
    name: &str,
    fragment: &str,
    cover_password: Option<&'static str>,
    hidden_password: &str,
) -> Value {
    json!({
        "name": name,
        "type": "open-hidden-error",
        "open": { "fragment": fragment, "coverPassword": cover_password, "hiddenPassword": hidden_password },
        "expectError": "BAD_PASSWORD",
    })
}

/// A seal-error vector: inputs that must fail at seal time.
fn seal_error_vector(name: &'static str, data_len: usize, expect: &'static str) -> Value {
    json!({
        "name": name,
        "type": "seal-error",
        "input": { "dataLen": data_len, "kind": 1, "expSecs": null, "password": null },
        "expectError": expect,
    })
}

/// A multi-slot roundtrip vector: seal_multi deterministically, open with a
/// designated slot password, and record both (spec 08 § multi).
fn multi_roundtrip_vector(c: &SealContext, v: &MultiVector) -> Value {
    let input = MultiSealInput {
        slots: v
            .slots
            .iter()
            .map(|s| MultiSlot {
                password: s.0.as_bytes().to_vec(),
                data: s.1.as_bytes().to_vec(),
                kind: s.2,
                exp: s.3,
            })
            .collect(),
        deterministic_slot_salts: Some(v.slot_salts.to_vec()),
        deterministic_slot_nonces: Some(v.slot_nonces.to_vec()),
        deterministic_salt: Some(v.salt),
        deterministic_nonce: Some(v.nonce),
        deterministic_epoch: v.epoch,
    };
    let fragment = c.seal_multi(&input).expect("seal multi vector");
    let open_pw = v.slots[v.open_slot_index].0.as_bytes();
    // Per-slot expiry is enforced with the mocked vector clock (spec 08).
    let out = c
        .open(&fragment, Some(open_pw), &FixedFetch(NOW))
        .expect("open multi vector");
    json!({
        "name": v.name,
        "type": "multi-roundtrip",
        "input": {
            "slots": v.slots.iter().map(|s| json!({
                "password": s.0,
                "data": s.1,
                "kind": s.2,
                "expSecs": s.3,
            })).collect::<Vec<_>>(),
        },
        "deterministic": {
            "slotSalts": v.slot_salts.iter().map(hex::encode).collect::<Vec<_>>(),
            "slotNonces": v.slot_nonces.iter().map(hex::encode).collect::<Vec<_>>(),
            "salt": hex::encode(v.salt),
            "nonce": hex::encode(v.nonce),
            "epoch": v.epoch,
        },
        "expectFragment": fragment,
        "openWithTime": NOW,
        "expectOpen": {
            "password": v.slots[v.open_slot_index].0,
            "data": String::from_utf8_lossy(&out.data),
            "exp": out.exp,
            "kind": out.kind,
        },
    })
}

struct MultiVector {
    name: &'static str,
    /// (password, data, kind, exp) per slot.
    slots: &'static [(&'static str, &'static str, u8, Option<u64>)],
    slot_salts: &'static [[u8; 16]],
    slot_nonces: &'static [[u8; 12]],
    salt: [u8; 16],
    nonce: [u8; 12],
    epoch: Option<u8>,
    open_slot_index: usize,
}

/// A deniable roundtrip vector: seal_deniable deterministically (padding
/// seed), open the hidden layer, and record both (spec 08 § deniable).
fn deniable_roundtrip_vector(c: &SealContext, v: &DeniableVector) -> Value {
    let input = DeniableSealInput {
        cover_mode: v.cover_mode,
        cover_password: v.cover_password.map(|p| p.as_bytes().to_vec()),
        cover_decoy: match v.decoy {
            Some(d) => CoverDecoy::User(d.as_bytes().to_vec()),
            None => CoverDecoy::Random,
        },
        hidden_password: v.hidden_password.as_bytes().to_vec(),
        hidden: HiddenSpec::Single {
            data: v.hidden_data.as_bytes().to_vec(),
            kind: v.hidden_kind,
            exp: v.hidden_exp,
            deterministic_salt: Some(v.hidden_salt),
            deterministic_nonce: Some(v.hidden_nonce),
            deterministic_epoch: None,
        },
        size_class: Some(v.size_class),
        deterministic_salt: Some(v.salt),
        deterministic_nonce: Some(v.nonce),
        deterministic_padding: Some(v.padding_seed),
        deterministic_epoch: None,
    };
    let fragment = c.seal_deniable(&input).expect("seal deniable vector");
    let out = c
        .open_deniable(
            &fragment,
            v.cover_password.map(str::as_bytes),
            Some(v.hidden_password.as_bytes()),
            &NoFetch,
        )
        .expect("open deniable vector");
    json!({
        "name": v.name,
        "type": "deniable-roundtrip",
        "input": {
            "cover": {
                "mode": match v.cover_mode { CoverMode::Hidden => "hidden", CoverMode::Plain => "plain" },
                "password": v.cover_password,
                "decoy": v.decoy,
            },
            "hiddenPassword": v.hidden_password,
            "hidden": {
                "data": v.hidden_data,
                "kind": v.hidden_kind,
                "expSecs": v.hidden_exp,
            },
            "sizeClass": match v.size_class {
                mosseal_core::seal::SizeClass::Kib1 => 1,
                mosseal_core::seal::SizeClass::Kib2 => 2,
                mosseal_core::seal::SizeClass::Kib4 => 4,
            },
        },
        "deterministic": {
            "salt": hex::encode(v.salt),
            "nonce": hex::encode(v.nonce),
            "paddingSeed": hex::encode(v.padding_seed),
            "hiddenSalt": hex::encode(v.hidden_salt),
            "hiddenNonce": hex::encode(v.hidden_nonce),
        },
        "expectFragment": fragment,
        "expectOpen": {
            "coverPassword": v.cover_password,
            "data": String::from_utf8_lossy(&out.data),
            "exp": out.exp,
            "kind": out.kind,
        },
    })
}

struct DeniableVector {
    name: &'static str,
    cover_mode: CoverMode,
    cover_password: Option<&'static str>,
    decoy: Option<&'static str>,
    hidden_password: &'static str,
    hidden_data: &'static str,
    hidden_kind: u8,
    hidden_exp: Option<u64>,
    size_class: mosseal_core::seal::SizeClass,
    salt: [u8; 16],
    nonce: [u8; 12],
    padding_seed: [u8; 32],
    hidden_salt: [u8; 16],
    hidden_nonce: [u8; 12],
}

/// Forge a v2 envelope whose AEAD is valid (encrypted under the true epoch
/// key with the correct AAD) but whose plaintext omits the key-commitment
/// prefix — the partitioning/forgery shape the commitment closes (spec 08).
fn forge_uncommitted_v2(c: &SealContext, salt: [u8; 16], nonce: [u8; 12]) -> String {
    use aes_gcm::{
        aead::{Aead, KeyInit, Payload as GcmPayload},
        Aes256Gcm,
    };
    use mosseal_core::envelope::{self, Envelope, Payload};
    let epoch = c.epochs.latest_epoch().unwrap();
    let b = mosseal_core::binding::binding_string(&c.whitelist);
    let secret = c.epochs.secret(epoch).unwrap();
    let key = kdf::derive_hkdf(secret, &salt, &b);
    let header = Envelope {
        version: 2,
        flags: 0,
        key_epoch: epoch,
        salt,
        nonce,
        ciphertext: Vec::new(),
    };
    let payload = Payload {
        kind: mosseal_core::envelope::kind::TOKEN,
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

/// Build the full vector set (spec 08: every KDF path, flag combo, error code).
pub fn build() -> Value {
    let c = ctx();

    let roundtrips = [
        Roundtrip {
            name: "token-nopass-exp0",
            data: "tok_abc123",
            kind: 1,
            exp: None,
            password: None,
            salt: [0x01; 16],
            nonce: [0x02; 12],
            epoch: None,
            version: 1,
            open_time: None,
        },
        Roundtrip {
            name: "token-nopass-exp3600",
            data: "tok_abc123",
            kind: 1,
            exp: Some(NOW as u64 + 3600),
            password: None,
            salt: [0x03; 16],
            nonce: [0x04; 12],
            epoch: None,
            version: 1,
            open_time: Some(NOW),
        },
        Roundtrip {
            name: "token-password-exp0",
            data: "tok_abc123",
            kind: 1,
            exp: None,
            password: Some("hunter2"),
            salt: [0x05; 16],
            nonce: [0x06; 12],
            epoch: None,
            version: 1,
            open_time: None,
        },
        Roundtrip {
            name: "token-password-exp3600",
            data: "tok_abc123",
            kind: 1,
            exp: Some(NOW as u64 + 3600),
            password: Some("hunter2"),
            salt: [0x07; 16],
            nonce: [0x08; 12],
            epoch: None,
            version: 1,
            open_time: Some(NOW),
        },
        Roundtrip {
            name: "binaryblob-nopass-exp0",
            data: "state-blob",
            kind: 2,
            exp: None,
            password: None,
            salt: [0x09; 16],
            nonce: [0x0a; 12],
            epoch: None,
            version: 1,
            open_time: None,
        },
        Roundtrip {
            name: "epoch2-nopass-exp0",
            data: "tok_epoch2",
            kind: 1,
            exp: None,
            password: None,
            salt: [0x0b; 16],
            nonce: [0x0c; 12],
            epoch: Some(2),
            version: 1,
            open_time: None,
        },
        Roundtrip {
            name: "empty-data-nopass-exp0",
            data: "",
            kind: 1,
            exp: None,
            password: None,
            salt: [0x0d; 16],
            nonce: [0x0e; 12],
            epoch: None,
            version: 1,
            open_time: None,
        },
        Roundtrip {
            name: "unicode-nopass-exp0",
            data: "tökén-✓",
            kind: 1,
            exp: None,
            password: None,
            salt: [0x0f; 16],
            nonce: [0x10; 12],
            epoch: None,
            version: 1,
            open_time: None,
        },
        // --- v2 single roundtrips (key-commitment prefix, current seals) ---
        Roundtrip {
            name: "v2-token-nopass-exp0",
            data: "tok_abc123",
            kind: 1,
            exp: None,
            password: None,
            salt: [0x15; 16],
            nonce: [0x16; 12],
            epoch: None,
            version: 2,
            open_time: None,
        },
        Roundtrip {
            name: "v2-token-password-exp0",
            data: "tok_abc123",
            kind: 1,
            exp: None,
            password: Some("hunter2"),
            salt: [0x17; 16],
            nonce: [0x18; 12],
            epoch: None,
            version: 2,
            open_time: None,
        },
        Roundtrip {
            name: "v2-token-nopass-exp3600",
            data: "tok_abc123",
            kind: 1,
            exp: Some(NOW as u64 + 3600),
            password: None,
            salt: [0x19; 16],
            nonce: [0x1a; 12],
            epoch: None,
            version: 2,
            open_time: Some(NOW),
        },
        Roundtrip {
            name: "v2-epoch2-nopass-exp0",
            data: "tok_epoch2",
            kind: 1,
            exp: None,
            password: None,
            salt: [0x1b; 16],
            nonce: [0x1c; 12],
            epoch: Some(2),
            version: 2,
            open_time: None,
        },
        Roundtrip {
            name: "v2-binaryblob-nopass-exp0",
            data: "state-blob",
            kind: 2,
            exp: None,
            password: None,
            salt: [0x1d; 16],
            nonce: [0x1e; 12],
            epoch: None,
            version: 2,
            open_time: None,
        },
    ];

    let mut vectors: Vec<Value> = roundtrips.iter().map(|v| roundtrip_vector(&c, v)).collect();

    // --- Error vectors (spec 08: every error code has ≥ 1 vector) ---

    // BAD_PASSWORD: wrong password on a password-protected link.
    let pw_frag = c.seal(&seal_input(&roundtrips[2])).unwrap();
    vectors.push(open_error_vector(
        "wrong-password",
        pw_frag.clone(),
        Some("WRONG"),
        None,
        "BAD_PASSWORD",
    ));
    // BAD_PASSWORD: password omitted entirely on a protected link.
    vectors.push(open_error_vector(
        "missing-password",
        pw_frag,
        None,
        None,
        "BAD_PASSWORD",
    ));

    // EXPIRED: exp in the past relative to mocked now.
    let expired = Roundtrip {
        name: "expired",
        data: "tok_abc123",
        kind: 1,
        exp: Some(1000),
        password: None,
        salt: [0x11; 16],
        nonce: [0x12; 12],
        epoch: None,
        version: 1,
        open_time: None,
    };
    let expired_frag = c.seal(&seal_input(&expired)).unwrap();
    vectors.push(open_error_vector(
        "expired",
        expired_frag,
        None,
        Some(NOW),
        "EXPIRED",
    ));

    // MALFORMED_ENVELOPE: not base64url.
    vectors.push(open_error_vector(
        "malformed-not-base64",
        "not!base64!!".to_string(),
        None,
        None,
        "MALFORMED_ENVELOPE",
    ));

    // MALFORMED_ENVELOPE: valid base64url but truncated envelope.
    vectors.push(open_error_vector(
        "malformed-truncated",
        b64(&[0x01, 0x00, 0x00]),
        None,
        None,
        "MALFORMED_ENVELOPE",
    ));

    // UNSUPPORTED_VERSION: bump the version byte of a valid envelope beyond
    // both openable versions (v1 and v2).
    let base = c.seal(&seal_input(&roundtrips[0])).unwrap();
    let mut bytes = mosseal_core::envelope::b64::decode(&base).unwrap();
    bytes[0] = 0x03;
    vectors.push(open_error_vector(
        "unsupported-version",
        b64(&bytes),
        None,
        None,
        "UNSUPPORTED_VERSION",
    ));

    // EPOCH_RETIRED: point the epoch byte at an epoch not in the registry.
    let mut bytes = mosseal_core::envelope::b64::decode(&base).unwrap();
    bytes[2] = 0x05;
    vectors.push(open_error_vector(
        "epoch-retired",
        b64(&bytes),
        None,
        None,
        "EPOCH_RETIRED",
    ));

    // EPOCH_RETIRED: point the epoch byte at a RETIRED HOLE (epoch 1).
    let mut bytes = mosseal_core::envelope::b64::decode(&base).unwrap();
    bytes[2] = 0x01;
    vectors.push(open_error_vector(
        "epoch-retired-hole",
        b64(&bytes),
        None,
        None,
        "EPOCH_RETIRED",
    ));

    // MALFORMED_ENVELOPE: flip a ciphertext byte (GCM tag failure, no password).
    let mut bytes = mosseal_core::envelope::b64::decode(&base).unwrap();
    let last = bytes.len() - 1;
    bytes[last] ^= 0x01;
    vectors.push(open_error_vector(
        "tampered-ciphertext",
        b64(&bytes),
        None,
        None,
        "MALFORMED_ENVELOPE",
    ));

    // UNSUPPORTED_KIND: seal with an unknown kind byte (seal does not validate
    // `kind`); open must reject it (spec 01/02 taxonomy).
    let unknown_kind = Roundtrip {
        name: "unsupported-kind",
        data: "tok",
        kind: 0x09,
        exp: None,
        password: None,
        salt: [0x13; 16],
        nonce: [0x14; 12],
        epoch: None,
        version: 1,
        open_time: None,
    };
    let unknown_frag = c.seal(&seal_input(&unknown_kind)).unwrap();
    vectors.push(open_error_vector(
        "unsupported-kind",
        unknown_frag,
        None,
        None,
        "UNSUPPORTED_KIND",
    ));

    // PAYLOAD_TOO_LARGE: one byte over the v1 cap.
    vectors.push(seal_error_vector(
        "payload-too-large",
        mosseal_core::MAX_PAYLOAD_BYTES + 1,
        "PAYLOAD_TOO_LARGE",
    ));

    // --- v2 error vectors ---

    // Commitment tamper (spec 08): a v2 envelope whose AEAD is valid but
    // whose plaintext omits the key-commitment prefix must be rejected.
    let forged = forge_uncommitted_v2(&c, [0x25; 16], [0x26; 12]);
    vectors.push(open_error_vector(
        "v2-commitment-missing",
        forged,
        None,
        None,
        "MALFORMED_ENVELOPE",
    ));

    // --- MULTI vectors (spec 08 § multi) ---

    let multi = MultiVector {
        name: "multi-2slot",
        slots: &[
            ("pw-one", "secret_one", 1, None),
            ("pw-two", "secret_two", 2, Some(NOW as u64 + 3600)),
        ],
        slot_salts: &[[0xD1; 16], [0xD2; 16]],
        slot_nonces: &[[0xE1; 12], [0xE2; 12]],
        salt: [0xF1; 16],
        nonce: [0xF2; 12],
        epoch: None,
        open_slot_index: 1,
    };
    let multi_json = multi_roundtrip_vector(&c, &multi);
    let multi_frag = multi_json["expectFragment"].as_str().unwrap().to_string();
    vectors.push(multi_json);
    // Wrong password across all slots.
    vectors.push(open_error_vector(
        "multi-wrong-password",
        multi_frag,
        Some("WRONG"),
        None,
        "BAD_PASSWORD",
    ));
    // Seal-time slot cap (default build: MAX_SLOTS = 4).
    vectors.push(json!({
        "name": "multi-too-many-slots",
        "type": "seal-multi-error",
        "input": { "slots": mosseal_core::envelope::multi::MAX_SLOTS + 1 },
        "expectError": "TOO_MANY_SLOTS",
    }));

    // --- Deniable vectors (spec 08 § deniable, both cover modes) ---

    let deniable_vectors = [
        DeniableVector {
            name: "deniable-plain-single",
            cover_mode: CoverMode::Plain,
            cover_password: None,
            decoy: Some("plausible decoy bytes "),
            hidden_password: "hidden-hunter",
            hidden_data: "hidden_secret_123",
            hidden_kind: 1,
            hidden_exp: None,
            size_class: mosseal_core::seal::SizeClass::Kib1,
            salt: [0x35; 16],
            nonce: [0x36; 12],
            padding_seed: [0x37; 32],
            hidden_salt: [0x38; 16],
            hidden_nonce: [0x39; 12],
        },
        DeniableVector {
            name: "deniable-hidden-cover-single",
            cover_mode: CoverMode::Hidden,
            cover_password: Some("cover-hunter"),
            decoy: None,
            hidden_password: "hidden-hunter",
            hidden_data: "hidden_secret_456",
            hidden_kind: 1,
            hidden_exp: None,
            size_class: mosseal_core::seal::SizeClass::Kib1,
            salt: [0x45; 16],
            nonce: [0x46; 12],
            padding_seed: [0x47; 32],
            hidden_salt: [0x48; 16],
            hidden_nonce: [0x49; 12],
        },
    ];
    for v in &deniable_vectors {
        let json = deniable_roundtrip_vector(&c, v);
        let frag = json["expectFragment"].as_str().unwrap().to_string();
        vectors.push(json);
        // Wrong hidden password (either cover mode): recovery fails closed.
        vectors.push(open_hidden_error_vector(
            &format!("{}-wrong-hidden-password", v.name),
            &frag,
            v.cover_password,
            "WRONG",
        ));
    }

    json!({
        "formatVersion": 1,
        "generatedBy": "mosseal-vectors",
        "envelopeVersion": mosseal_core::ENVELOPE_VERSION,
        "config": {
            "secrets": [b64(&SECRET_0), String::new(), b64(&SECRET_2)],
            "domains": DOMAINS,
            "argonProfile": "minimum",
        },
        "now": NOW,
        "vectors": vectors,
    })
}

/// Canonical `vectors.json` text (pretty-printed, trailing newline).
pub fn generate() -> String {
    let mut s = serde_json::to_string_pretty(&build()).expect("serialize vectors");
    s.push('\n');
    s
}

/// Compare a file at `path` against freshly generated vectors.
///
/// Returns `Ok(())` when identical, `Err(reason)` otherwise. Extracted from the
/// binary so the `--check` tripwire is unit-testable without touching the
/// checked-in file.
pub fn check_file(path: &std::path::Path, generated: &str) -> std::result::Result<(), String> {
    let existing = std::fs::read_to_string(path).map_err(|e| format!("cannot read: {e}"))?;
    if existing == generated {
        Ok(())
    } else {
        Err("vectors.json is STALE — regenerate with `cargo run -p mosseal-vectors`".into())
    }
}

/// Write freshly generated vectors to `path`.
pub fn write_file(path: &std::path::Path, generated: &str) -> std::io::Result<()> {
    std::fs::write(path, generated)
}

/// Sanity check used by the drift test: the config's binding string must match
/// what the vectors were sealed under (guards accidental whitelist drift).
pub fn binding_string() -> Vec<u8> {
    binding::binding_string(&DOMAINS.iter().map(|s| s.to_string()).collect::<Vec<_>>())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vectors_are_deterministic() {
        assert_eq!(generate(), generate(), "generation must be stable");
    }

    #[test]
    fn every_error_code_covered() {
        let v = build();
        let codes: Vec<&str> = v["vectors"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|x| x["expectError"].as_str())
            .collect();
        for code in [
            "MALFORMED_ENVELOPE",
            "UNSUPPORTED_VERSION",
            "UNSUPPORTED_KIND",
            "PAYLOAD_TOO_LARGE",
            "BAD_PASSWORD",
            "EXPIRED",
            "EPOCH_RETIRED",
            "TOO_MANY_SLOTS",
        ] {
            assert!(codes.contains(&code), "missing error vector for {code}");
        }
        // TOO_MANY_SLOTS arrives via the seal-multi-error vector type.
        let types: Vec<&str> = v["vectors"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|x| x["type"].as_str())
            .collect();
        assert!(types.contains(&"seal-multi-error"));
        assert!(types.contains(&"multi-roundtrip"));
        assert!(types.contains(&"deniable-roundtrip"));
        assert!(types.contains(&"open-hidden-error"));
        // STRICT_TIME_UNAVAILABLE and DOMAIN_MISMATCH are covered elsewhere
        // (native unit/integration tests + the browser suite) — they are not
        // reachable through this vector harness (lenient mode, no host gate).
    }

    /// Cross-compat proof: every v1 vector's recorded fragment still opens
    /// through the v2-capable code (spec 08 § v1 read path).
    #[test]
    fn v1_fragments_open_on_v2() {
        let c = ctx();
        let v = build();
        for vec in v["vectors"].as_array().unwrap() {
            if vec["type"] != "roundtrip" {
                continue;
            }
            let version = vec["deterministic"]["version"].as_u64().unwrap();
            if version != 1 {
                continue;
            }
            // Loop-invariant: type is "roundtrip" (filtered above) and the
            // vector needs no mocked clock at open.
            if vec["openWithTime"].is_null() {
                let fragment = vec["expectFragment"].as_str().unwrap();
                let password = vec["input"]["password"].as_str().map(str::as_bytes);
                let out = c
                    .open(fragment, password, &NoFetch)
                    .unwrap_or_else(|e| panic!("v1 vector {} failed: {e}", vec["name"]));
                assert_eq!(out.version, 1, "v1 opens report version 1");
            }
        }
    }

    /// Multi vectors reproduce byte-exactly from their deterministic inputs
    /// and reopen to the designated slot's output.
    #[test]
    fn multi_vectors_reproduce_and_reopen() {
        let c = ctx();
        let v = build();
        for vec in v["vectors"].as_array().unwrap() {
            if vec["type"] != "multi-roundtrip" {
                continue;
            }
            // Re-seal from the recorded deterministic inputs.
            let slots: Vec<MultiSlot> = vec["input"]["slots"]
                .as_array()
                .unwrap()
                .iter()
                .map(|s| MultiSlot {
                    password: s["password"].as_str().unwrap().as_bytes().to_vec(),
                    data: s["data"].as_str().unwrap().as_bytes().to_vec(),
                    kind: s["kind"].as_u64().unwrap() as u8,
                    exp: s["expSecs"].as_u64(),
                })
                .collect();
            let salts: Vec<[u8; 16]> = vec["deterministic"]["slotSalts"]
                .as_array()
                .unwrap()
                .iter()
                .map(|h| {
                    hex::decode(h.as_str().unwrap())
                        .unwrap()
                        .try_into()
                        .unwrap()
                })
                .collect();
            let nonces: Vec<[u8; 12]> = vec["deterministic"]["slotNonces"]
                .as_array()
                .unwrap()
                .iter()
                .map(|h| {
                    hex::decode(h.as_str().unwrap())
                        .unwrap()
                        .try_into()
                        .unwrap()
                })
                .collect();
            let input = MultiSealInput {
                slots,
                deterministic_slot_salts: Some(salts),
                deterministic_slot_nonces: Some(nonces),
                deterministic_salt: Some(
                    hex::decode(vec["deterministic"]["salt"].as_str().unwrap())
                        .unwrap()
                        .try_into()
                        .unwrap(),
                ),
                deterministic_nonce: Some(
                    hex::decode(vec["deterministic"]["nonce"].as_str().unwrap())
                        .unwrap()
                        .try_into()
                        .unwrap(),
                ),
                deterministic_epoch: vec["deterministic"]["epoch"].as_u64().map(|e| e as u8),
            };
            let frag = c.seal_multi(&input).unwrap();
            assert_eq!(
                frag,
                vec["expectFragment"].as_str().unwrap(),
                "multi vector {} drifted",
                vec["name"]
            );
            // Reopen through the designated slot (mocked vector clock).
            let pw = vec["expectOpen"]["password"].as_str().unwrap();
            let now = vec["openWithTime"].as_f64().unwrap_or(NOW);
            let out = c
                .open(&frag, Some(pw.as_bytes()), &FixedFetch(now))
                .unwrap();
            assert_eq!(
                String::from_utf8_lossy(&out.data),
                vec["expectOpen"]["data"].as_str().unwrap()
            );
            assert_eq!(out.kind, vec["expectOpen"]["kind"].as_u64().unwrap() as u8);
            assert_eq!(out.version, 2);
        }
    }

    /// Deniable vectors reproduce byte-exactly from their deterministic
    /// inputs (padding seed included) and reopen via the hidden path.
    #[test]
    fn deniable_vectors_reproduce_and_reopen() {
        let c = ctx();
        let v = build();
        for vec in v["vectors"].as_array().unwrap() {
            if vec["type"] != "deniable-roundtrip" {
                continue;
            }
            let d = &vec["deterministic"];
            let input = DeniableSealInput {
                cover_mode: match vec["input"]["cover"]["mode"].as_str().unwrap() {
                    "hidden" => CoverMode::Hidden,
                    _ => CoverMode::Plain,
                },
                cover_password: vec["input"]["cover"]["password"]
                    .as_str()
                    .map(|p| p.as_bytes().to_vec()),
                cover_decoy: match vec["input"]["cover"]["decoy"].as_str() {
                    Some(d) => CoverDecoy::User(d.as_bytes().to_vec()),
                    None => CoverDecoy::Random,
                },
                hidden_password: vec["input"]["hiddenPassword"]
                    .as_str()
                    .unwrap()
                    .as_bytes()
                    .to_vec(),
                hidden: HiddenSpec::Single {
                    data: vec["input"]["hidden"]["data"]
                        .as_str()
                        .unwrap()
                        .as_bytes()
                        .to_vec(),
                    kind: vec["input"]["hidden"]["kind"].as_u64().unwrap() as u8,
                    exp: vec["input"]["hidden"]["expSecs"].as_u64(),
                    deterministic_salt: Some(
                        hex::decode(d["hiddenSalt"].as_str().unwrap())
                            .unwrap()
                            .try_into()
                            .unwrap(),
                    ),
                    deterministic_nonce: Some(
                        hex::decode(d["hiddenNonce"].as_str().unwrap())
                            .unwrap()
                            .try_into()
                            .unwrap(),
                    ),
                    deterministic_epoch: None,
                },
                size_class: Some(match vec["input"]["sizeClass"].as_u64().unwrap() {
                    1 => mosseal_core::seal::SizeClass::Kib1,
                    2 => mosseal_core::seal::SizeClass::Kib2,
                    4 => mosseal_core::seal::SizeClass::Kib4,
                    other => panic!("bad size class {other}"),
                }),
                deterministic_salt: Some(
                    hex::decode(d["salt"].as_str().unwrap())
                        .unwrap()
                        .try_into()
                        .unwrap(),
                ),
                deterministic_nonce: Some(
                    hex::decode(d["nonce"].as_str().unwrap())
                        .unwrap()
                        .try_into()
                        .unwrap(),
                ),
                deterministic_padding: Some(
                    hex::decode(d["paddingSeed"].as_str().unwrap())
                        .unwrap()
                        .try_into()
                        .unwrap(),
                ),
                deterministic_epoch: None,
            };
            let frag = c.seal_deniable(&input).unwrap();
            assert_eq!(
                frag,
                vec["expectFragment"].as_str().unwrap(),
                "deniable vector {} drifted",
                vec["name"]
            );
            // Hidden reopen matches the recorded output.
            let cpw = vec["expectOpen"]["coverPassword"]
                .as_str()
                .map(str::as_bytes);
            let hpw = vec["input"]["hiddenPassword"].as_str().unwrap();
            let out = c
                .open_deniable(&frag, cpw, Some(hpw.as_bytes()), &NoFetch)
                .unwrap();
            assert_eq!(
                String::from_utf8_lossy(&out.data),
                vec["expectOpen"]["data"].as_str().unwrap()
            );
        }
    }

    #[test]
    fn roundtrips_reproduce() {
        // Re-sealing each roundtrip vector must yield the recorded fragment.
        let c = ctx();
        let v = build();
        for vec in v["vectors"].as_array().unwrap() {
            if vec["type"] != "roundtrip" {
                continue;
            }
            let salt: [u8; 16] = hex::decode(vec["deterministic"]["salt"].as_str().unwrap())
                .unwrap()
                .try_into()
                .unwrap();
            let nonce: [u8; 12] = hex::decode(vec["deterministic"]["nonce"].as_str().unwrap())
                .unwrap()
                .try_into()
                .unwrap();
            let input = SealInput {
                data: vec["input"]["data"].as_str().unwrap().as_bytes().to_vec(),
                kind: vec["input"]["kind"].as_u64().unwrap() as u8,
                exp: vec["input"]["expSecs"].as_u64(),
                password: vec["input"]["password"]
                    .as_str()
                    .map(|p| p.as_bytes().to_vec()),
                deterministic_salt: Some(salt),
                deterministic_nonce: Some(nonce),
                deterministic_epoch: vec["deterministic"]["epoch"].as_u64().map(|e| e as u8),
                deterministic_version: vec["deterministic"]["version"].as_u64().map(|v| v as u8),
            };
            let frag = c.seal(&input).unwrap();
            assert_eq!(
                frag,
                vec["expectFragment"].as_str().unwrap(),
                "vector {} drifted",
                vec["name"]
            );
        }
    }

    #[test]
    fn roundtrips_reopen_to_expect_open() {
        // Opening each recorded fragment must reproduce `expectOpen` exactly
        // (only re-sealing was checked before; open is the receiver path).
        let c = ctx();
        let v = build();
        for vec in v["vectors"].as_array().unwrap() {
            if vec["type"] != "roundtrip" {
                continue;
            }
            let fragment = vec["expectFragment"].as_str().unwrap();
            let password = vec["input"]["password"].as_str().map(str::as_bytes);
            let out = match vec["openWithTime"].as_f64() {
                Some(now) => c.open(fragment, password, &FixedFetch(now)),
                None => c.open(fragment, password, &NoFetch),
            }
            .unwrap_or_else(|e| panic!("open {} failed: {e}", vec["name"]));
            let expect = &vec["expectOpen"];
            assert_eq!(
                String::from_utf8_lossy(&out.data),
                expect["data"].as_str().unwrap(),
                "data drifted for {}",
                vec["name"]
            );
            assert_eq!(out.exp, expect["exp"].as_u64().unwrap(), "exp drifted");
            assert_eq!(
                out.kind,
                expect["kind"].as_u64().unwrap() as u8,
                "kind drifted"
            );
        }
    }

    #[test]
    fn check_and_write_helpers() {
        let dir = std::env::temp_dir().join(format!("mosseal-vectors-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("vectors.json");
        let generated = generate();

        // A freshly written file passes the check...
        write_file(&path, &generated).unwrap();
        assert!(check_file(&path, &generated).is_ok());
        // ...but any drift fails it.
        assert!(check_file(&path, &format!("{generated} ")).is_err());
        // A missing file is an error, not a panic.
        assert!(check_file(&dir.join("nope.json"), &generated).is_err());

        std::fs::remove_dir_all(&dir).ok();
    }
}
