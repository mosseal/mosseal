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
    kdf::Argon2Profile,
    seal::{SealContext, SealInput},
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

/// A seal-error vector: inputs that must fail at seal time.
fn seal_error_vector(name: &'static str, data_len: usize, expect: &'static str) -> Value {
    json!({
        "name": name,
        "type": "seal-error",
        "input": { "dataLen": data_len, "kind": 1, "expSecs": null, "password": null },
        "expectError": expect,
    })
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
            open_time: Some(NOW),
        },
        Roundtrip {
            name: "appstate-nopass-exp0",
            data: "state-blob",
            kind: 2,
            exp: None,
            password: None,
            salt: [0x09; 16],
            nonce: [0x0a; 12],
            epoch: None,
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

    // UNSUPPORTED_VERSION: bump the version byte of a valid envelope.
    let base = c.seal(&seal_input(&roundtrips[0])).unwrap();
    let mut bytes = mosseal_core::envelope::b64::decode(&base).unwrap();
    bytes[0] = 0x02;
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

    // PAYLOAD_TOO_LARGE: 256-byte payload exceeds the v1 cap.
    vectors.push(seal_error_vector(
        "payload-too-large",
        256,
        "PAYLOAD_TOO_LARGE",
    ));

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
        ] {
            assert!(codes.contains(&code), "missing error vector for {code}");
        }
        // STRICT_TIME_UNAVAILABLE and DOMAIN_MISMATCH are covered elsewhere
        // (native unit/integration tests + the browser suite) — they are not
        // reachable through this vector harness (lenient mode, no host gate).
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
