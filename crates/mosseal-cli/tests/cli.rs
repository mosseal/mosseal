//! CLI integration tests: drive the real `mosseal` binary end-to-end.
//!
//! These exercise the parts unit tests cannot: argument parsing, environment
//! variables (`MOSSEAL_EPOCHS` / `MOSSEAL_ALLOWED_DOMAINS`), stdout format, and
//! process exit codes (spec 05).

use assert_cmd::Command;
use predicates::prelude::*;

/// A base64url 32-byte epoch secret.
fn secret(byte: u8) -> String {
    use base64::Engine;
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([byte; 32])
}

fn mosseal() -> Command {
    Command::cargo_bin("mosseal").expect("mosseal binary builds")
}

#[test]
fn gen_secret_emits_32_byte_base64url() {
    let out = mosseal().arg("gen-secret").assert().success();
    let stdout = String::from_utf8(out.get_output().stdout.clone()).unwrap();
    let s = stdout.trim();
    assert!(!s.contains(['+', '/', '=']), "url-safe, unpadded");
    use base64::Engine;
    let raw = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(s)
        .expect("valid base64url");
    assert_eq!(raw.len(), 32);
}

#[test]
fn seal_then_open_roundtrip_via_flags() {
    let s = secret(1);
    let sealed = mosseal()
        .args(["seal", "tok_abc123", "--epochs", &s, "--domains", "a.test"])
        .assert()
        .success();
    let frag = String::from_utf8(sealed.get_output().stdout.clone())
        .unwrap()
        .trim()
        .to_string();
    assert!(!frag.is_empty());

    mosseal()
        .args(["open", &frag, "--epochs", &s, "--domains", "a.test"])
        .assert()
        .success()
        .stdout(predicate::str::contains("data: tok_abc123"))
        .stdout(predicate::str::contains("kind: 1"))
        .stdout(predicate::str::contains("exp:  0"));
}

#[test]
fn seal_then_open_roundtrip_via_env_vars() {
    let s = secret(2);
    let sealed = mosseal()
        .env("MOSSEAL_EPOCHS", &s)
        .env("MOSSEAL_ALLOWED_DOMAINS", "a.test,b.test")
        .args(["seal", "tok_env"])
        .assert()
        .success();
    let frag = String::from_utf8(sealed.get_output().stdout.clone())
        .unwrap()
        .trim()
        .to_string();

    mosseal()
        .env("MOSSEAL_EPOCHS", &s)
        .env("MOSSEAL_ALLOWED_DOMAINS", "a.test,b.test")
        .args(["open", &frag])
        .assert()
        .success()
        .stdout(predicate::str::contains("tok_env"));
}

#[test]
fn password_protected_link_needs_the_password() {
    let s = secret(3);
    let sealed = mosseal()
        .args([
            "seal",
            "tok_pw",
            "--password",
            "hunter2",
            "--epochs",
            &s,
            "--domains",
            "a.test",
        ])
        .assert()
        .success();
    let frag = String::from_utf8(sealed.get_output().stdout.clone())
        .unwrap()
        .trim()
        .to_string();

    // Correct password opens.
    mosseal()
        .args([
            "open",
            &frag,
            "--password",
            "hunter2",
            "--epochs",
            &s,
            "--domains",
            "a.test",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("tok_pw"));

    // Wrong password fails (non-zero exit), prints the stable code, and does
    // not leak the token.
    mosseal()
        .args([
            "open",
            &frag,
            "--password",
            "WRONG",
            "--epochs",
            &s,
            "--domains",
            "a.test",
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains("BAD_PASSWORD"))
        .stderr(predicate::str::contains("tok_pw").not());
}

#[test]
fn expired_link_fails_unless_ignore_expiry() {
    let s = secret(4);
    let sealed = mosseal()
        .args([
            "seal",
            "tok_exp",
            "--exp",
            "1",
            "--epochs",
            &s,
            "--domains",
            "a.test",
        ])
        .assert()
        .success();
    let frag = String::from_utf8(sealed.get_output().stdout.clone())
        .unwrap()
        .trim()
        .to_string();

    // Normal open: expired → failure.
    mosseal()
        .args(["open", &frag, "--epochs", &s, "--domains", "a.test"])
        .assert()
        .failure();

    // Admin path: `--ignore-expiry` prints the payload and exits 0.
    mosseal()
        .args([
            "open",
            &frag,
            "--epochs",
            &s,
            "--domains",
            "a.test",
            "--ignore-expiry",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("tok_exp"))
        .stdout(predicate::str::contains("exp:  1"));
}

#[test]
fn missing_epochs_fails() {
    mosseal()
        .args(["seal", "tok", "--domains", "a.test"])
        .env_remove("MOSSEAL_EPOCHS")
        .assert()
        .failure();
}

#[test]
fn invalid_domain_is_rejected() {
    let s = secret(5);
    mosseal()
        .args(["seal", "tok", "--epochs", &s, "--domains", "https://a.com"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("DOMAIN_MISMATCH"));
}

#[test]
fn seal_kind_binary_blob_roundtrips() {
    let s = secret(6);
    let sealed = mosseal()
        .args([
            "seal",
            "blob",
            "--kind",
            "binary-blob",
            "--epochs",
            &s,
            "--domains",
            "a.test",
        ])
        .assert()
        .success();
    let frag = String::from_utf8(sealed.get_output().stdout.clone())
        .unwrap()
        .trim()
        .to_string();

    mosseal()
        .args(["open", &frag, "--epochs", &s, "--domains", "a.test"])
        .assert()
        .success()
        .stdout(predicate::str::contains("kind: 2"));
}

#[test]
fn errors_use_the_stable_code_prefix() {
    // Parity contract with the TS CLI: `Error: <CODE>: <detail>`.
    mosseal()
        .args(["seal", "tok", "--epochs", "AAAA", "--domains", "a.test"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("Error: EPOCH_RETIRED:"));
}

#[test]
fn help_and_version_succeed() {
    mosseal()
        .arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains("seal"))
        .stdout(predicate::str::contains("open"))
        .stdout(predicate::str::contains("gen-secret"));

    mosseal()
        .arg("--version")
        .assert()
        .success()
        .stdout(predicate::str::contains("mosseal"));
}
