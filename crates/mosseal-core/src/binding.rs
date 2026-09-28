//! Domain binding string construction (spec 03).
//!
//! Two deliberately separated roles:
//!
//! 1. **Binding string** — the KDF input. Canonical and deployment-stable:
//!    the entire sorted whitelist participates, so links are portable across
//!    all whitelisted hosts of one deployment.
//!
//! 2. **Runtime allow-list check** — enforcement gate (browser only; the
//!    Node/CLI path is trusted and skips the check, but the whitelist still
//!    participates in the binding string).

use crate::{ErrorCode, MossealError, Result};

/// Unit separator joining binding components (spec 02 § Key derivation).
pub const SEP: u8 = 0x1F;

/// Construct the canonical binding string:
/// `"mosseal/v1" ‖ 0x1F ‖ join(sorted(whitelist), ",")`.
///
/// The whitelist is sorted before joining so `.env` reordering does not
/// invalidate links (spec 03 test requirements).
pub fn binding_string(whitelist: &[String]) -> Vec<u8> {
    let mut sorted: Vec<&str> = whitelist.iter().map(|s| s.trim()).collect();
    sorted.sort_unstable();
    let mut out = b"mosseal/v1".to_vec();
    out.push(SEP);
    out.extend_from_slice(sorted.join(",").as_bytes());
    out
}

/// Runtime allow-list check: exact-match hostnames only
/// (`evil-user.github.io` must not match `github.io`).
/// Missing/duplicate entries are the caller's problem (CLI validates).
pub fn runtime_host_allowed(hostname: &str, whitelist: &[String]) -> bool {
    whitelist.iter().any(|h| h.trim() == hostname)
}

/// Parse a comma-separated domains string into a whitelist.
///
/// This is the inverse of the wasm/template `allowed_domains_str()` codegen
/// slot (spec 05): entries are trimmed and empty entries dropped, so a
/// placeholder build (empty string) yields an empty list rather than `[""]`.
/// Shared by the wasm `Mosseal::new` and the template so both parse the
/// generated string identically.
pub fn parse_domain_list(s: &str) -> Vec<String> {
    s.split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect()
}

/// Validation shared by CLI + wasm init: bare lowercase hostnames only.
/// Regex equivalent: `^[a-z0-9.-]+$` (no scheme, slash, or port).
pub fn validate_whitelist(whitelist: &[String]) -> Result<()> {
    if whitelist.is_empty() {
        return Err(MossealError::new(
            ErrorCode::DomainMismatch,
            "allowed domains list is empty",
        ));
    }
    for host in whitelist {
        let h = host.trim();
        if h.is_empty() {
            return Err(MossealError::new(
                ErrorCode::DomainMismatch,
                "empty hostname in allowed domains",
            ));
        }
        let ok = !h.starts_with('.')
            && h.chars()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '.' || c == '-');
        if !ok {
            return Err(MossealError::new(
                ErrorCode::DomainMismatch,
                format!("invalid hostname entry: {h:?} (expected bare lowercase hostname)"),
            ));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn binding_is_order_insensitive() {
        let a = binding_string(&["b.com".into(), "a.com".into()]);
        let b = binding_string(&["a.com".into(), "b.com".into()]);
        assert_eq!(a, b);
        assert_eq!(&a, b"mosseal/v1\x1Fa.com,b.com");
    }

    #[test]
    fn runtime_check_is_exact_match() {
        let wl = [
            "user.github.io".to_string(),
            "custom-domain.com".to_string(),
        ];
        assert!(runtime_host_allowed("user.github.io", &wl));
        assert!(!runtime_host_allowed("github.io", &wl));
        assert!(!runtime_host_allowed("evil-user.github.io", &wl));
        assert!(!runtime_host_allowed("USER.GITHUB.IO", &wl));
        assert!(!runtime_host_allowed("", &wl));
    }

    #[test]
    fn validation_rejects_bad_entries() {
        assert!(validate_whitelist(&["a.com".into()]).is_ok());
        assert!(validate_whitelist(&[]).is_err());
        assert!(validate_whitelist(&["https://a.com".into()]).is_err());
        assert!(validate_whitelist(&["a.com:8080".into()]).is_err());
        assert!(validate_whitelist(&["A.com".into()]).is_err());
        assert!(validate_whitelist(&["a.com/x".into()]).is_err());
        assert!(validate_whitelist(&[".com".into()]).is_err());
        assert!(validate_whitelist(&["".into()]).is_err());
    }

    #[test]
    fn sep_is_unit_separator() {
        assert_eq!(SEP, 0x1F);
    }

    #[test]
    fn binding_trims_whitespace_entries() {
        // Surrounding whitespace must not change the binding (it would brick
        // links across `.env` files that pad entries).
        let a = binding_string(&[" a.com ".into(), "b.com".into()]);
        let b = binding_string(&["a.com".into(), "b.com".into()]);
        assert_eq!(a, b);
    }

    #[test]
    fn validation_accepts_surrounding_whitespace() {
        assert!(validate_whitelist(&["  a.com  ".into()]).is_ok());
    }

    #[test]
    fn parse_domain_list_trims_and_drops_empties() {
        assert_eq!(
            parse_domain_list("a.test,b.test"),
            vec!["a.test".to_string(), "b.test".to_string()]
        );
        // Whitespace-padded entries are trimmed.
        assert_eq!(
            parse_domain_list(" a.test , b.test "),
            vec!["a.test".to_string(), "b.test".to_string()]
        );
        // Placeholder/empty build → empty list (not `[""]`).
        assert!(parse_domain_list("").is_empty());
        assert!(parse_domain_list(",,").is_empty());
        assert!(parse_domain_list("  ").is_empty());
    }
}
