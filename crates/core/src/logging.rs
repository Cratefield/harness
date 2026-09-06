//! Log-field redaction shared by every runtime (architecture section
//! 11, issue #13): field names matching `(?i)secret|token|key|
//! authorization|password` never reach output, and email-ish values are
//! logged only as a truncated SHA-256 `subject_hash` (12 hex chars).
//!
//! The tracing **formatter** lives in each runtime; the redaction rules
//! live here so Workers and native logs cannot drift apart.

use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use tracing::field::{Field, Visit};

/// Whether a field name marks a secret: matches
/// `(?i)secret|token|key|authorization|password`.
#[must_use]
pub fn is_secret_field(name: &str) -> bool {
    let lowered = name.to_ascii_lowercase();
    ["secret", "token", "key", "authorization", "password"]
        .iter()
        .any(|needle| lowered.contains(needle))
}

/// Whether a field is expected to carry an email address.
#[must_use]
pub fn is_email_field(name: &str) -> bool {
    let lowered = name.to_ascii_lowercase();
    lowered.contains("email") || lowered == "subject"
}

/// The redacted form of an email-ish value: its SHA-256 digest, 12 hex
/// characters, no `@` ever reaches the logs.
#[must_use]
pub fn subject_hash(value: &str) -> String {
    use std::fmt::Write as _;
    let digest = Sha256::digest(value.as_bytes());
    let mut hex = String::with_capacity(12);
    for byte in digest.iter().take(6) {
        let _ = write!(hex, "{byte:02x}");
    }
    hex
}

/// How one recorded field is stored: `[redacted]` for secrets, the hash
/// for emails, the value otherwise.
#[must_use]
pub fn redacted_value(name: &str, value: &str) -> String {
    if is_secret_field(name) {
        "[redacted]".to_owned()
    } else if is_email_field(name) && value.contains('@') {
        format!("subject_hash:{}", subject_hash(value))
    } else {
        value.to_owned()
    }
}

/// A `tracing` field visitor that records `(name, redacted value)` pairs
/// into a map. Runtimes use it in their formatters; tests use it to
/// prove the redaction rules.
#[derive(Debug, Default)]
pub struct RedactingVisitor {
    pub fields: BTreeMap<String, String>,
}

impl RedactingVisitor {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    fn record(&mut self, name: &str, value: &str) {
        self.fields
            .insert(name.to_owned(), redacted_value(name, value));
    }
}

impl Visit for RedactingVisitor {
    fn record_str(&mut self, field: &Field, value: &str) {
        self.record(field.name(), value);
    }

    fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
        self.record(field.name(), &format!("{value:?}"));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn secret_names_are_detected_case_insensitively() {
        for name in [
            "authorization",
            "Authorization",
            "api_token",
            "captchaToken",
            "HARNESS_SECRET",
            "kid_key",
            "password",
        ] {
            assert!(is_secret_field(name), "{name}");
        }
        assert!(!is_secret_field("outcome"));
        // Deliberately over-broad: `idempotency_key` matches too, so the
        // mailer-outcome logs name the field `idempotency` (issue #14).
        assert!(is_secret_field("idempotency_key"));
    }

    #[test]
    fn subject_hash_is_twelve_hex_without_the_address() {
        let hash = subject_hash("nick@example.com");
        assert_eq!(hash.len(), 12);
        assert!(hash.chars().all(|c| c.is_ascii_hexdigit()));
        assert!(!hash.contains('@'));
        assert_eq!(hash, subject_hash("nick@example.com"), "deterministic");
        assert_ne!(hash, subject_hash("nick2@example.com"));
    }

    #[test]
    fn visitor_rules_match_redacted_value() {
        for (name, value) in [
            ("authorization", "Bearer super-secret-token"),
            ("token", "captcha-value"),
            ("email", "nick@example.com"),
            ("subject", "nick@example.com"),
            ("outcome", "sent"),
        ] {
            let stored = redacted_value(name, value);
            if is_secret_field(name) {
                assert_eq!(stored, "[redacted]", "{name}");
            } else if is_email_field(name) && value.contains('@') {
                assert!(stored.starts_with("subject_hash:"), "{name}: {stored}");
                assert!(!stored.contains('@'));
            } else {
                assert_eq!(stored, value, "{name}");
            }
        }
    }

    #[test]
    fn non_email_values_in_email_fields_pass_through() {
        assert_eq!(
            redacted_value("email_domain", "factory0.ventures"),
            "factory0.ventures"
        );
    }
}
