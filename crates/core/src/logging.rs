//! Log-field redaction shared by every runtime (architecture section
//! 11, issue #13): field names matching `(?i)secret|token|key|
//! authorization|password` never reach output, and email-ish values are
//! logged only as a truncated SHA-256 `subject_hash` (12 hex chars).
//!
//! The tracing **formatter** lives in each runtime; the redaction rules
//! live here so Workers and native logs cannot drift apart.

use hmac::{Hmac, KeyInit, Mac};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::sync::OnceLock;
use tracing::field::{Field, Visit};

/// A process-wide key that turns a logged email pseudonym into a keyed HMAC
/// rather than a bare hash. See [`set_log_pseudonym_key`].
static LOG_PSEUDONYM_KEY: OnceLock<Vec<u8>> = OnceLock::new();

/// Domain-separates the pseudonym HMAC from the signer's use of the same
/// secret, and versions it so the scheme can change without silently
/// colliding.
const PSEUDONYM_DOMAIN: &[u8] = b"cratefield/log-pseudonym/v1\x00";

/// Installs the key that [`subject_hash`] uses to pseudonymise email values in
/// logs (issue #135). A bare SHA-256 of a low-entropy email is
/// dictionary-reversible, so a runtime derives this from `HARNESS_SECRET` and
/// installs it once at startup; `subject_hash` then emits `HMAC(key, email)`
/// instead. Unset (tests, or a runtime that hasn't wired it) falls back to the
/// bare hash. Boot-time infrastructure, not request state (ADR 0007);
/// first-install-wins.
pub fn set_log_pseudonym_key(key: &[u8]) {
    let _ = LOG_PSEUDONYM_KEY.set(key.to_vec());
}

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

/// The redacted form of an email-ish value: a 12-hex pseudonym, no `@` ever
/// reaching the logs. When a [pseudonym key](set_log_pseudonym_key) is
/// installed it is `HMAC-SHA256(key, domain ‖ value)` (a keyed pseudonym,
/// resistant to dictionary reversal); otherwise it degrades to a bare
/// SHA-256 digest.
#[must_use]
pub fn subject_hash(value: &str) -> String {
    use std::fmt::Write as _;
    // Keyed HMAC pseudonym when a key is installed, else a bare digest. The
    // redaction path never panics: HMAC accepts any key length, and the
    // `.ok()` fallback covers the impossible error rather than unwrapping it.
    let digest: [u8; 32] = LOG_PSEUDONYM_KEY
        .get()
        .and_then(|key| Hmac::<Sha256>::new_from_slice(key).ok())
        .map_or_else(
            || Sha256::digest(value.as_bytes()).into(),
            |mut mac| {
                mac.update(PSEUDONYM_DOMAIN);
                mac.update(value.as_bytes());
                mac.finalize().into_bytes().into()
            },
        );
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

// ---------------------------------------------------------------------------
// Internal-error forwarder (issue #107)

/// A process-wide sink for internal-error diagnostics, installed by the
/// runtime. See [`set_error_forwarder`].
type ErrorForwarder = fn(&str);

static ERROR_FORWARDER: OnceLock<ErrorForwarder> = OnceLock::new();

/// Installs a process-wide forwarder for internal-error diagnostics
/// (architecture section 11).
///
/// On `wasm32` a tracing dispatcher cannot be installed — it hangs the
/// workerd/miniflare isolate — so every `tracing::error!` core emits when it
/// maps an internal failure to a 500 is dropped, and a Workers 500 becomes a
/// black box (issue #107). The Cloudflare runtime therefore points this
/// forwarder at `worker::console_error!`, and core calls it alongside its
/// `tracing::error!` so the same one-line diagnostic reaches Workers Logs.
///
/// Native runs leave it unset and rely on the tracing subscriber. This is
/// boot-time infrastructure installed before the first response, not request
/// state (ADR 0007); the first installation wins and later calls are ignored.
pub fn set_error_forwarder(forwarder: ErrorForwarder) {
    let _ = ERROR_FORWARDER.set(forwarder);
}

/// Forwards a one-line internal-error diagnostic to the installed sink, if
/// any; a no-op when none is installed (native, tests). Callers pass a message
/// already safe to log — no raw field values that could carry a secret or an
/// email (the [`redacted_value`] rules apply to structured `tracing` fields,
/// not to this pre-formatted line).
pub(crate) fn forward_internal_error(line: &str) {
    if let Some(forwarder) = ERROR_FORWARDER.get() {
        forwarder(line);
    }
}

#[cfg(test)]
#[allow(clippy::disallowed_types)] // test-only capture of the forwarded line
mod forwarder_tests {
    use super::*;
    use std::sync::Mutex;

    static CAPTURED: Mutex<Vec<String>> = Mutex::new(Vec::new());

    fn capture(line: &str) {
        CAPTURED.lock().unwrap().push(line.to_owned());
    }

    #[test]
    fn an_installed_forwarder_receives_the_line() {
        // The forwarder is a process-wide `OnceLock`, so this is the only test
        // that installs one; `set` after the first is a no-op by contract.
        set_error_forwarder(capture);
        forward_internal_error("database error mapped to internal problem: boom");
        assert!(
            CAPTURED
                .lock()
                .unwrap()
                .iter()
                .any(|line| line.contains("boom")),
            "the installed forwarder should have received the diagnostic"
        );
    }

    #[test]
    fn forwarding_without_a_sink_is_a_noop() {
        // No panic, no output when nothing is installed (native, tests that do
        // not opt in). This asserts the call is safe regardless of ordering.
        forward_internal_error("ignored when no sink or captured when set");
    }
}
