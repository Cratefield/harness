//! Log-field redaction shared by every runtime (architecture section
//! 11, issue #13): field names matching `(?i)secret|token|key|
//! authorization|password` never reach output, and email-ish values are
//! logged only as a 12-hex `subject_hash` pseudonym — a keyed HMAC when
//! a runtime installed [`set_log_pseudonym_key`], and a fixed placeholder
//! when it has not: never a bare digest, even misconfigured (issue #135).
//!
//! Field **names** are only half the story (issue #135): a secret riding
//! inside a generic `uri`, `message` or `error` value is invisible to a
//! name rule. Every value that is not redacted by name therefore also
//! passes [`scrub_text`], which rewrites emails, signed tokens, URL query
//! strings, URL credentials and `Bearer` values wherever they appear.
//!
//! The tracing **formatter** lives in each runtime; the redaction rules
//! live here so Workers and native logs cannot drift apart.

use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;
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

/// The value [`subject_hash`] emits when no pseudonym key is installed: a
/// fixed placeholder, never a function of the input (issue #135, fail-closed).
/// The unkeyed path is reachable in production — a runtime that finds
/// `HARNESS_SECRET` missing or too short only warns and keeps serving, so a
/// misconfigured deployment must still not emit a truncated bare SHA-256
/// (deterministic, unkeyed, dictionary-reversible for low-entropy emails).
/// All-zero hex is obviously-not-a-pseudonym in a log grep, lies outside the
/// range any real HMAC prefix occupies, and keeps the `subject_hash:<12 hex>`
/// output shape that [`scrub_text`]'s idempotence and the runtime formatters
/// depend on, so nothing downstream changes.
const UNKEYED_PSEUDONYM: &str = "000000000000";

/// Installs the key that [`subject_hash`] uses to pseudonymise email values in
/// logs (issue #135). A bare SHA-256 of a low-entropy email is
/// dictionary-reversible, so a runtime derives this from `HARNESS_SECRET` and
/// installs it once at startup; `subject_hash` then emits `HMAC(key, email)`
/// instead. Unset (tests, or a runtime whose `HARNESS_SECRET` failed
/// validation) makes `subject_hash` emit the fixed [`UNKEYED_PSEUDONYM`]
/// placeholder — fail-closed; no digest of the address ever reaches a sink.
/// Boot-time infrastructure, not request state (ADR 0007); first-install-wins.
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
/// resistant to dictionary reversal); when it is not, a fixed
/// [placeholder](UNKEYED_PSEUDONYM) — correlation is lost, but a bare digest
/// never leaks (issue #135, fail-closed).
#[must_use]
pub fn subject_hash(value: &str) -> String {
    pseudonym_hex(LOG_PSEUDONYM_KEY.get().map(Vec::as_slice), value)
}

/// The pseudonym decision of [`subject_hash`], pure in `key` so both arms
/// are testable without touching the process-wide `OnceLock` (which is
/// first-install-wins and already set by `tests/log_pseudonym.rs`).
fn pseudonym_hex(key: Option<&[u8]>, value: &str) -> String {
    use std::fmt::Write as _;
    // The redaction path never panics: HMAC accepts any key length, and
    // the `.ok()` arm covers the impossible error without unwrapping it —
    // a key that fails to install is treated as no key at all (fail-closed).
    let digest = key.and_then(|secret| {
        Hmac::<Sha256>::new_from_slice(secret).ok().map(|mut mac| {
            mac.update(PSEUDONYM_DOMAIN);
            mac.update(value.as_bytes());
            mac.finalize().into_bytes()
        })
    });
    let Some(digest) = digest else {
        return UNKEYED_PSEUDONYM.to_owned();
    };
    let mut hex = String::with_capacity(12);
    for byte in digest.iter().take(6) {
        let _ = write!(hex, "{byte:02x}");
    }
    hex
}

/// How one recorded field is stored: `[redacted]` for secrets, the hash
/// for emails, the value passed through [`scrub_text`] otherwise (issue
/// #135: a secret inside a generic `uri`/`message`/`error` value is
/// invisible to the field-name rules alone).
#[must_use]
pub fn redacted_value(name: &str, value: &str) -> String {
    if is_secret_field(name) {
        "[redacted]".to_owned()
    } else if is_email_field(name) && value.contains('@') {
        format!("subject_hash:{}", subject_hash(value))
    } else {
        scrub_text(value)
    }
}

// ---------------------------------------------------------------------------
// Value-level scrubbing (issue #135)

/// The marker [`scrub_text`] leaves in place of redacted material.
const REDACTED: &str = "[redacted]";

/// Bytes that may appear inside a URL run in log text. Whitespace and the
/// delimiters a URL is typically wrapped in (`"`, `'`, `(`, `<`, …) end
/// the run, so a URL embedded in prose or `{:?}` output is matched whole.
/// `[` and `]` stay inside the run so a re-scrub of an already-redacted
/// `?[redacted]` query is a no-op: the scrubber is idempotent.
fn url_body_byte(b: u8) -> bool {
    !matches!(
        b,
        b' ' | b'\t'
            | b'\n'
            | b'\r'
            | b'"'
            | b'\''
            | b'<'
            | b'>'
            | b'`'
            | b','
            | b';'
            | b')'
            | b'}'
            | b'\\'
            | b'|'
    )
}

fn base64url_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'-' || b == b'_'
}

fn email_local_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric()
        || matches!(
            b,
            b'.' | b'!'
                | b'#'
                | b'$'
                | b'%'
                | b'&'
                | b'\''
                | b'*'
                | b'+'
                | b'-'
                | b'/'
                | b'='
                | b'?'
                | b'^'
                | b'_'
                | b'`'
                | b'{'
                | b'|'
                | b'}'
                | b'~'
        )
}

fn email_domain_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'.' || b == b'-'
}

/// Scrubs secrets out of a free-text **value** (issue #135).
///
/// Field-name redaction ([`redacted_value`]) cannot see a secret riding
/// inside a generic field — an `error` carrying a driver's `DETAIL:` line
/// that quotes a row, a `message` carrying a confirmation URL, a `uri`
/// carrying `?token=…`. Every value that is not redacted by name goes
/// through here:
///
/// - an email address becomes `[subject_hash:<pseudonym>]` — the same
///   keyed pseudonym the email fields use, so correlation survives;
/// - a signed token or JWT (`eyJ…`, dot-separated base64url runs) becomes
///   `[redacted]` — the signer's payload is base64url JSON, which always
///   starts with `eyJ`;
/// - the query of a URL (`scheme://…?…`) or of a path-shaped value
///   (`/v1/…?…`) becomes `?[redacted]` — confirmation, unsubscribe and
///   status tokens ride in the query;
/// - URL userinfo (`scheme://user:pass@host`) becomes
///   `scheme://[redacted]@host` — a connect failure must not disclose
///   database credentials;
/// - `Bearer <credential>` becomes `Bearer [redacted]`.
///
/// The rules are heuristics tuned for log values and deliberately
/// over-redact: losing a query string costs debugging convenience,
/// leaking a token or an address costs users. Idempotent — scrubbing
/// already-scrubbed text changes nothing. Never panics.
#[must_use]
pub fn scrub_text(value: &str) -> String {
    let urls = scrub_urls(value);
    let paths = scrub_path_queries(&urls);
    let tokens = scrub_dotted_tokens(&paths);
    let bearer = scrub_bearer(&tokens);
    scrub_emails(&bearer)
}

/// The URL pass of [`scrub_text`]: query and userinfo redaction for every
/// absolute URL (`scheme://…`) in the value.
fn scrub_urls(value: &str) -> String {
    let bytes = value.as_bytes();
    let mut out = String::with_capacity(value.len());
    let mut processed = 0;
    let mut search = 0;
    while let Some(relative) = value[search..].find("://") {
        let colon = search + relative;
        let mut scheme_start = colon;
        while scheme_start > processed {
            let b = bytes[scheme_start - 1];
            if b.is_ascii_alphanumeric() || matches!(b, b'+' | b'-' | b'.') {
                scheme_start -= 1;
            } else {
                break;
            }
        }
        if scheme_start == colon {
            // "://" with no scheme in front of it is not a URL.
            search = colon + 3;
            continue;
        }
        let mut end = colon + 3;
        while end < bytes.len() && url_body_byte(bytes[end]) {
            end += 1;
        }
        out.push_str(&value[processed..scheme_start]);
        out.push_str(&scrub_one_url(&value[scheme_start..end]));
        processed = end;
        search = end;
    }
    out.push_str(&value[processed..]);
    out
}

fn scrub_one_url(url: &str) -> String {
    let Some((scheme, rest)) = url.split_once("://") else {
        return url.to_owned();
    };
    let authority_end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let (authority, tail) = rest.split_at(authority_end);
    let mut out = String::with_capacity(url.len());
    out.push_str(scheme);
    out.push_str("://");
    match authority.rfind('@') {
        Some(at) => {
            out.push_str(REDACTED);
            out.push_str(&authority[at..]);
        }
        None => out.push_str(authority),
    }
    match tail.find('?') {
        Some(query) => {
            out.push_str(&tail[..query]);
            out.push('?');
            out.push_str(REDACTED);
        }
        None => out.push_str(tail),
    }
    out
}

/// The path pass of [`scrub_text`]: a whitespace-delimited word that is
/// itself a path — a `uri` field, a redirect target inside a message —
/// loses its query: "/v1/waitlist/status?token=…".
fn scrub_path_queries(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    let mut rest = value;
    while !rest.is_empty() {
        let lead = rest
            .find(|c: char| !c.is_ascii_whitespace())
            .unwrap_or(rest.len());
        out.push_str(&rest[..lead]);
        let word_end = rest[lead..]
            .find(|c: char| c.is_ascii_whitespace())
            .map_or(rest.len(), |offset| lead + offset);
        let word = &rest[lead..word_end];
        match word.strip_prefix('/') {
            Some(_) => match word.find('?') {
                Some(query) => {
                    out.push_str(&word[..query]);
                    out.push('?');
                    out.push_str(REDACTED);
                }
                None => out.push_str(word),
            },
            None => out.push_str(word),
        }
        rest = &rest[word_end..];
    }
    out
}

/// The signed-token pass of [`scrub_text`]: a run of dot-separated
/// base64url segments, each at least 8 chars, starting with `eyJ`.
fn scrub_dotted_tokens(value: &str) -> String {
    let bytes = value.as_bytes();
    let mut out = String::with_capacity(value.len());
    let mut processed = 0;
    let mut search = 0;
    while let Some(relative) = value[search..].find("eyJ") {
        let start = search + relative;
        if start > processed && (base64url_byte(bytes[start - 1]) || bytes[start - 1] == b'.') {
            // A mid-run hit inside a longer token or word, not its start.
            search = start + 3;
            continue;
        }
        let mut end = start;
        let mut segments = 0;
        let mut all_segments_long = true;
        loop {
            let segment_start = end;
            while end < bytes.len() && base64url_byte(bytes[end]) {
                end += 1;
            }
            segments += 1;
            if end - segment_start < 8 {
                all_segments_long = false;
            }
            if end + 1 < bytes.len() && bytes[end] == b'.' && base64url_byte(bytes[end + 1]) {
                end += 1;
                continue;
            }
            break;
        }
        if segments >= 2 && all_segments_long {
            out.push_str(&value[processed..start]);
            out.push_str(REDACTED);
            processed = end;
        }
        search = end.max(start + 3);
    }
    out.push_str(&value[processed..]);
    out
}

/// The `Bearer`-credential pass of [`scrub_text`].
fn scrub_bearer(value: &str) -> String {
    const LABEL: &str = "Bearer ";
    let bytes = value.as_bytes();
    let mut out = String::with_capacity(value.len());
    let mut processed = 0;
    let mut search = 0;
    while let Some(relative) = value[search..].find(LABEL) {
        let label_end = search + relative + LABEL.len();
        let mut end = label_end;
        while end < bytes.len()
            && (base64url_byte(bytes[end])
                || matches!(bytes[end], b'.' | b'+' | b'/' | b'=' | b'~'))
        {
            end += 1;
        }
        if end - label_end >= 8 {
            out.push_str(&value[processed..label_end]);
            out.push_str(REDACTED);
            processed = end;
        }
        search = label_end.max(processed);
    }
    out.push_str(&value[processed..]);
    out
}

/// The email pass of [`scrub_text`]: RFC-ish local part, dotted domain
/// whose last label is alphabetic — conservative enough that dependency
/// specs (`crate@1.0.0`) and versions survive, strict enough that every
/// address the harness itself accepts ([`crate::email::is_valid`]) is
/// caught.
fn scrub_emails(value: &str) -> String {
    let bytes = value.as_bytes();
    let mut out = String::with_capacity(value.len());
    let mut processed = 0;
    let mut search = 0;
    while let Some(relative) = value[search..].find('@') {
        let at = search + relative;
        let mut start = at;
        while start > processed && email_local_byte(bytes[start - 1]) {
            start -= 1;
        }
        let mut end = at + 1;
        while end < bytes.len() && email_domain_byte(bytes[end]) {
            end += 1;
        }
        let local = &value[start..at];
        let domain = &value[at + 1..end];
        if email_shape_ok(local, domain) {
            out.push_str(&value[processed..start]);
            out.push_str("[subject_hash:");
            out.push_str(&subject_hash(&value[start..end]));
            out.push(']');
            processed = end;
        }
        search = (at + 1).max(processed);
    }
    out.push_str(&value[processed..]);
    out
}

fn email_shape_ok(local: &str, domain: &str) -> bool {
    if local.is_empty() || local.len() > crate::email::MAX_LOCAL_BYTES {
        return false;
    }
    if local.starts_with('.') || local.ends_with('.') {
        return false;
    }
    if domain.is_empty() || !domain.contains('.') {
        return false;
    }
    if domain.starts_with('.') || domain.ends_with('.') || domain.contains("..") {
        return false;
    }
    if domain.len() > crate::email::MAX_EMAIL_BYTES {
        return false;
    }
    domain
        .split('.')
        .all(|label| !label.is_empty() && !label.starts_with('-') && !label.ends_with('-'))
        && domain
            .rsplit('.')
            .next()
            .is_some_and(|tld| tld.len() >= 2 && tld.bytes().all(|b| b.is_ascii_alphabetic()))
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

    /// The 12-hex truncation of `bytes`, same as `pseudonym_hex` does.
    fn hex_prefix(bytes: &[u8]) -> String {
        use std::fmt::Write as _;
        let mut hex = String::with_capacity(12);
        for byte in bytes.iter().take(6) {
            let _ = write!(hex, "{byte:02x}");
        }
        hex
    }

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
    fn subject_hash_without_a_key_is_the_fixed_placeholder() {
        // This binary never installs the process-wide `LOG_PSEUDONYM_KEY`,
        // so the public entry point exercises the fail-closed arm: the
        // output shape survives, the input sensitivity does not.
        let hash = subject_hash("nick@example.com");
        assert_eq!(hash, UNKEYED_PSEUDONYM, "no key, no digest");
        assert_eq!(hash.len(), 12);
        assert!(hash.chars().all(|c| c.is_ascii_hexdigit()));
        assert!(!hash.contains('@'));
        assert_eq!(
            hash,
            subject_hash("nick2@example.com"),
            "unkeyed output must not vary with the address"
        );
    }

    #[test]
    fn pseudonym_hex_without_a_key_is_constant_and_not_a_bare_digest() {
        // The fail-open regression (issue #135): with no key the old code
        // emitted the first 12 hex of a bare SHA-256 — deterministic and
        // dictionary-attackable. Every unkeyed pseudonym must be the fixed
        // placeholder instead, and never a digest prefix of its input.
        use sha2::Digest as _;
        for value in ["a@x.com", "b@x.com", "nick@example.com", ""] {
            assert_eq!(pseudonym_hex(None, value), UNKEYED_PSEUDONYM, "{value}");
            let digest: [u8; 32] = Sha256::digest(value.as_bytes()).into();
            assert_ne!(
                hex_prefix(&digest),
                pseudonym_hex(None, value),
                "the placeholder must not be a SHA-256 prefix of {value}"
            );
        }
        assert_eq!(
            pseudonym_hex(None, "a@x.com"),
            pseudonym_hex(None, "b@x.com"),
            "input-independent"
        );
    }

    #[test]
    fn pseudonym_hex_with_a_key_is_the_input_sensitive_hmac_form() {
        let key: &[u8] = b"harness-secret-long-enough-for-this-test-0123456789";
        let a = pseudonym_hex(Some(key), "a@x.com");
        assert_eq!(a.len(), 12, "keyed pseudonym keeps the shape: {a}");
        assert!(a.chars().all(|c| c.is_ascii_hexdigit()), "{a}");
        assert_ne!(a, UNKEYED_PSEUDONYM, "keyed output is not the placeholder");
        assert_eq!(
            a,
            pseudonym_hex(Some(key), "a@x.com"),
            "stable under one key"
        );
        assert_ne!(
            a,
            pseudonym_hex(Some(key), "b@x.com"),
            "keyed pseudonym stays input-sensitive"
        );
        // Byte-for-byte the same scheme as before the fail-closed change:
        // HMAC-SHA256(key, PSEUDONYM_DOMAIN ‖ value), first 6 bytes as hex.
        let mut mac = Hmac::<Sha256>::new_from_slice(key).expect("HMAC accepts any key length");
        mac.update(PSEUDONYM_DOMAIN);
        mac.update(b"a@x.com");
        assert_eq!(a, hex_prefix(&mac.finalize().into_bytes()));
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

    /// The leak the field-name rules miss (issue #135): a Postgres unique
    /// violation quotes the offending row — an email — in a generic
    /// `error` field, and the raw driver text must never reach the logs.
    #[test]
    fn scrub_text_pseudonymises_emails_inside_generic_values() {
        let driver = "duplicate key value violates unique constraint \
             \"subscribers_email_normalized_key\"\n\
             DETAIL:  Key (email_normalized)=(nick@example.com) already exists.";
        let scrubbed = scrub_text(driver);
        assert!(!scrubbed.contains('@'), "{scrubbed}");
        assert!(!scrubbed.contains("nick"), "{scrubbed}");
        assert!(scrubbed.contains("[subject_hash:"), "{scrubbed}");
        assert!(
            scrubbed.contains(&subject_hash("nick@example.com")),
            "the pseudonym is the same one the email fields use: {scrubbed}"
        );
        assert!(
            scrubbed.contains("duplicate key value violates unique constraint"),
            "the diagnostic itself survives: {scrubbed}"
        );

        assert_eq!(
            redacted_value("message", "mailer rejected bob@example.com"),
            format!(
                "mailer rejected [subject_hash:{}]",
                subject_hash("bob@example.com")
            )
        );
    }

    #[test]
    fn scrub_text_drops_query_strings_from_urls_and_paths() {
        let message = "GET https://api.factory0.ventures/v1/email-signup/confirm?token=abc \
             redirected to /v1/waitlist/status?token=def";
        let scrubbed = scrub_text(message);
        assert!(!scrubbed.contains("token=abc"), "{scrubbed}");
        assert!(!scrubbed.contains("token=def"), "{scrubbed}");
        assert!(
            scrubbed.contains("https://api.factory0.ventures/v1/email-signup/confirm?[redacted]"),
            "{scrubbed}"
        );
        assert!(
            scrubbed.contains("redirected to /v1/waitlist/status?[redacted]"),
            "{scrubbed}"
        );

        let uri = scrub_text("/ui/waitlist/status?token=01J.secret");
        assert_eq!(uri, "/ui/waitlist/status?[redacted]");

        assert_eq!(
            scrub_text("/v1/email-signup/confirm"),
            "/v1/email-signup/confirm",
            "a path without a query is untouched"
        );
    }

    #[test]
    fn scrub_text_redacts_url_credentials() {
        let connect = "error connecting to postgres://venture:sup3r-s3cret@db.internal:5432/app";
        let scrubbed = scrub_text(connect);
        assert!(!scrubbed.contains("sup3r-s3cret"), "{scrubbed}");
        assert!(!scrubbed.contains("venture:"), "{scrubbed}");
        assert!(
            scrubbed.contains("postgres://[redacted]@db.internal:5432/app"),
            "{scrubbed}"
        );
    }

    #[test]
    fn scrub_text_redacts_signed_tokens_wherever_they_appear() {
        use crate::ports::signer::{Kid, Payload, Signer};
        use crate::signer::HmacSigner;

        let signer = HmacSigner::new("0".repeat(crate::signer::MIN_SECRET_BYTES), None)
            .expect("test secret is long enough");
        let token = signer.sign(&Payload {
            purpose: "email-signup.confirm".to_owned(),
            subject: "01J0000000000000000000000A".to_owned(),
            exp: None,
            kid: Kid::Cur,
        });
        assert!(token.starts_with("eyJ"), "test premise: {token}");

        let scrubbed = scrub_text(&format!("confirm token {token} was rejected"));
        assert!(!scrubbed.contains(&token), "{scrubbed}");
        assert!(!scrubbed.contains("eyJ"), "{scrubbed}");
        assert!(scrubbed.contains(REDACTED), "{scrubbed}");
        assert!(
            scrubbed.contains("confirm token") && scrubbed.contains("was rejected"),
            "surrounding words survive: {scrubbed}"
        );

        // Inside a URL the query rule already dropped it; no `eyJ` survives
        // either way.
        let in_url = scrub_text(&format!("https://x.example/confirm?token={token}"));
        assert!(!in_url.contains("eyJ"), "{in_url}");

        // A JWT-shaped three-segment token is caught too.
        let jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIwMUoifQ.c2lnbmF0dXJlLXJ1bg";
        assert!(!scrub_text(jwt).contains("eyJ"));

        // Short dotted runs that merely start with eyJ are left alone.
        assert_eq!(scrub_text("eyJhYi.短"), "eyJhYi.短");
    }

    #[test]
    fn scrub_text_redacts_bearer_credentials() {
        let scrubbed = scrub_text("request carried Authorization: Bearer 01Jsupersecretvalue");
        assert!(!scrubbed.contains("01Jsupersecretvalue"), "{scrubbed}");
        assert!(scrubbed.contains("Bearer [redacted]"), "{scrubbed}");
    }

    #[test]
    fn scrub_text_leaves_ordinary_log_values_alone() {
        for value in [
            "sent",
            "not_configured",
            "01J8Z4QWERTYUIOPASDFGH",
            "/v1/email-signup/confirm",
            "factory0.ventures",
            "cratefield-core@0.1.0",
            "database did not answer within 2 s",
            "[redacted]",
        ] {
            assert_eq!(scrub_text(value), value, "{value}");
        }
    }

    #[test]
    fn scrub_text_is_idempotent() {
        let nasty = "failed for nick@example.com with Bearer abcdefgh12345 at \
             https://x.example/v1/confirm?token=eyJ and postgres://u:p@h/db";
        let once = scrub_text(nasty);
        assert_eq!(scrub_text(&once), once, "{once}");
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
/// any; a no-op when none is installed (native, tests). The line is a
/// pre-formatted string, so the structured-field rules ([`redacted_value`])
/// never see it; it passes [`scrub_text`] here instead (issue #135), which
/// is idempotent for callers that already scrubbed what they formatted in.
pub(crate) fn forward_internal_error(line: &str) {
    if let Some(forwarder) = ERROR_FORWARDER.get() {
        forwarder(&scrub_text(line));
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

        // The forwarded line is a pre-formatted string the structured-field
        // rules never see, so the forwarder itself scrubs it (issue #135):
        // a driver DETAIL quoting a row, or a redirect target with a token,
        // must not reach Workers Logs verbatim.
        forward_internal_error(
            "database error: DETAIL: Key (email)=(nick@example.com) already exists",
        );
        forward_internal_error("redirect to /v1/waitlist/status?token=eyJhYmNkZWZnaA.mac failed");
        let captured = CAPTURED.lock().unwrap();
        let joined = captured.join("\n");
        assert!(!joined.contains('@'), "email reached the sink: {joined}");
        assert!(
            !joined.contains("token=eyJ"),
            "token reached the sink: {joined}"
        );
        assert!(
            joined.contains("[subject_hash:"),
            "the pseudonym should survive for correlation: {joined}"
        );
    }

    #[test]
    fn forwarding_without_a_sink_is_a_noop() {
        // No panic, no output when nothing is installed (native, tests that do
        // not opt in). This asserts the call is safe regardless of ordering.
        forward_internal_error("ignored when no sink or captured when set");
    }
}
