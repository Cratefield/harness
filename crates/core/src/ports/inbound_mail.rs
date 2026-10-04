//! Inbound mail (issue #563): a venture receives messages, not only sends
//! them. The mirror of the outbound [`Mailer`](crate::Mailer) port and the
//! sibling of tracker's [`StatusWebhook`](crate::StatusWebhook) — inbound,
//! so a verify-then-parse trait rather than a `Port` variant (ADR 0028).
//!
//! Verification is core's [`WebhookVerifier`] over the raw body and a
//! per-provider [`SignatureScheme`](crate::SignatureScheme), never
//! re-derived by an adapter; a redelivery is claimed once through the
//! [`Inbox`](crate::Inbox) dedup ledger, keyed on the provider's message id
//! ([`InboundMessage::event_key`]).

use http::HeaderMap;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::webhook_signature::WebhookVerifier;

/// One inbound message, read out of a verified provider delivery.
///
/// **Metadata first.** Whether a delivery carries the body depends on the
/// vendor. A source whose webhook is metadata-only leaves
/// [`text`](Self::text) and [`html`](Self::html) `None` rather than
/// fetching the body behind the caller's back — the fetch is its own step.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InboundMessage {
    /// The provider's own id for the message: the dedup key, so
    /// [`event_key`](Self::event_key) claims a redelivery once.
    pub id: String,
    /// The sender address as the provider spells it: some vendors send a
    /// bare address, others a display name too (`Name <user@example.com>`).
    pub from: String,
    /// The envelope recipients.
    pub to: Vec<String>,
    /// The `Cc` recipients the payload names, if any.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub cc: Vec<String>,
    /// The subject line.
    pub subject: String,
    /// The plain-text body, when the delivery carries it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub text: Option<String>,
    /// The HTML body, when the delivery carries it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub html: Option<String>,
    /// Extra headers the vendor hands over (`Message-ID`, `In-Reply-To`),
    /// in order. Empty when the delivery names none.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub headers: Vec<(String, String)>,
    /// When the provider says it received the message, Unix seconds.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub received_at: Option<i64>,
}

impl InboundMessage {
    /// The [`Inbox`](crate::Inbox) key for this message, so a redelivery
    /// applies its effect once: `inbound-mail:<provider id>`.
    #[must_use]
    pub fn event_key(&self) -> String {
        format!("inbound-mail:{}", self.id)
    }
}

/// A vendor's inbound-mail webhook, implemented per vendor by adapter
/// crates: how to verify a delivery's signature and how to read a message
/// out of the verified body. The inbound sibling of
/// [`StatusWebhook`](crate::StatusWebhook) and the mirror of
/// [`Mailer`](crate::Mailer) — it hands a parsed [`InboundMessage`] to a
/// module, where `Mailer` takes one from it.
///
/// Verification is **not** reimplemented here: [`verifier`](Self::verifier)
/// returns core's [`WebhookVerifier`], so constant-time compare, fail-closed
/// on unreadable input and the replay tolerance are inherited, never
/// re-derived. Resend signs with Svix ([`Svix`](crate::Svix)); a provider
/// whose delivery carries no HMAC — Postmark's shared token — is a
/// follow-up (ADR 0028).
pub trait InboundMailSource: Send + Sync {
    /// The vendor this source speaks for, for logs and metrics.
    fn kind(&self) -> &'static str;

    /// The verifier deliveries must pass before [`parse`](Self::parse) is
    /// ever reached. Returned per call so an adapter may hold its config
    /// without holding a verifier — the secret is a parameter of
    /// [`receive_mail`], never of the source.
    fn verifier(&self) -> WebhookVerifier;

    /// Reads one **verified** body. `Ok(None)` for a verified event that is
    /// not an inbound message (a delivery receipt, a ping).
    ///
    /// # Errors
    ///
    /// [`InboundMailError::Malformed`] when the verified body is not an
    /// event this vendor sends. Never [`InboundMailError::Signature`] —
    /// that answer belongs to [`receive_mail`], before bytes are parsed.
    fn parse(&self, body: &[u8]) -> Result<Option<InboundMessage>, InboundMailError>;
}

/// An inbound-mail failure. `Signature` carries no provider text —
/// [`WebhookVerifier::verify`] answers a boolean, fail closed with no
/// detail to leak — and `Malformed` scrubs the adapter's own description
/// in `Display`, because a payload can quote the message and its sender.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum InboundMailError {
    /// The delivery's signature did not verify (or could not be read). The
    /// body is never parsed, and the caller should answer `4xx` without
    /// saying which part failed.
    #[error("inbound mail signature verification failed")]
    Signature,
    /// The delivery verified, but its body is not an event this vendor
    /// sends. `Display` scrubs the text — a payload can quote a message.
    #[error("inbound mail body is malformed: {scrubbed}", scrubbed = crate::logging::scrub_text(.0))]
    Malformed(String),
}

/// Verifies a webhook delivery against `source`'s verifier, and only then
/// parses it: `parse` never sees unverified bytes. The parameters are
/// [`WebhookVerifier::verify`]'s — the endpoint's `secret`, the request's
/// `headers`, the **raw** `body` bytes and `now_unix` for the replay
/// tolerance.
///
/// # Errors
///
/// [`InboundMailError::Signature`] when the delivery does not verify;
/// [`InboundMailError::Malformed`] when it verifies but
/// [`InboundMailSource::parse`] cannot read a message out of it.
/// `Ok(None)` is a verified event that is not an inbound message.
pub fn receive_mail(
    source: &dyn InboundMailSource,
    secret: &str,
    headers: &HeaderMap,
    body: &[u8],
    now_unix: i64,
) -> Result<Option<InboundMessage>, InboundMailError> {
    if !source.verifier().verify(secret, headers, body, now_unix) {
        return Err(InboundMailError::Signature);
    }
    source.parse(body)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::webhook_signature::{ProviderScheme, SignatureEncoding};
    use http::HeaderValue;
    use std::sync::atomic::{AtomicBool, Ordering};

    const SECRET: &str = "right-secret";
    const NOW: i64 = 1_800_000_000;
    const BODY: &[u8] = b"message";

    /// A source recording whether `parse` ran, so a refused delivery can
    /// prove it did not.
    #[derive(Default)]
    struct Source {
        parsed: AtomicBool,
    }

    impl InboundMailSource for Source {
        fn kind(&self) -> &'static str {
            "test"
        }

        fn verifier(&self) -> WebhookVerifier {
            WebhookVerifier::new(ProviderScheme {
                signature: "X-Signature",
                encoding: SignatureEncoding::Hex,
                prefix: None,
                timestamp: None,
            })
        }

        fn parse(&self, body: &[u8]) -> Result<Option<InboundMessage>, InboundMailError> {
            self.parsed.store(true, Ordering::Relaxed);
            match body {
                // A verified event that is not a message.
                b"none" => Ok(None),
                b"malformed" => Err(InboundMailError::Malformed("not a message".to_owned())),
                _ => Ok(Some(InboundMessage {
                    id: "msg_1".to_owned(),
                    from: "a@example.test".to_owned(),
                    to: vec!["b@example.test".to_owned()],
                    cc: Vec::new(),
                    subject: "hi".to_owned(),
                    text: None,
                    html: None,
                    headers: Vec::new(),
                    received_at: None,
                })),
            }
        }
    }

    /// The bare hex HMAC the verifier reads, signed a second time here,
    /// never through core's own extraction.
    fn sig_headers(body: &[u8]) -> HeaderMap {
        use hmac::{Hmac, KeyInit, Mac};
        use sha2::Sha256;
        use std::fmt::Write as _;

        let mut mac =
            <Hmac<Sha256> as KeyInit>::new_from_slice(SECRET.as_bytes()).expect("any key length");
        mac.update(body);
        let hex = mac
            .finalize()
            .into_bytes()
            .iter()
            .fold(String::new(), |mut out, byte| {
                let _ = write!(out, "{byte:02x}");
                out
            });
        let mut headers = HeaderMap::new();
        headers.insert("X-Signature", HeaderValue::from_str(&hex).expect("hex"));
        headers
    }

    #[test]
    fn receive_mail_refuses_a_bad_signature_without_parsing() {
        let hook = Source::default();
        let signed = sig_headers(BODY);
        // A wrong secret, a tampered body, an unreadable header map and an
        // empty secret — all `Signature`, and `parse` never ran on any.
        for (secret, headers, body) in [
            ("wrong-secret", &signed, BODY),
            (SECRET, &signed, b"{}" as &[u8]),
            (SECRET, &HeaderMap::new(), BODY),
            ("", &signed, BODY),
        ] {
            assert_eq!(
                receive_mail(&hook, secret, headers, body, NOW).unwrap_err(),
                InboundMailError::Signature
            );
        }
        assert!(!hook.parsed.load(Ordering::Relaxed));
    }

    #[test]
    fn receive_mail_parses_a_verified_message() {
        let signed = sig_headers(BODY);
        let message = receive_mail(&Source::default(), SECRET, &signed, BODY, NOW)
            .expect("the signature verifies")
            .expect("an inbound message");
        assert_eq!(message.id, "msg_1");
        assert_eq!(message.from, "a@example.test");
        assert_eq!(message.to, vec!["b@example.test".to_owned()]);
        assert_eq!(message.subject, "hi");
        assert_eq!(message.event_key(), "inbound-mail:msg_1");
        // A verified delivery that is not a message is `Ok(None)`.
        let signed = sig_headers(b"none");
        assert_eq!(
            receive_mail(&Source::default(), SECRET, &signed, b"none", NOW).expect("verifies"),
            None
        );
    }

    #[test]
    fn a_verified_body_that_does_not_parse_is_malformed() {
        let body = b"malformed";
        let signed = sig_headers(body);
        assert!(matches!(
            receive_mail(&Source::default(), SECRET, &signed, body, NOW),
            Err(InboundMailError::Malformed(_))
        ));
        // `Malformed`'s `Display` scrubs the text — a payload can quote a
        // message and its sender.
        let printed =
            InboundMailError::Malformed("leaked https://x.test/a?t=secret".to_owned()).to_string();
        assert!(!printed.contains("secret"), "{printed}");
    }
}
