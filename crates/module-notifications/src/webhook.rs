//! Svix delivery verification, for the provider bounce webhook (#233).
//!
//! Resend signs its webhooks with Svix, whose scheme is an HMAC-SHA256
//! over `{id}.{timestamp}.{body}` keyed by the endpoint secret, sent
//! base64 in `svix-signature` as a space-separated list of
//! `<version>,<signature>` pairs. The list is why an endpoint survives a
//! secret rotation: for a while the provider signs with both, and one
//! match is enough.
//!
//! Verification is over the **raw body bytes**, so the handler must read
//! the body before anything parses it. Re-serialising the parsed JSON and
//! signing that would verify a different byte string than the one the
//! provider signed, and would start failing the day the provider changed
//! its key order or its spacing.
//!
//! Nothing here is Resend-specific: the scheme is Svix's, and what the
//! payload means is the handler's business.

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;
use subtle::ConstantTimeEq;

type HmacSha256 = Hmac<Sha256>;

/// How far a delivery's timestamp may be from now, in seconds.
///
/// Svix's own tolerance. It is what stops a delivery captured off the
/// wire being replayed indefinitely: the signature stays valid forever,
/// the timestamp does not.
pub(crate) const TOLERANCE_SECS: i64 = 300;

/// The prefix an endpoint secret is presented with. Svix writes the
/// secret as `whsec_<base64>`; the base64 alone is also accepted, because
/// operators paste both.
const SECRET_PREFIX: &str = "whsec_";

/// The only signature version this understands.
const VERSION: &str = "v1";

/// One delivery's signature material, as the three headers carry it.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Delivery<'a> {
    /// `svix-id` — the message id, part of the signed string.
    pub id: &'a str,
    /// `svix-timestamp` — Unix seconds, part of the signed string and
    /// checked against [`TOLERANCE_SECS`].
    pub timestamp: &'a str,
    /// `svix-signature` — space-separated `<version>,<base64>` pairs.
    pub signatures: &'a str,
}

/// Whether `body` really was signed for this delivery with `secret`.
///
/// Fails closed on every unreadable input — an undecodable secret, a
/// timestamp that is not a number, a signature list with nothing this
/// understands in it. There is no arm here that returns "probably".
pub(crate) fn is_signed(secret: &str, delivery: &Delivery<'_>, body: &[u8], now_unix: i64) -> bool {
    if !within_tolerance(delivery.timestamp, now_unix) {
        return false;
    }
    let Some(key) = decode_secret(secret) else {
        return false;
    };
    let expected = mac(&key, delivery.id, delivery.timestamp, body);
    // No early exit: every candidate is compared, and the results are
    // OR-ed, so how long this takes says nothing about how much of a
    // wrong signature was right.
    let mut matched = false;
    for candidate in delivery.signatures.split_whitespace() {
        let Some((version, value)) = candidate.split_once(',') else {
            continue;
        };
        if version != VERSION {
            continue;
        }
        let Ok(bytes) = STANDARD.decode(value) else {
            continue;
        };
        matched |= bool::from(bytes.ct_eq(&expected));
    }
    matched
}

/// Whether the delivery's timestamp is close enough to now.
fn within_tolerance(timestamp: &str, now_unix: i64) -> bool {
    let Ok(sent) = timestamp.trim().parse::<i64>() else {
        return false;
    };
    now_unix.saturating_sub(sent).abs() <= TOLERANCE_SECS
}

/// The endpoint secret's key bytes: base64, with or without the
/// `whsec_` Svix writes it with. `None` when it does not decode, which
/// is a misconfiguration and must refuse rather than verify against
/// something else.
fn decode_secret(secret: &str) -> Option<Vec<u8>> {
    let trimmed = secret.trim();
    let encoded = trimmed.strip_prefix(SECRET_PREFIX).unwrap_or(trimmed);
    STANDARD.decode(encoded).ok().filter(|key| !key.is_empty())
}

/// `HMAC-SHA256(key, "{id}.{timestamp}.{body}")`.
fn mac(key: &[u8], id: &str, timestamp: &str, body: &[u8]) -> Vec<u8> {
    let mut mac =
        <HmacSha256 as KeyInit>::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(id.as_bytes());
    mac.update(b".");
    mac.update(timestamp.as_bytes());
    mac.update(b".");
    mac.update(body);
    mac.finalize().into_bytes().to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;

    const SECRET: &str = "whsec_MfKQ9r8GKYqrTwjUPD8ILPZIo2LaLaSw";
    const ID: &str = "msg_p5jXN8AQM9LWM0D4loKWxJek";
    const NOW: i64 = 1_800_000_000;

    /// The header a provider would send for this body at this time.
    fn sign(secret: &str, id: &str, timestamp: i64, body: &[u8]) -> String {
        let key = decode_secret(secret).expect("the fixture secret decodes");
        let digest = mac(&key, id, &timestamp.to_string(), body);
        format!("v1,{}", STANDARD.encode(digest))
    }

    fn delivery<'a>(timestamp: &'a str, signatures: &'a str) -> Delivery<'a> {
        Delivery {
            id: ID,
            timestamp,
            signatures,
        }
    }

    #[test]
    fn a_delivery_signed_with_the_endpoint_secret_verifies() {
        let body = br#"{"type":"email.bounced"}"#;
        let header = sign(SECRET, ID, NOW, body);
        assert!(is_signed(
            SECRET,
            &delivery("1800000000", &header),
            body,
            NOW
        ));
    }

    #[test]
    fn the_secret_verifies_with_or_without_the_whsec_prefix() {
        let body = b"{}";
        let header = sign(SECRET, ID, NOW, body);
        let bare = SECRET.strip_prefix(SECRET_PREFIX).expect("prefixed");
        assert!(is_signed(bare, &delivery("1800000000", &header), body, NOW));
    }

    #[test]
    fn a_body_changed_after_signing_does_not_verify() {
        let body = br#"{"type":"email.bounced"}"#;
        let header = sign(SECRET, ID, NOW, body);
        let tampered = br#"{"type":"email.complained"}"#;
        assert!(!is_signed(
            SECRET,
            &delivery("1800000000", &header),
            tampered,
            NOW
        ));
    }

    #[test]
    fn another_secret_does_not_verify() {
        let body = b"{}";
        let header = sign("whsec_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", ID, NOW, body);
        assert!(!is_signed(
            SECRET,
            &delivery("1800000000", &header),
            body,
            NOW
        ));
    }

    #[test]
    fn the_id_is_part_of_what_is_signed() {
        let body = b"{}";
        let header = sign(SECRET, "msg_another", NOW, body);
        assert!(!is_signed(
            SECRET,
            &delivery("1800000000", &header),
            body,
            NOW
        ));
    }

    #[test]
    fn one_matching_signature_among_several_is_enough() {
        // What a secret rotation looks like on the wire: the provider
        // signs with both endpoints' secrets for the overlap.
        let body = b"{}";
        let old = sign("whsec_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", ID, NOW, body);
        let new = sign(SECRET, ID, NOW, body);
        let both = format!("{old} {new}");
        assert!(is_signed(SECRET, &delivery("1800000000", &both), body, NOW));
    }

    #[test]
    fn a_signature_of_an_unknown_version_is_not_read() {
        let body = b"{}";
        let header = sign(SECRET, ID, NOW, body).replace("v1,", "v0,");
        assert!(!is_signed(
            SECRET,
            &delivery("1800000000", &header),
            body,
            NOW
        ));
    }

    #[test]
    fn a_replay_outside_the_tolerance_is_refused() {
        let body = b"{}";
        let sent = NOW - TOLERANCE_SECS - 1;
        let header = sign(SECRET, ID, sent, body);
        // The signature itself is still perfectly valid — the timestamp
        // is the only thing that stops it being replayed forever.
        assert!(is_signed(
            SECRET,
            &delivery(&sent.to_string(), &header),
            body,
            sent
        ));
        assert!(!is_signed(
            SECRET,
            &delivery(&sent.to_string(), &header),
            body,
            NOW
        ));
    }

    #[test]
    fn a_timestamp_far_in_the_future_is_refused_too() {
        let body = b"{}";
        let sent = NOW + TOLERANCE_SECS + 1;
        let header = sign(SECRET, ID, sent, body);
        assert!(!is_signed(
            SECRET,
            &delivery(&sent.to_string(), &header),
            body,
            NOW
        ));
    }

    #[test]
    fn unreadable_input_refuses_rather_than_verifies() {
        let body = b"{}";
        let header = sign(SECRET, ID, NOW, body);
        // A timestamp that is not a number.
        assert!(!is_signed(
            SECRET,
            &delivery("recently", &header),
            body,
            NOW
        ));
        // A signature list with no pair in it at all.
        assert!(!is_signed(
            SECRET,
            &delivery("1800000000", "garbage"),
            body,
            NOW
        ));
        // A secret that is not base64: a misconfigured endpoint verifies
        // nothing rather than falling back to the raw bytes.
        assert!(!is_signed(
            "whsec_!!!!",
            &delivery("1800000000", &header),
            body,
            NOW
        ));
        // An empty secret is not a key.
        assert!(!is_signed("", &delivery("1800000000", &header), body, NOW));
    }
}
