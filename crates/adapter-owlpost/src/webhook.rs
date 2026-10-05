//! Owlpost's inbound webhooks: verify the delivery, then parse it (issue
//! #668). The inbound sibling of [`Owlpost`](crate::Owlpost), which sends.
//!
//! **Verify first, parse second — always.** [`parse_verified`] runs the
//! signature check over the **raw body bytes** before any JSON is read, and
//! returns [`WebhookError::Signature`] without touching them when it fails.
//! Parsing first and verifying after is the vulnerability this shape exists
//! to prevent. Owlpost signs Stripe-style (`t=<unix>,v1=<hex HMAC-SHA256 of
//! "{t}.{body}">`), so this is core's [`WebhookVerifier`] rather than a
//! hand-rolled HMAC; the tolerance is core's default ±300 s, widened with
//! `verifier().tolerance_secs(n)` — which is why [`parse_verified`] takes the
//! verifier.
//!
//! **Deduplicate on [`Envelope::id`], not on [`event_id`].** The signature
//! covers `{t}.{body}` only, so [`EVENT_ID_HEADER`] is *unauthenticated*: a
//! captured delivery replayed with a fresh id header still verifies, and
//! would slip past a dedup ledger keyed on the header. The id inside the
//! signed body is the only id an attacker cannot mint, so it is the dedup
//! key ([`Inbox`](cratefield_core::Inbox)). [`event_id`] is for correlation
//! and logging — reading it before verification, for instance — and nothing
//! else.
//!
//! ```
//! use cratefield_adapter_owlpost::webhook::{parse_verified, verifier};
//! use http::HeaderMap;
//!
//! let body = br#"{"id":"evt_1","type":"email.delivered","created_at":"2026-01-01T00:00:00Z",
//!                "data":{"message_id":"msg_1","to":["a@example.com"]}}"#;
//! let mut headers = HeaderMap::new();
//! // A zero digest is not a real MAC, so this refuses `Signature` — which is
//! // the point: the body is never parsed on a failed check.
//! headers.insert(
//!     "cratefield-signature",
//!     "t=1767225600,v1=0000000000000000000000000000000000000000000000000000000000000000"
//!         .parse()
//!         .unwrap(),
//! );
//! assert!(parse_verified(&verifier(), "whsec_example", &headers, body, 1_767_225_600).is_err());
//! ```

use std::fmt;

use cratefield_core::{StripeStyle, WebhookVerifier};
use http::HeaderMap;
use serde::Deserialize;

/// The header carrying Owlpost's signature: `t=<unix>,v1=<hex>`.
pub const SIGNATURE_HEADER: &str = "Cratefield-Signature";

/// The header carrying the delivery's event id.
///
/// **Unauthenticated and not a dedup key.** The signature covers
/// `{t}.{body}`, not the headers, so a replayed delivery with a rewritten
/// id header still verifies. Deduplicate on [`Envelope::id`] — from the
/// signed body — and use this for correlation and logging only.
pub const EVENT_ID_HEADER: &str = "Cratefield-Event-Id";

/// Owlpost's webhook verifier: [`StripeStyle`] reading [`SIGNATURE_HEADER`].
#[must_use]
pub fn verifier() -> WebhookVerifier {
    WebhookVerifier::new(StripeStyle {
        header: SIGNATURE_HEADER,
    })
}

/// The delivery's event id from [`EVENT_ID_HEADER`]; `None` when absent,
/// empty or not UTF-8.
///
/// **Unauthenticated.** Stripe-style verification signs `{t}.{body}` and
/// ignores the headers, so this id is attacker-controlled on any delivery
/// that verifies. Fine for correlation and logging — reading it before
/// verification, for instance. **Not** a dedup key: use [`Envelope::id`],
/// which arrives inside the signed body, with an [`Inbox`](cratefield_core::Inbox).
#[must_use]
pub fn event_id(headers: &HeaderMap) -> Option<&str> {
    let value = headers.get(EVENT_ID_HEADER)?.to_str().ok()?;
    if value.is_empty() { None } else { Some(value) }
}

/// Why a delivery was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum WebhookError {
    /// The signature did not verify: wrong secret, tampered body, a
    /// timestamp outside the tolerance, or none at all. The body was not
    /// parsed, so this says nothing about its content.
    Signature,
    /// The body verified but is not a well-formed envelope, or is a known
    /// type whose `data` does not fit its struct. Carries the serde message
    /// only — never the body, never the secret.
    Malformed(String),
}

impl fmt::Display for WebhookError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Signature => f.write_str("owlpost webhook signature did not verify"),
            Self::Malformed(detail) => write!(f, "malformed owlpost webhook body: {detail}"),
        }
    }
}

impl std::error::Error for WebhookError {}

/// One verified delivery: the envelope's own fields, plus the parsed `data`.
/// Field names mirror the wire (`type` is read as [`Envelope::event_type`]).
#[derive(Debug, Clone, PartialEq)]
pub struct Envelope {
    /// The delivery's id, from the signed body — the `Inbox` dedup key.
    pub id: String,
    /// The event type verbatim, including one this crate does not know.
    pub event_type: String,
    /// RFC 3339 exactly as sent.
    pub created_at: String,
    /// The parsed `data`.
    pub data: OwlpostEvent,
}

/// Verifies `body` against `headers`, then parses it. `now_unix` is the
/// current Unix time the replay tolerance runs on.
///
/// # Errors
///
/// [`WebhookError::Signature`] if verification fails — returned before the
/// body is read, so an unverified delivery is never parsed. Otherwise
/// [`WebhookError::Malformed`] if the verified body is not a well-formed
/// envelope, or is a known type whose `data` does not fit its struct.
pub fn parse_verified(
    verifier: &WebhookVerifier,
    secret: &str,
    headers: &HeaderMap,
    body: &[u8],
    now_unix: i64,
) -> Result<Envelope, WebhookError> {
    if !verifier.verify(secret, headers, body, now_unix) {
        return Err(WebhookError::Signature);
    }
    let raw: RawEnvelope =
        serde_json::from_slice(body).map_err(|error| WebhookError::Malformed(error.to_string()))?;
    let data = match raw.event_type.as_str() {
        "email.sent" => OwlpostEvent::EmailSent(decode(raw.data)?),
        "email.delivered" => OwlpostEvent::EmailDelivered(decode(raw.data)?),
        "email.delivery_delayed" => OwlpostEvent::EmailDeliveryDelayed(decode(raw.data)?),
        "email.bounced" => OwlpostEvent::EmailBounced(decode(raw.data)?),
        "email.soft_bounced" => OwlpostEvent::EmailSoftBounced(decode(raw.data)?),
        "email.complained" => OwlpostEvent::EmailComplained(decode(raw.data)?),
        "email.unsubscribed" => OwlpostEvent::EmailUnsubscribed(decode(raw.data)?),
        "email.rejected" => OwlpostEvent::EmailRejected(decode(raw.data)?),
        "email.opened" => OwlpostEvent::EmailOpened(decode(raw.data)?),
        "email.clicked" => OwlpostEvent::EmailClicked(decode(raw.data)?),
        "email.failed" => OwlpostEvent::EmailFailed(decode(raw.data)?),
        "message.received" => OwlpostEvent::MessageReceived(decode(raw.data)?),
        "message.held" => OwlpostEvent::MessageHeld(decode(raw.data)?),
        // A type this crate does not know is not an error: Owlpost may add
        // one, and a handler can log and ignore it. The id still reaches
        // the dedup ledger.
        other => OwlpostEvent::Unknown(other.to_owned()),
    };
    Ok(Envelope {
        id: raw.id,
        event_type: raw.event_type,
        created_at: raw.created_at,
        data,
    })
}

/// A delivery as it arrives: `data` kept unparsed, since which struct it
/// deserializes into depends on `type`.
#[derive(Deserialize)]
struct RawEnvelope {
    id: String,
    #[serde(rename = "type")]
    event_type: String,
    created_at: String,
    data: serde_json::Value,
}

/// Deserializes a verified `data` into its event's struct. Nothing about the
/// body or the secret is included in the error.
fn decode<T: serde::de::DeserializeOwned>(data: serde_json::Value) -> Result<T, WebhookError> {
    serde_json::from_value(data).map_err(|error| WebhookError::Malformed(error.to_string()))
}

/// Every event type Owlpost sends, plus [`OwlpostEvent::Unknown`] for one it
/// adds later. The data structs are `#[non_exhaustive]` and lenient — unknown
/// fields and absent optional ones are accepted — so a provider addition does
/// not break parsing.
#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
pub enum OwlpostEvent {
    /// `email.sent` — accepted by the provider.
    EmailSent(EmailData),
    /// `email.delivered` — handed to the recipient's server.
    EmailDelivered(EmailData),
    /// `email.delivery_delayed` — held back for retry.
    EmailDeliveryDelayed(EmailIssueData),
    /// `email.bounced` — hard bounce; the address is not deliverable.
    EmailBounced(BounceData),
    /// `email.soft_bounced` — temporary failure, retried.
    EmailSoftBounced(BounceData),
    /// `email.complained` — the recipient marked it as spam.
    EmailComplained(EmailData),
    /// `email.unsubscribed` — the recipient opted out.
    EmailUnsubscribed(EmailData),
    /// `email.rejected` — refused before delivery (policy, blocklist).
    EmailRejected(EmailIssueData),
    /// `email.opened` — a tracking pixel was fetched.
    EmailOpened(OpenData),
    /// `email.clicked` — a tracked link was followed.
    EmailClicked(ClickData),
    /// `email.failed` — the provider gave up on it.
    EmailFailed(EmailIssueData),
    /// `message.received` — inbound mail at a receiving address. Metadata
    /// only; fetching the body is the caller's call.
    MessageReceived(InboundData),
    /// `message.held` — inbound mail quarantined for review.
    MessageHeld(HeldData),
    /// A type this crate does not know, carried verbatim.
    Unknown(String),
}

impl OwlpostEvent {
    /// The wire name of this event's type, e.g. `"email.delivered"`; also
    /// the string [`OwlpostEvent::Unknown`] holds.
    #[must_use]
    pub fn event_type(&self) -> &str {
        match self {
            Self::EmailSent(_) => "email.sent",
            Self::EmailDelivered(_) => "email.delivered",
            Self::EmailDeliveryDelayed(_) => "email.delivery_delayed",
            Self::EmailBounced(_) => "email.bounced",
            Self::EmailSoftBounced(_) => "email.soft_bounced",
            Self::EmailComplained(_) => "email.complained",
            Self::EmailUnsubscribed(_) => "email.unsubscribed",
            Self::EmailRejected(_) => "email.rejected",
            Self::EmailOpened(_) => "email.opened",
            Self::EmailClicked(_) => "email.clicked",
            Self::EmailFailed(_) => "email.failed",
            Self::MessageReceived(_) => "message.received",
            Self::MessageHeld(_) => "message.held",
            Self::Unknown(other) => other,
        }
    }
}

/// `data` of `email.sent`, `email.delivered`, `email.complained` and
/// `email.unsubscribed`.
#[derive(Debug, Clone, PartialEq, Deserialize)]
#[non_exhaustive]
pub struct EmailData {
    /// Owlpost's message id — the join key back to a send.
    pub message_id: String,
    /// Recipients; an array even for one address.
    #[serde(default)]
    pub to: Vec<String>,
    #[serde(default)]
    pub from: Option<String>,
    #[serde(default)]
    pub subject: Option<String>,
}

/// `data` of `email.delivery_delayed`, `email.rejected`, `email.failed`.
#[derive(Debug, Clone, PartialEq, Deserialize)]
#[non_exhaustive]
pub struct EmailIssueData {
    pub message_id: String,
    #[serde(default)]
    pub to: Vec<String>,
    /// The provider's wording for the delay, rejection or failure.
    #[serde(default)]
    pub reason: Option<String>,
}

/// `data` of `email.bounced` and `email.soft_bounced`.
#[derive(Debug, Clone, PartialEq, Deserialize)]
#[non_exhaustive]
pub struct BounceData {
    pub message_id: String,
    #[serde(default)]
    pub to: Vec<String>,
    /// `"hard"` or `"soft"`, when the payload says which.
    #[serde(default)]
    pub bounce_type: Option<String>,
    /// The SMTP code the recipient's server answered with, e.g. `"550"`.
    #[serde(default)]
    pub code: Option<String>,
    #[serde(default)]
    pub description: Option<String>,
}

/// `data` of `email.opened`.
#[derive(Debug, Clone, PartialEq, Deserialize)]
#[non_exhaustive]
pub struct OpenData {
    pub message_id: String,
    #[serde(default)]
    pub user_agent: Option<String>,
    #[serde(default)]
    pub ip: Option<String>,
}

/// `data` of `email.clicked`.
#[derive(Debug, Clone, PartialEq, Deserialize)]
#[non_exhaustive]
pub struct ClickData {
    pub message_id: String,
    /// Where the click landed.
    pub url: String,
    #[serde(default)]
    pub user_agent: Option<String>,
    #[serde(default)]
    pub ip: Option<String>,
}

/// `data` of `message.received` — inbound mail metadata.
#[derive(Debug, Clone, PartialEq, Deserialize)]
#[non_exhaustive]
pub struct InboundData {
    pub message_id: String,
    pub from: String,
    #[serde(default)]
    pub to: Vec<String>,
    #[serde(default)]
    pub subject: Option<String>,
}

/// `data` of `message.held`.
#[derive(Debug, Clone, PartialEq, Deserialize)]
#[non_exhaustive]
pub struct HeldData {
    pub message_id: String,
    /// Why it was held (spam score, blocklist, policy), when given.
    #[serde(default)]
    pub reason: Option<String>,
}
