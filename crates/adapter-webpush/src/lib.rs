//! `cratefield-adapter-webpush`: the [`Push`] port over Web Push
//! (issue #180) — [RFC 8030] delivery, [RFC 8188]/[RFC 8291] `aes128gcm`
//! payload encryption, [RFC 8292] VAPID authentication. Uses the runtime's
//! [`HttpClient`] and [`Clock`] ports — no vendor SDK, no `reqwest`, no
//! OpenSSL — so the same adapter runs on Workers (`worker::Fetch`) and
//! natively.
//!
//! **One adapter, two audiences.** A browser subscription and a
//! UnifiedPush endpoint are the *same protocol*: a UnifiedPush distributor
//! (ntfy, `NextPush`, Sunup) hands the app an endpoint that accepts exactly
//! the RFC 8030 request a browser push service accepts. So this adapter
//! serves Google-free Android as well as Chrome, Firefox, Edge and Safari,
//! and nothing in it knows which it is talking to (ADR 0015: the transport
//! is a fact about the recipient, not about the device).
//!
//! **Recipients.** It serves [`Recipient::WebPush`] and returns
//! [`PushError::unsupported_recipient`] for APNs and FCM. A venture with
//! more than one transport wires
//! [`RoutingPush`](cratefield_core::RoutingPush), which dispatches by
//! variant.
//!
//! **Encryption.** Every message gets a fresh P-256 key pair and a fresh
//! 16-byte salt, combined with the subscription's `p256dh` by ECDH and with
//! its `auth` secret by HKDF, then one AES-128-GCM record (module
//! [`ece`]). The push service sees ciphertext; only the browser that
//! created the subscription holds the private half. The RFC 8291 Appendix A
//! and RFC 8188 §3.1 vectors are reproduced byte for byte in that module's
//! tests, and `tests/rfc8291.rs` decrypts from the user agent's side so a
//! regression cannot pass by matching a vector alone.
//!
//! **Authentication.** VAPID (module [`vapid`]) is an ES256 JWT whose `aud`
//! is the push service's origin, signed by [`cratefield_push_auth`] and
//! cached per origin — the audience differs per vendor, so one cached token
//! would be wrong for all but one of them.
//!
//! **Degraded mode.** [`WebPush::not_configured`] reports
//! [`PushOutcome::NotConfigured`] without any network call, the same
//! contract the other adapters use, so a venture with no VAPID key still
//! builds and runs. It answers that only for the transport it serves: an
//! APNs or FCM recipient is still [`PushError::unsupported_recipient`],
//! configured or not.
//!
//! [RFC 8030]: https://www.rfc-editor.org/rfc/rfc8030
//! [RFC 8188]: https://www.rfc-editor.org/rfc/rfc8188
//! [RFC 8291]: https://www.rfc-editor.org/rfc/rfc8291
//! [RFC 8292]: https://www.rfc-editor.org/rfc/rfc8292
#![doc = include_str!("../README.md")]
#![forbid(unsafe_code)]

pub mod ece;
pub mod vapid;

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use bytes::Bytes;
use cratefield_core::{
    Clock, HttpClient, Notification, Priority, Push, PushError, PushOutcome, Recipient, ttl_secs,
};
use http::header::{AUTHORIZATION, CONTENT_ENCODING, CONTENT_TYPE, LOCATION, RETRY_AFTER};
use http::{HeaderMap, Request, StatusCode};
use serde_json::{Map, Value};
use sha2::{Digest as _, Sha256};
use time::OffsetDateTime;

use crate::ece::{Ece, EceError, SubscriptionKeys};
use crate::vapid::{Vapid, VapidError, VapidKeys};

/// How long a push service holds an undelivered notification when the caller
/// names no TTL.
///
/// RFC 8030 §5.2 makes the `TTL` header **mandatory** — there is no "unset"
/// on the wire — so an adapter has to choose. A day is the same default the
/// browser tooling uses, and it is the answer that loses nothing: a `0` TTL
/// (deliver only if the device is online now) is a deliberate instruction
/// and is passed through when a caller asks for it.
#[allow(clippy::duration_suboptimal_units)] // `from_hours` is not const-stable on 1.98
pub const DEFAULT_TTL: Duration = Duration::from_secs(24 * 3_600);

/// RFC 8030 §5.4: a `Topic` is 1–32 characters from the URL-safe base64
/// alphabet.
pub const MAX_TOPIC_LEN: usize = 32;

/// Building a [`WebPush`] adapter failed.
#[derive(Debug, thiserror::Error)]
pub enum WebPushConfigError {
    /// The VAPID key or subject was not usable.
    #[error(transparent)]
    Vapid(#[from] VapidError),
    /// The record size was outside RFC 8188's bounds.
    #[error(transparent)]
    Ece(#[from] EceError),
}

/// [`Push`] over `POST <subscription endpoint>`.
pub struct WebPush {
    inner: Inner,
}

enum Inner {
    Live(Box<Live>),
    NotConfigured,
}

struct Live {
    http: Arc<dyn HttpClient>,
    clock: Arc<dyn Clock>,
    vapid: Vapid,
    ece: Ece,
}

impl WebPush {
    /// Builds a live adapter, parsing the VAPID key up front so a malformed
    /// one is reported at construction rather than on the first send.
    ///
    /// [`VapidKeys`] carries the `VAPID_PRIVATE_KEY` (a PKCS#8 PEM or the
    /// bare 32-byte P-256 scalar base64url) and the `VAPID_SUBJECT` contact
    /// URI. The public key is derived, never configured, so the pair cannot
    /// drift.
    ///
    /// # Errors
    ///
    /// [`WebPushConfigError::Vapid`] if the key or the subject is not
    /// usable.
    pub fn new(
        http: Arc<dyn HttpClient>,
        clock: Arc<dyn Clock>,
        keys: VapidKeys,
    ) -> Result<Self, WebPushConfigError> {
        Self::with_record_size(http, clock, keys, ece::DEFAULT_RECORD_SIZE)
    }

    /// The same, with an explicit RFC 8188 record size.
    ///
    /// The default is derived so the whole body fits the 4096 octets a push
    /// service is required to accept ([`ece::DEFAULT_RECORD_SIZE`]); raising
    /// it is a deliberate bet that a venture's subscribers are all on
    /// services that accept more.
    ///
    /// # Errors
    ///
    /// [`WebPushConfigError::Vapid`] as [`WebPush::new`];
    /// [`WebPushConfigError::Ece`] if the record size is below RFC 8188's
    /// floor of 18.
    pub fn with_record_size(
        http: Arc<dyn HttpClient>,
        clock: Arc<dyn Clock>,
        keys: VapidKeys,
        record_size: u32,
    ) -> Result<Self, WebPushConfigError> {
        let vapid = Vapid::new(keys)?;
        let ece = Ece::new(record_size)?;
        Ok(Self {
            inner: Inner::Live(Box::new(Live {
                http,
                clock,
                vapid,
                ece,
            })),
        })
    }

    /// A degraded adapter that reports [`PushOutcome::NotConfigured`]
    /// without any network call — for a venture with no VAPID key set.
    #[must_use]
    pub fn not_configured() -> Self {
        Self {
            inner: Inner::NotConfigured,
        }
    }

    /// The `applicationServerKey` a browser must pass to
    /// `pushManager.subscribe()`, base64url — or `None` when the adapter is
    /// not configured. A venture serves this to its client.
    #[must_use]
    pub fn public_key(&self) -> Option<&str> {
        match &self.inner {
            Inner::Live(live) => Some(live.vapid.public_key()),
            Inner::NotConfigured => None,
        }
    }

    /// The largest JSON payload this adapter will send, in bytes — computed
    /// from the record size, see [`ece::max_plaintext`].
    #[must_use]
    pub fn max_payload(&self) -> Option<usize> {
        match &self.inner {
            Inner::Live(live) => Some(live.ece.max_plaintext()),
            Inner::NotConfigured => None,
        }
    }
}

impl std::fmt::Debug for WebPush {
    /// Prints whether it is configured and the public half of the VAPID key
    /// — never the private key, which `Es256Signer` already refuses to
    /// print, and never a recipient.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self.inner {
            Inner::Live(live) => f
                .debug_struct("WebPush")
                .field("vapid", &live.vapid)
                .field("record_size", &live.ece.record_size())
                .finish_non_exhaustive(),
            Inner::NotConfigured => f.write_str("WebPush::NotConfigured"),
        }
    }
}

/// The `Urgency` header (RFC 8030 §5.3) for a [`Priority`].
///
/// The header's four values are `very-low`, `low`, `normal` and `high`; the
/// port carries two, so two are used. `Immediate` is `high` (wake the device
/// now) and `Conserve` is `normal` — deliberately not `low`, which on a
/// battery-saving device can mean "hold this until the screen is on next",
/// and the port's `Conserve` only asks not to *wake* the device.
fn urgency_header(priority: Priority) -> &'static str {
    match priority {
        Priority::Immediate => "high",
        Priority::Conserve => "normal",
    }
}

/// The `TTL` header: whole seconds, mandatory, [`DEFAULT_TTL`] when the
/// caller named none.
///
/// A sub-second TTL rounds **up** to one second through
/// [`ttl_secs`](cratefield_core::ttl_secs) rather than truncating to `0`,
/// which would say the opposite thing — drop it unless the device is online
/// right now.
fn ttl_header(ttl: Option<Duration>) -> String {
    ttl_secs(ttl.unwrap_or(DEFAULT_TTL)).to_string()
}

/// The `Topic` header for a `collapse_id`.
///
/// RFC 8030 §5.4 allows at most 32 characters from the URL-safe base64
/// alphabet, which a caller's `collapse_id` need not respect — the same
/// field is `apns-collapse-id` (64 bytes, any octets) and
/// `android.collapse_key` (arbitrary) elsewhere. A value that does not fit
/// is replaced by the first 32 base64url characters of its SHA-256, which
/// keeps the one property a topic has to have: two notifications collapse
/// exactly when their `collapse_id`s are equal.
///
/// The hash is not reversible and the push service never needed to read the
/// value — a `Topic` is an opaque equality token, and RFC 8030 §5.4 warns
/// that it is visible to the push service, so hashing a topic that might
/// carry a user identifier is an improvement rather than a cost.
fn topic_header(collapse_id: &str) -> String {
    let fits = !collapse_id.is_empty()
        && collapse_id.len() <= MAX_TOPIC_LEN
        && collapse_id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_');
    if fits {
        return collapse_id.to_owned();
    }
    let digest = Sha256::digest(collapse_id.as_bytes());
    let mut encoded = URL_SAFE_NO_PAD.encode(digest);
    encoded.truncate(MAX_TOPIC_LEN);
    encoded
}

/// The JSON a service worker reads out of `event.data.json()`.
///
/// `Notification` is transport-neutral, so some fields are mapped and some
/// are dropped, deliberately:
///
/// - `badge` is **dropped**: the port's `badge` is the iOS app-icon *count*,
///   while the web `Notification.badge` is an icon *URL*. Putting a number
///   there would be silently wrong.
/// - `category` and `loc` are **dropped**: neither has a counterpart in the
///   web Notification API — there is no OS-side string catalogue to look a
///   loc key up in, so localisation on the web happens before this point.
/// - `collapse_id` is the `Topic` **header**, not a payload field.
/// - `data` is **nested** under `data` rather than merged at the top level
///   (as the APNs adapter does), because `showNotification` takes a `data`
///   member of its own and the service worker reads it there. Nesting also
///   means a caller's key can never collide with the adapter's.
fn build_payload(notification: &Notification) -> Vec<u8> {
    let mut root = Map::new();
    root.insert(
        "title".to_owned(),
        Value::String(notification.title.clone()),
    );
    root.insert("body".to_owned(), Value::String(notification.body.clone()));
    if let Some(icon) = &notification.icon {
        root.insert("icon".to_owned(), Value::String(icon.clone()));
    }
    if let Some(url) = &notification.url {
        root.insert("url".to_owned(), Value::String(url.clone()));
    }
    // `tag` is the web Notification API's name for what the port calls
    // `thread_id`: notifications sharing one replace each other in the
    // shade. (`Topic`, from `collapse_id`, is the same idea one layer down —
    // it collapses messages the *push service* has not delivered yet.)
    if let Some(thread_id) = &notification.thread_id {
        root.insert("tag".to_owned(), Value::String(thread_id.clone()));
    }
    root.insert("silent".to_owned(), Value::Bool(notification.silent));
    if !notification.data.is_null() {
        root.insert("data".to_owned(), notification.data.clone());
    }
    Value::Object(root).to_string().into_bytes()
}

/// `Retry-After` (RFC 9110 §10.2.3) as a duration, so the outbox can honour
/// it.
///
/// Both forms are read. The delta-seconds form is the common one; the
/// HTTP-date form is legal, is what some CDNs in front of a push service
/// emit, and silently ignoring it would turn a "come back in an hour" into
/// an immediate retry. The date is resolved against the [`Clock`] port —
/// the only clock this workspace may read — and a date already in the past
/// becomes [`Duration::ZERO`] ("retry now") rather than being discarded.
fn retry_after(headers: &HeaderMap, clock: &dyn Clock) -> Option<Duration> {
    let value = headers.get(RETRY_AFTER)?.to_str().ok()?.trim();
    if let Ok(seconds) = value.parse::<u64>() {
        return Some(Duration::from_secs(seconds));
    }
    let when = parse_http_date(value)?;
    let delta = when - clock.now();
    if delta.is_negative() {
        return Some(Duration::ZERO);
    }
    Duration::try_from(delta).ok()
}

/// An IMF-fixdate, the one form RFC 9110 §5.6.7 allows a sender to generate:
/// `Sun, 06 Nov 1994 08:49:37 GMT`.
///
/// The two obsolete forms (RFC 850 and asctime) are not parsed. A recipient
/// is required to accept them, but nothing in front of a push service emits
/// them, and mis-parsing a two-digit year is worse than falling back to
/// "retry on your own schedule".
fn parse_http_date(value: &str) -> Option<OffsetDateTime> {
    // Version 2 of the format-description syntax, pinned explicitly:
    // `parse` without a version is deprecated precisely because the
    // unversioned form's meaning can shift under a `time` upgrade.
    let format = time::format_description::parse_borrowed::<2>(
        "[weekday repr:short], [day] [month repr:short] [year] [hour]:[minute]:[second] GMT",
    )
    .ok()?;
    time::PrimitiveDateTime::parse(value, &format)
        .ok()
        .map(time::PrimitiveDateTime::assume_utc)
}

/// A push service's error body, made safe to put in an error message: the
/// first 200 characters, control characters dropped.
///
/// Push services answer with anything from problem+json to a bare string, so
/// the body is passed through as text rather than parsed. It is bounded
/// because the message ends up in a log line and an error body is not a
/// budgeted response.
fn detail(body: &[u8], status: StatusCode) -> String {
    let text: String = String::from_utf8_lossy(body)
        .chars()
        .filter(|c| !c.is_control())
        .take(200)
        .collect();
    let text = text.trim();
    if text.is_empty() {
        status.as_u16().to_string()
    } else {
        text.to_owned()
    }
}

#[async_trait]
impl Push for WebPush {
    async fn send(
        &self,
        to: &Recipient,
        notification: &Notification,
    ) -> Result<PushOutcome, PushError> {
        // One transport per adapter, decided before configuration is: an
        // unconfigured Web Push adapter still does not serve APNs, and
        // answering `NotConfigured` for an APNs recipient would claim a
        // transport it will never carry (ADR 0015).
        let Recipient::WebPush {
            endpoint,
            p256dh,
            auth,
        } = to
        else {
            return Err(PushError::unsupported_recipient(to));
        };
        let live = match &self.inner {
            Inner::NotConfigured => return Ok(PushOutcome::NotConfigured),
            Inner::Live(live) => live,
        };

        // Everything that can be refused locally is refused before a socket
        // is opened: a bad endpoint, a malformed subscription, and an
        // oversize payload are all the caller's to fix, and a push service
        // would only tell us the same thing more slowly.
        let origin =
            vapid::origin_of(endpoint).map_err(|err| PushError::Rejected(err.to_string()))?;
        let keys = SubscriptionKeys::parse(p256dh, auth)
            .map_err(|err| PushError::Rejected(err.to_string()))?;
        let payload = build_payload(notification);
        let body = live.ece.seal(&keys, &payload).map_err(|err| match &err {
            // A randomness failure is the platform's, not the request's:
            // the same send may work on the next isolate.
            EceError::Random(_) => PushError::transient(err.to_string()),
            _ => PushError::Rejected(err.to_string()),
        })?;

        let mut builder = Request::builder()
            .method("POST")
            .uri(endpoint)
            .header(
                AUTHORIZATION,
                live.vapid.authorization(live.clock.as_ref(), &origin),
            )
            // RFC 8291 §4: exactly one content encoding, and it is this one.
            .header(CONTENT_ENCODING, "aes128gcm")
            // RFC 8188 §3.1's own advice: an opaque type, so the request
            // says nothing about what was encrypted.
            .header(CONTENT_TYPE, "application/octet-stream")
            .header("ttl", ttl_header(notification.ttl))
            .header("urgency", urgency_header(notification.priority));
        if let Some(collapse_id) = &notification.collapse_id {
            builder = builder.header("topic", topic_header(collapse_id));
        }
        let request = builder
            .body(Bytes::from(body))
            .map_err(|err| PushError::Rejected(format!("could not build request: {err}")))?;

        let response = live
            .http
            .send(request)
            .await
            .map_err(|err| PushError::transient(err.to_string()))?;

        let status = response.status();
        match status {
            // RFC 8030 §5 answers `201 Created` with a `Location` naming the
            // push message resource. Any other 2xx is accepted too: ntfy
            // answers `200 OK` to a UnifiedPush publish, and refusing that
            // would fail a delivery that succeeded.
            status if status.is_success() => Ok(PushOutcome::Delivered {
                id: response
                    .headers()
                    .get(LOCATION)
                    .and_then(|value| value.to_str().ok())
                    .map(str::to_owned),
            }),
            // The subscription is gone. `404` and `410` both mean it across
            // vendors — Mozilla answers `410`, others `404` once the
            // capability URL stops resolving — and the caller must delete
            // the recipient either way.
            StatusCode::NOT_FOUND | StatusCode::GONE => Err(PushError::Unregistered),
            StatusCode::TOO_MANY_REQUESTS => Err(PushError::transient_after(
                format!(
                    "web push {}: {}",
                    status.as_u16(),
                    detail(response.body(), status)
                ),
                retry_after(response.headers(), live.clock.as_ref()),
            )),
            status if status.is_server_error() => Err(PushError::transient_after(
                format!(
                    "web push {}: {}",
                    status.as_u16(),
                    detail(response.body(), status)
                ),
                retry_after(response.headers(), live.clock.as_ref()),
            )),
            // `400` (malformed request), `401`/`403` (the VAPID token was
            // refused) and `413` (body too large for this service) are all
            // ours to fix, not to retry.
            //
            // A `401` in particular is almost always an `aud` that is not
            // the endpoint's origin, so the cached token for this origin is
            // dropped: if the token was merely stale the next send re-signs,
            // and if the audience is wrong the error repeats identically
            // instead of being masked by a cache hit.
            status => {
                if status == StatusCode::UNAUTHORIZED || status == StatusCode::FORBIDDEN {
                    live.vapid.invalidate(&origin);
                }
                Err(PushError::Rejected(format!(
                    "web push {}: {}",
                    status.as_u16(),
                    detail(response.body(), status)
                )))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_topic_that_already_fits_is_passed_through() {
        assert_eq!(topic_header("room-42"), "room-42");
        assert_eq!(topic_header("a"), "a");
        let exactly_32 = "a".repeat(MAX_TOPIC_LEN);
        assert_eq!(topic_header(&exactly_32), exactly_32);
    }

    #[test]
    fn a_topic_that_does_not_fit_becomes_a_stable_32_character_hash() {
        let long = "a".repeat(MAX_TOPIC_LEN + 1);
        let hashed = topic_header(&long);
        assert_eq!(hashed.len(), MAX_TOPIC_LEN);
        assert!(
            hashed
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_'),
            "{hashed}"
        );
        // The one property a topic must keep: equal ids collapse, different
        // ids do not.
        assert_eq!(hashed, topic_header(&long));
        assert_ne!(hashed, topic_header(&"b".repeat(MAX_TOPIC_LEN + 1)));

        // Characters outside the alphabet are hashed even when short, and
        // the empty string is hashed rather than sent as an illegal header.
        for id in ["room/42", "user@example.test", "café", ""] {
            let topic = topic_header(id);
            assert_eq!(topic.len(), MAX_TOPIC_LEN, "{id}");
            assert!(
                topic
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_'),
                "{id} -> {topic}"
            );
        }
    }

    #[test]
    fn the_ttl_header_is_whole_seconds_with_a_day_by_default() {
        assert_eq!(ttl_header(None), "86400");
        assert_eq!(ttl_header(Some(Duration::from_secs(60))), "60");
        assert_eq!(ttl_header(Some(Duration::ZERO)), "0", "deliberate drop");
        assert_eq!(
            ttl_header(Some(Duration::from_millis(900))),
            "1",
            "sub-second rounds up, never down to the drop-now instruction"
        );
    }

    #[test]
    fn urgency_maps_the_two_priorities_the_port_carries() {
        assert_eq!(urgency_header(Priority::Immediate), "high");
        assert_eq!(urgency_header(Priority::Conserve), "normal");
    }

    #[test]
    fn an_http_date_parses_and_a_nonsense_one_does_not() {
        let parsed = parse_http_date("Sun, 06 Nov 1994 08:49:37 GMT").expect("IMF-fixdate");
        assert_eq!(parsed.unix_timestamp(), 784_111_777);
        assert!(parse_http_date("Sunday, 06-Nov-94 08:49:37 GMT").is_none());
        assert!(parse_http_date("tomorrow").is_none());
    }

    #[test]
    fn an_error_detail_is_bounded_and_stripped_of_control_characters() {
        assert_eq!(
            detail(b"bad request", StatusCode::BAD_REQUEST),
            "bad request"
        );
        assert_eq!(detail(b"", StatusCode::BAD_REQUEST), "400");
        assert_eq!(detail(b"  \n ", StatusCode::GONE), "410");
        assert_eq!(detail(b"a\nb\tc", StatusCode::BAD_REQUEST), "abc");
        let long = vec![b'x'; 4_096];
        assert_eq!(detail(&long, StatusCode::BAD_REQUEST).len(), 200);
    }
}
