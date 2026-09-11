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
//! # `Unregistered` is a delete instruction
//!
//! [`PushError::Unregistered`] does not mean "this send failed". It is the
//! one error in the port that tells the caller to **destroy** the recipient,
//! and it is far too easy to over-apply — this adapter and its FCM sibling
//! each mapped an extra status onto it independently, before either was
//! reviewed.
//!
//! It costs more here than anywhere else in the port. An APNs device token
//! or an FCM registration token is re-registered by the app on its next
//! launch, unattended; a Web Push subscription can be recreated **only** by
//! the browser calling `pushManager.subscribe()`, which needs the user back
//! on the site with notification permission still granted. Pruning a live
//! subscription is not a lost message, it is a lost subscriber.
//!
//! So the bar is a status whose *only* meaning is "gone": RFC 8030 §5
//! defines exactly one, `410 Gone`, and that is the only one mapped. A
//! status that a misconfigured proxy, a stale ingress rule or a rate limiter
//! can also produce is retried, however often it happens to mean a dead
//! subscription in practice. When in doubt, retry: the cost of a wrong
//! `Transient` is some wasted sends, and the cost of a wrong `Unregistered`
//! cannot be undone from the server at all.
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
use http::header::{AUTHORIZATION, CONTENT_ENCODING, CONTENT_TYPE, LOCATION};
use http::{Request, StatusCode};
use serde_json::{Map, Value};
use sha2::{Digest as _, Sha256};

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

/// What a redacted URL or path is replaced by in an error message.
const REDACTED: &str = "[redacted]";

/// How much of a push service's error body reaches the error message.
const DETAIL_MAX_CHARS: usize = 200;

/// The characters RFC 3986 allows in a URI reference — unreserved, reserved
/// and the percent sign. A maximal run of them containing a `/` is treated
/// as a URL or a path by [`redact_uris`].
fn is_uri_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || "-._~:/?#[]@!$&'()*+,;=%".contains(c)
}

/// Replaces anything URL- or path-shaped with [`REDACTED`].
///
/// The rule is deliberately blunt — any run of URI characters containing a
/// `/` goes — because the thing being protected is a bearer capability and
/// the thing being preserved is a diagnostic string. Over-redacting an error
/// body costs a line of log detail; under-redacting one publishes a
/// subscription that anyone holding it can push to.
fn redact_uris(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while !rest.is_empty() {
        let start = rest.find(is_uri_char).unwrap_or(rest.len());
        out.push_str(&rest[..start]);
        rest = &rest[start..];
        let end = rest.find(|c: char| !is_uri_char(c)).unwrap_or(rest.len());
        let (run, tail) = rest.split_at(end);
        if run.contains('/') {
            out.push_str(REDACTED);
        } else {
            out.push_str(run);
        }
        rest = tail;
    }
    out
}

/// A push service's error body, made safe to put in an error message: the
/// first [`DETAIL_MAX_CHARS`] characters, control characters dropped, and
/// every URL or path redacted.
///
/// Push services answer with anything from problem+json to a bare string, so
/// the body is passed through as text rather than parsed — the way the APNs
/// adapter reads only its `reason` is not available here, because there is no
/// error schema the vendors share.
///
/// **The redaction is the point.** ntfy, nginx and every CDN error page echo
/// the request path, and a Web Push request path *is* the subscription:
/// `crates/core/src/ports/push.rs` calls the endpoint a bearer capability —
/// whoever holds it can push to that browser — that must appear "never in a
/// log, an event payload, or an error body". This message is all three.
///
/// Bounded first and redacted second, so a 10 MB error page never becomes a
/// 10 MB allocation. Truncation can only cut a URL's tail, never its head,
/// so what survives the cut still carries the `/` that gets it redacted.
fn detail(body: &[u8], status: StatusCode) -> String {
    let text: String = String::from_utf8_lossy(body)
        .chars()
        .filter(|c| !c.is_control())
        .take(DETAIL_MAX_CHARS)
        .collect();
    let text = redact_uris(&text);
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
        // Every arm says the same thing: `web push <status>: <redacted
        // body>`. Built once so no arm can forget the redaction.
        let message = || {
            format!(
                "web push {}: {}",
                status.as_u16(),
                detail(response.body(), status)
            )
        };
        let retry_after = || cratefield_core::retry_after(response.headers(), live.clock.as_ref());

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
            // The subscription is gone, and **only** this status says so.
            // See the note on over-applying `Unregistered` in the module
            // documentation before adding a second one.
            StatusCode::GONE => Err(PushError::Unregistered),
            // `404` is *not* that. RFC 8030 defines only `410`, and a `404`
            // is what a proxy that came back without its routes, an edited
            // ingress rule or a moved reverse proxy answers for **every**
            // path — so pruning on it deletes a venture's whole Web Push
            // register in one pass. That is unrecoverable server-side: a
            // subscription can only be recreated by the browser calling
            // `pushManager.subscribe()` again, which needs the user back on
            // the site.
            //
            // So it is retryable, and the cost of being wrong is the other
            // way round: a subscription that really is gone behind a service
            // that only ever says `404` is retried until the caller's own
            // attempt budget gives up, and lingers in the register. Wasted
            // sends against lost subscribers is the trade.
            StatusCode::NOT_FOUND => Err(PushError::transient_after(
                format!(
                    "{} (a 404 is not a dead subscription; only 410 is)",
                    message()
                ),
                retry_after(),
            )),
            // ntfy answers `507 "cannot publish to UnifiedPush topic without
            // previously active subscriber"` when it runs with
            // `visitor-subscriber-rate-limiting` on, as the public
            // `ntfy.sh` does. It is an operator configuration state, not
            // load: it never clears on its own, so retrying it as a 5xx
            // retries forever. The README documents it; this arm is the
            // README made executable.
            StatusCode::INSUFFICIENT_STORAGE => Err(PushError::Rejected(format!(
                "{} (a push service refusing storage is an operator state, not load: on ntfy \
                 this is `visitor-subscriber-rate-limiting`, which needs a subscriber on the \
                 topic or the setting turned off)",
                message()
            ))),
            // The VAPID token was refused. The cached token for this origin
            // is dropped so the next send re-signs — and the send is
            // **retryable**, because the commonest cause is exactly that:
            // a clock a few minutes out, or a token that aged past its
            // `exp` in flight, both of which the re-sign fixes. Returning
            // `Rejected` here arranged the re-sign and then threw away the
            // message that would have used it.
            //
            // A genuinely wrong `aud` or a revoked key repeats the error
            // instead of clearing, and is bounded by the caller's retry
            // budget rather than by us. The APNs adapter makes the same
            // trade for `ExpiredProviderToken`/`InvalidProviderToken`.
            StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN => {
                live.vapid.invalidate(&origin);
                Err(PushError::transient_after(
                    format!(
                        "{} (VAPID token refused; re-signing for this origin)",
                        message()
                    ),
                    retry_after(),
                ))
            }
            // A push service that moved. This adapter does not follow the
            // redirect — the VAPID token is signed over the *old* origin, so
            // replaying the POST at the `Location` earns a `401` from any
            // service that checks `aud` — but a move is at worst temporary
            // and never a reason to destroy the notification. The `Location`
            // is deliberately not quoted: it is a push endpoint.
            status if status.is_redirection() => Err(PushError::transient_after(
                format!(
                    "{message} (redirects are not followed: the VAPID `aud` is signed over the original origin)",
                    message = message()
                ),
                retry_after(),
            )),
            StatusCode::TOO_MANY_REQUESTS => {
                Err(PushError::transient_after(message(), retry_after()))
            }
            status if status.is_server_error() => {
                Err(PushError::transient_after(message(), retry_after()))
            }
            // `400` (malformed request) and `413` (body too large for this
            // service) are ours to fix, not to retry.
            _ => Err(PushError::Rejected(message())),
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

    /// The subscription endpoint is a bearer capability, and error pages
    /// echo the request path. Everything URL-shaped goes; the prose around
    /// it, which is the diagnostic value, stays.
    #[test]
    fn an_error_detail_never_carries_a_url_or_a_path() {
        // Apache's 404 page, and the one that started this: the path *is*
        // the subscription.
        let apache =
            b"The requested URL /wpush/v2/gAAAAABsecret-capability was not found on this server.";
        let redacted = detail(apache, StatusCode::NOT_FOUND);
        assert_eq!(
            redacted,
            "The requested URL [redacted] was not found on this server."
        );
        assert!(!redacted.contains("wpush"), "{redacted}");
        assert!(!redacted.contains("gAAAAAB"), "{redacted}");

        // An absolute URL anywhere in the body, including one glued to the
        // text by a stripped newline.
        for body in [
            &b"see https://updates.push.services.mozilla.com/wpush/v2/gAAAAABsecret"[..],
            &b"Not Found\nhttps://push.example/wpush/v2/gAAAAABsecret"[..],
            &b"{\"endpoint\":\"https://push.example/wpush/v2/gAAAAABsecret\"}"[..],
        ] {
            let redacted = detail(body, StatusCode::NOT_FOUND);
            assert!(!redacted.contains("gAAAAABsecret"), "{redacted}");
            assert!(!redacted.contains("push.example"), "{redacted}");
            assert!(!redacted.contains("mozilla.com"), "{redacted}");
            assert!(redacted.contains(REDACTED), "{redacted}");
        }

        // The diagnostic that matters is prose and survives intact — this is
        // the ntfy body the README quotes.
        assert_eq!(
            detail(
                b"cannot publish to UnifiedPush topic without previously active subscriber",
                StatusCode::INSUFFICIENT_STORAGE
            ),
            "cannot publish to UnifiedPush topic without previously active subscriber"
        );
        assert_eq!(
            detail(b"UnauthorizedRegistration", StatusCode::UNAUTHORIZED),
            "UnauthorizedRegistration"
        );

        // A body that is nothing but the endpoint redacts to the endpoint's
        // absence, not to a bare status — and one long enough to be
        // truncated is still cut tail-first, so the `/` that triggers the
        // redaction is always inside what survives.
        let long_endpoint = format!("https://push.example/wpush/v2/{}", "A".repeat(4_000));
        let redacted = detail(long_endpoint.as_bytes(), StatusCode::NOT_FOUND);
        assert_eq!(redacted, REDACTED);
    }

    #[test]
    fn redaction_leaves_text_that_is_not_a_path_alone() {
        assert_eq!(
            redact_uris("plain prose, with punctuation!"),
            "plain prose, with punctuation!"
        );
        assert_eq!(redact_uris(""), "");
        assert_eq!(redact_uris("410"), "410");
        // Non-ASCII is not a URI character, so it neither joins a run nor
        // splits one incorrectly.
        assert_eq!(redact_uris("café /a/b naïve"), "café [redacted] naïve");
    }
}
