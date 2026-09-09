//! The `Push` port (issues #104, #177): a notification to a device, whatever
//! carries it. Mail reaches an inbox through [`Mailer`](crate::Mailer);
//! nothing else reached a device until this. APNs today, FCM and Web Push
//! next (ADR 0015).
//!
//! A recipient is a [`Recipient`], not a token string: a Web Push
//! subscription is `{ endpoint, p256dh, auth }` and never fits in one opaque
//! string, and JSON-in-a-string would make every adapter parse and every
//! mistake silent. [`Notification`] is transport-neutral — each adapter maps
//! the fields its protocol has and documents what it drops.
//!
//! The device-token registry is venture code — each venture decides what a
//! recipient belongs to — but the port defines the [`PushError::Unregistered`]
//! contract so a module knows when to prune a dead one.

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use thiserror::Error;

/// The transport a [`Recipient`] is reached over, which is **not** a
/// statement about the device: a UnifiedPush endpoint is
/// [`Platform::Web`] on an Android phone (ADR 0015).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Platform {
    /// Apple Push Notification service.
    Ios,
    /// Firebase Cloud Messaging.
    Android,
    /// Web Push (RFC 8030), browser or UnifiedPush.
    Web,
}

impl Platform {
    /// The name used in errors and logs.
    pub fn name(&self) -> &'static str {
        match self {
            Platform::Ios => "ios",
            Platform::Android => "android",
            Platform::Web => "web",
        }
    }
}

impl std::fmt::Display for Platform {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.name())
    }
}

/// Where a notification is sent. One variant per push transport, because the
/// three do not share a shape: APNs and FCM take an opaque token, Web Push
/// takes a subscription of three parts (RFC 8291).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Recipient {
    /// An APNs device token (hex, from `application:didRegister...`).
    Apns { device_token: String },
    /// An FCM registration token.
    Fcm { registration_token: String },
    /// A Web Push subscription: the push service URL plus the two RFC 8291
    /// keys, both base64url as the browser hands them over.
    WebPush {
        endpoint: String,
        p256dh: String,
        auth: String,
    },
}

impl Recipient {
    /// An APNs recipient.
    pub fn apns(device_token: impl Into<String>) -> Self {
        Recipient::Apns {
            device_token: device_token.into(),
        }
    }

    /// An FCM recipient.
    pub fn fcm(registration_token: impl Into<String>) -> Self {
        Recipient::Fcm {
            registration_token: registration_token.into(),
        }
    }

    /// A Web Push recipient (RFC 8291 keys, base64url).
    pub fn web_push(
        endpoint: impl Into<String>,
        p256dh: impl Into<String>,
        auth: impl Into<String>,
    ) -> Self {
        Recipient::WebPush {
            endpoint: endpoint.into(),
            p256dh: p256dh.into(),
            auth: auth.into(),
        }
    }

    /// The transport this recipient is reached over. A *transport* fact, not
    /// a device fact (ADR 0015).
    pub fn platform(&self) -> Platform {
        match self {
            Recipient::Apns { .. } => Platform::Ios,
            Recipient::Fcm { .. } => Platform::Android,
            Recipient::WebPush { .. } => Platform::Web,
        }
    }
}

/// How urgently the notification should be delivered. Maps to APNs priority
/// `10` (deliver now, may wake the device) and `5` (deliver to save power);
/// to `android.priority` `HIGH`/`NORMAL`; to the Web Push `Urgency` header
/// `high`/`normal`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Priority {
    /// Deliver immediately.
    #[default]
    Immediate,
    /// Deliver when convenient, to conserve power.
    Conserve,
}

/// Native localisation keys. The strings are looked up in the app's own
/// catalogue by the operating system, so a notification can be localised
/// without the server knowing the device's language. Reserved here and
/// mapped by the adapters; rendering is the i18n child's job.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct LocKeys {
    /// Key for the title (`aps.alert.title-loc-key`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub title_loc_key: Option<String>,
    /// Substitutions for the title key.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub title_loc_args: Vec<String>,
    /// Key for the body (`aps.alert.loc-key`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub body_loc_key: Option<String>,
    /// Substitutions for the body key.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub body_loc_args: Vec<String>,
}

/// One notification, in transport-neutral terms. `data` is the custom
/// key-value payload the app reads; `collapse_id` coalesces notifications the
/// user has not seen yet.
///
/// Every optional field is a *request*: an adapter maps what its protocol
/// has and documents what it drops (APNs has no `icon`, Web Push has no
/// `badge`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Notification {
    pub title: String,
    pub body: String,
    /// The notification category (an app-defined action group).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub category: Option<String>,
    /// Groups related notifications in the UI.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub thread_id: Option<String>,
    /// Custom payload the app reads; merged alongside the `aps` block.
    #[serde(default)]
    pub data: Value,
    /// Coalesces with any undelivered notification carrying the same id.
    /// `apns-collapse-id` / `android.collapse_key` / the Web Push `Topic`
    /// header (≤32 URL-safe characters, so a Web Push adapter shortens it
    /// and documents how).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub collapse_id: Option<String>,
    #[serde(default)]
    pub priority: Priority,
    /// An icon for the notification (Web Push `icon`; ignored by APNs, which
    /// takes its icon from the app bundle).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub icon: Option<String>,
    /// Where a tap should take the user: the Web Push click target, FCM's
    /// `click_action`, and a top-level `url` in the APNs payload.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    /// How long the push service may hold the notification while the device
    /// is offline. Serialised as whole seconds.
    ///
    /// Note the wire forms differ: `apns-expiration` is an **absolute** UNIX
    /// epoch, so the APNs adapter sends `now + ttl`; `android.ttl` is
    /// `"<s>s"`; Web Push `TTL` is seconds. A zero TTL means "deliver now or
    /// drop" in all three.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        with = "duration_secs"
    )]
    pub ttl: Option<Duration>,
    /// The badge number to show on the app icon (iOS). Ignored elsewhere.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub badge: Option<u32>,
    /// A data-only notification: nothing is shown, the app is woken to do
    /// work (`content-available` / FCM data message).
    #[serde(default, skip_serializing_if = "is_false")]
    pub silent: bool,
    /// Native localisation keys, in place of `title`/`body`, where the
    /// platform supports them.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub loc: Option<LocKeys>,
}

#[allow(clippy::trivially_copy_pass_by_ref)] // serde's skip_serializing_if shape
fn is_false(value: &bool) -> bool {
    !*value
}

/// `Option<Duration>` on the wire as whole seconds, so a notification
/// round-trips as `{"ttl": 3600}` and not serde's `{"secs":…,"nanos":…}`.
mod duration_secs {
    use serde::{Deserialize, Deserializer, Serializer};
    use std::time::Duration;

    // serde's `with` module fixes this signature; `Option<&Duration>` does
    // not compile as a serializer here.
    #[allow(clippy::ref_option)]
    pub fn serialize<S: Serializer>(
        value: &Option<Duration>,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        match value {
            Some(duration) => serializer.serialize_some(&duration.as_secs()),
            None => serializer.serialize_none(),
        }
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Option<Duration>, D::Error> {
        Ok(Option::<u64>::deserialize(deserializer)?.map(Duration::from_secs))
    }
}

impl Notification {
    /// A minimal notification with a title and body.
    #[must_use]
    pub fn new(title: impl Into<String>, body: impl Into<String>) -> Self {
        Self {
            title: title.into(),
            body: body.into(),
            category: None,
            thread_id: None,
            data: Value::Null,
            collapse_id: None,
            priority: Priority::Immediate,
            icon: None,
            url: None,
            ttl: None,
            badge: None,
            silent: false,
            loc: None,
        }
    }
}

/// The result of a send that the provider accepted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PushOutcome {
    /// Accepted; carries the provider's id where it gives one (`apns-id`).
    Delivered { id: Option<String> },
    /// The adapter is not configured (no key / unverified). The caller can
    /// degrade rather than treating it as a failure, the same way
    /// [`SendOutcome::NotConfigured`](crate::SendOutcome) works for mail.
    /// [`RoutingPush`] also answers this for a recipient no adapter serves.
    NotConfigured,
}

/// Push failures. `Unregistered` is separated because the caller must act on
/// it — the recipient is dead and should be pruned — where the others are
/// transient or a bad request.
#[derive(Debug, Clone, Error)]
pub enum PushError {
    /// The provider says the recipient is no longer valid (APNs `410`, Web
    /// Push `404`/`410`, FCM `UNREGISTERED`): delete it.
    #[error("device token is no longer registered; delete it")]
    Unregistered,
    /// The provider rejected the request (a `4xx` that is not `410`), or the
    /// adapter does not serve this recipient's transport; not retryable
    /// without a change.
    #[error("push rejected: {0}")]
    Rejected(String),
    /// A transient failure (a `5xx`, a `429`, a transport error): retry
    /// later, and not before `retry_after` when the provider named one
    /// (APNs `429`, FCM `RESOURCE_EXHAUSTED`/`UNAVAILABLE`, Web Push
    /// `429`/`503` — all carry `Retry-After`).
    #[error("push failed, retryable: {message}")]
    Transient {
        message: String,
        retry_after: Option<Duration>,
    },
}

impl PushError {
    /// A retryable failure with no provider-supplied delay.
    pub fn transient(message: impl Into<String>) -> Self {
        PushError::Transient {
            message: message.into(),
            retry_after: None,
        }
    }

    /// A retryable failure the provider asked us to hold off on.
    pub fn transient_after(message: impl Into<String>, retry_after: Option<Duration>) -> Self {
        PushError::Transient {
            message: message.into(),
            retry_after,
        }
    }

    /// The rejection an adapter returns for a transport it does not serve.
    /// [`RoutingPush`] exists so a venture never has to see this.
    pub fn unsupported_recipient(recipient: &Recipient) -> Self {
        PushError::Rejected(format!(
            "unsupported recipient: this adapter does not serve {}",
            recipient.platform()
        ))
    }

    /// How long the provider asked the caller to wait, where it said.
    pub fn retry_after(&self) -> Option<Duration> {
        match self {
            PushError::Transient { retry_after, .. } => *retry_after,
            _ => None,
        }
    }
}

/// Sends notifications to a device, over whichever transport the
/// [`Recipient`] names. An adapter serves one transport and returns
/// [`PushError::unsupported_recipient`] for the rest; [`RoutingPush`] fans a
/// mixed set of recipients out across the adapters a venture configured.
#[async_trait]
pub trait Push: Send + Sync {
    /// Sends `notification` to `to`.
    async fn send(
        &self,
        to: &Recipient,
        notification: &Notification,
    ) -> Result<PushOutcome, PushError>;
}

/// Dispatches by [`Recipient`] variant to the adapter a venture configured
/// for that transport, so venture code holds one `Arc<dyn Push>` and never
/// matches on the transport itself (ADR 0015).
///
/// A recipient whose transport has no adapter is
/// [`PushOutcome::NotConfigured`] — the same answer an unconfigured adapter
/// gives, and deliberately not [`PushError::Rejected`]: nothing is wrong with
/// the recipient, the venture simply did not wire that transport.
#[derive(Default, Clone)]
pub struct RoutingPush {
    apns: Option<Arc<dyn Push>>,
    fcm: Option<Arc<dyn Push>>,
    web_push: Option<Arc<dyn Push>>,
}

impl RoutingPush {
    /// A router with no adapters: every recipient is `NotConfigured`.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// The adapter for [`Recipient::Apns`].
    #[must_use]
    pub fn apns(mut self, push: Arc<dyn Push>) -> Self {
        self.apns = Some(push);
        self
    }

    /// The adapter for [`Recipient::Fcm`].
    #[must_use]
    pub fn fcm(mut self, push: Arc<dyn Push>) -> Self {
        self.fcm = Some(push);
        self
    }

    /// The adapter for [`Recipient::WebPush`].
    #[must_use]
    pub fn web_push(mut self, push: Arc<dyn Push>) -> Self {
        self.web_push = Some(push);
        self
    }

    /// The adapter that serves `recipient`, if one is configured.
    #[must_use]
    pub fn route_for(&self, recipient: &Recipient) -> Option<&Arc<dyn Push>> {
        match recipient {
            Recipient::Apns { .. } => self.apns.as_ref(),
            Recipient::Fcm { .. } => self.fcm.as_ref(),
            Recipient::WebPush { .. } => self.web_push.as_ref(),
        }
    }
}

impl std::fmt::Debug for RoutingPush {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RoutingPush")
            .field("apns", &self.apns.is_some())
            .field("fcm", &self.fcm.is_some())
            .field("web_push", &self.web_push.is_some())
            .finish()
    }
}

#[async_trait]
impl Push for RoutingPush {
    async fn send(
        &self,
        to: &Recipient,
        notification: &Notification,
    ) -> Result<PushOutcome, PushError> {
        match self.route_for(to) {
            Some(push) => push.send(to, notification).await,
            None => Ok(PushOutcome::NotConfigured),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_recipient_round_trips_through_json() {
        for recipient in [
            Recipient::apns("devicetoken"),
            Recipient::fcm("registration"),
            Recipient::web_push("https://fcm.googleapis.com/wp/x", "p256dh-key", "auth-key"),
        ] {
            let json = serde_json::to_string(&recipient).expect("serialises");
            let back: Recipient = serde_json::from_str(&json).expect("deserialises");
            assert_eq!(recipient, back);
        }
    }

    #[test]
    fn the_recipient_tag_is_the_transport_name() {
        let json = serde_json::to_value(Recipient::web_push("https://e", "p", "a")).unwrap();
        assert_eq!(json["web_push"]["endpoint"], "https://e");
        assert_eq!(json["web_push"]["p256dh"], "p");
        assert_eq!(json["web_push"]["auth"], "a");
    }

    #[test]
    fn platform_is_a_transport_fact() {
        assert_eq!(Recipient::apns("t").platform(), Platform::Ios);
        assert_eq!(Recipient::fcm("t").platform(), Platform::Android);
        // A UnifiedPush endpoint on an Android phone is still Web Push.
        assert_eq!(
            Recipient::web_push("https://ntfy.sh/x", "p", "a").platform(),
            Platform::Web
        );
    }

    #[test]
    fn a_minimal_notification_serialises_to_title_body_data_priority() {
        let json = serde_json::to_value(Notification::new("Hi", "there")).unwrap();
        let object = json.as_object().expect("object");
        let mut keys: Vec<&str> = object.keys().map(String::as_str).collect();
        keys.sort_unstable();
        assert_eq!(keys, ["body", "data", "priority", "title"]);
    }

    #[test]
    fn a_full_notification_round_trips_and_ttl_is_seconds() {
        let mut notification = Notification::new("Room starting", "Yoga in 10 min");
        notification.category = Some("SESSION".to_owned());
        notification.thread_id = Some("room-42".to_owned());
        notification.data = serde_json::json!({ "room_id": "42" });
        notification.collapse_id = Some("room-42".to_owned());
        notification.priority = Priority::Conserve;
        notification.icon = Some("https://example.test/icon.png".to_owned());
        notification.url = Some("https://example.test/rooms/42".to_owned());
        notification.ttl = Some(Duration::from_secs(3_600));
        notification.badge = Some(3);
        notification.silent = true;
        notification.loc = Some(LocKeys {
            title_loc_key: Some("ROOM_STARTING".to_owned()),
            title_loc_args: vec!["Yoga".to_owned()],
            body_loc_key: Some("ROOM_BODY".to_owned()),
            body_loc_args: vec!["10".to_owned()],
        });

        let json = serde_json::to_value(&notification).unwrap();
        assert_eq!(json["ttl"], 3_600, "a TTL is whole seconds on the wire");
        assert_eq!(json["silent"], true);
        assert_eq!(json["loc"]["title_loc_key"], "ROOM_STARTING");

        let back: Notification = serde_json::from_value(json).unwrap();
        assert_eq!(back, notification);
    }

    #[test]
    fn a_notification_from_the_pre_recipient_wire_form_still_parses() {
        // Every field #177 added is optional, so a payload written against
        // the old shape (an outbox row, say) still deserialises.
        let old = serde_json::json!({
            "title": "Hi",
            "body": "there",
            "data": {},
            "priority": "immediate"
        });
        let notification: Notification = serde_json::from_value(old).unwrap();
        assert_eq!(notification.title, "Hi");
        assert_eq!(notification.ttl, None);
        assert!(!notification.silent);
    }

    #[test]
    fn transient_carries_an_optional_retry_after() {
        let plain = PushError::transient("apns 503");
        assert_eq!(plain.retry_after(), None);
        let throttled = PushError::transient_after("apns 429", Some(Duration::from_secs(30)));
        assert_eq!(throttled.retry_after(), Some(Duration::from_secs(30)));
        assert_eq!(PushError::Unregistered.retry_after(), None);
    }

    #[test]
    fn an_unsupported_recipient_names_the_transport() {
        let error = PushError::unsupported_recipient(&Recipient::fcm("t"));
        let message = error.to_string();
        assert!(message.contains("unsupported recipient"), "{message}");
        assert!(message.contains("android"), "{message}");
    }

    // -----------------------------------------------------------------
    // RoutingPush

    struct Recording {
        label: &'static str,
        seen: std::sync::atomic::AtomicUsize,
    }

    impl Recording {
        fn new(label: &'static str) -> Arc<Self> {
            Arc::new(Self {
                label,
                seen: std::sync::atomic::AtomicUsize::new(0),
            })
        }
        fn count(&self) -> usize {
            self.seen.load(std::sync::atomic::Ordering::Relaxed)
        }
    }

    #[async_trait]
    impl Push for Recording {
        async fn send(
            &self,
            _to: &Recipient,
            _notification: &Notification,
        ) -> Result<PushOutcome, PushError> {
            self.seen.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            Ok(PushOutcome::Delivered {
                id: Some(self.label.to_owned()),
            })
        }
    }

    #[test]
    fn the_router_dispatches_by_variant() {
        let apns = Recording::new("apns");
        let web = Recording::new("web");
        let router = RoutingPush::new().apns(apns.clone()).web_push(web.clone());
        let notification = Notification::new("a", "b");

        let outcome =
            pollster::block_on(router.send(&Recipient::apns("t"), &notification)).unwrap();
        assert_eq!(
            outcome,
            PushOutcome::Delivered {
                id: Some("apns".to_owned())
            }
        );
        let outcome = pollster::block_on(
            router.send(&Recipient::web_push("https://e", "p", "a"), &notification),
        )
        .unwrap();
        assert_eq!(
            outcome,
            PushOutcome::Delivered {
                id: Some("web".to_owned())
            }
        );
        assert_eq!(apns.count(), 1);
        assert_eq!(web.count(), 1);
    }

    #[test]
    fn a_transport_with_no_adapter_is_not_configured_not_rejected() {
        let router = RoutingPush::new().apns(Recording::new("apns"));
        let outcome =
            pollster::block_on(router.send(&Recipient::fcm("t"), &Notification::new("a", "b")))
                .unwrap();
        assert_eq!(outcome, PushOutcome::NotConfigured);
    }

    #[test]
    fn an_empty_router_is_not_configured_for_every_transport() {
        let router = RoutingPush::new();
        for recipient in [
            Recipient::apns("t"),
            Recipient::fcm("t"),
            Recipient::web_push("https://e", "p", "a"),
        ] {
            let outcome =
                pollster::block_on(router.send(&recipient, &Notification::new("a", "b"))).unwrap();
            assert_eq!(outcome, PushOutcome::NotConfigured);
            assert!(router.route_for(&recipient).is_none());
        }
    }
}
