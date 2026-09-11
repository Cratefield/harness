//! `cratefield-adapter-apns`: the [`Push`] port over Apple Push Notification
//! service (issues #104, #177). Uses the runtime's [`HttpClient`] and
//! [`Clock`] ports — no vendor SDK, no `reqwest`, no `openssl` — so the same
//! adapter runs on Workers (`worker::Fetch`) and natively.
//!
//! **Recipients.** It serves [`Recipient::Apns`] and returns
//! [`PushError::unsupported_recipient`] for FCM and Web Push. A venture with
//! more than one transport wires
//! [`RoutingPush`](cratefield_core::RoutingPush), which dispatches by variant
//! (ADR 0015).
//!
//! **Authentication.** APNs takes a provider JWT signed ES256 with the `.p8`
//! key from the Apple developer portal. Signing and caching live in
//! [`cratefield_push_auth`] (issue #178), shared with the VAPID and Google
//! signers: the token is minted once and reused, because Apple rejects
//! regenerating it more than once per ~20 minutes
//! (`TooManyProviderTokenUpdates`) and accepts it for up to 60, so the
//! adapter caches it for [`JWT_TTL`] and re-mints past that. Signing is
//! pure-Rust P-256 ECDSA with a deterministic RFC6979 nonce, so it needs no
//! RNG on the isolate.
//!
//! **Degraded mode.** [`Apns::not_configured`] reports
//! [`PushOutcome::NotConfigured`] without any network call, the same contract
//! [`Resend`](cratefield_core::Mailer) uses when its key is absent, so a
//! venture with no APNs credentials still builds and runs. It answers that
//! only for the transport it serves: an FCM or Web Push recipient is still
//! [`PushError::unsupported_recipient`], configured or not.
//!
//! **Verification.** Signing and payload construction are unit-tested here,
//! but the live path against Apple's sandbox is `needs-human` (issue #104
//! acceptance): it needs a real `.p8`, a bundle id, and a device token, none
//! of which live in the repo.
#![doc = include_str!("../README.md")]
#![forbid(unsafe_code)]

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use cratefield_core::{
    Clock, HttpClient, Notification, Priority, Push, PushError, PushOutcome, Recipient, ttl_secs,
};
use cratefield_push_auth::{CachedToken, Es256Signer};
use http::header::AUTHORIZATION;
use http::{Request, StatusCode};
use serde_json::{Map, Value, json};

use bytes::Bytes;

/// How long a minted provider JWT is reused before it is re-signed. Apple
/// accepts a token for 60 minutes and rejects regenerating one more than once
/// per ~20; 50 minutes sits safely inside both bounds.
#[allow(clippy::duration_suboptimal_units)] // `from_mins` is not const-stable on 1.98
pub const JWT_TTL: Duration = Duration::from_secs(3_000);

/// Which APNs environment to target. A build signed with a development
/// provisioning profile registers its token with the sandbox; a
/// TestFlight/App Store build with production. Sending to the wrong host
/// returns `BadDeviceToken`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApnsHost {
    Production,
    Sandbox,
}

impl ApnsHost {
    fn authority(self) -> &'static str {
        match self {
            ApnsHost::Production => "api.push.apple.com",
            ApnsHost::Sandbox => "api.sandbox.push.apple.com",
        }
    }

    /// Parses the `APNS_HOST` secret: `production`/`prod` or
    /// `sandbox`/`development`/`dev` (case-insensitive).
    pub fn parse(value: &str) -> Option<Self> {
        match value.trim().to_ascii_lowercase().as_str() {
            "production" | "prod" => Some(ApnsHost::Production),
            "sandbox" | "development" | "dev" => Some(ApnsHost::Sandbox),
            _ => None,
        }
    }
}

/// The credentials a venture reads from its secrets to reach APNs.
pub struct ApnsCredentials {
    /// The `.p8` key file contents (PKCS#8 PEM) from the Apple developer
    /// portal.
    pub key_p8_pem: String,
    /// The key's 10-character id (the `.p8` filename suffix).
    pub key_id: String,
    /// The 10-character Apple team id (the JWT issuer).
    pub team_id: String,
    /// The app's bundle id, sent as `apns-topic`.
    pub topic: String,
    pub host: ApnsHost,
}

/// Building an [`Apns`] adapter failed.
#[derive(Debug, thiserror::Error)]
pub enum ApnsConfigError {
    /// The `.p8` did not parse as a PKCS#8 PEM P-256 private key.
    #[error("invalid APNs .p8 key: {0}")]
    Key(String),
}

/// [`Push`] over `POST https://{host}/3/device/{token}`.
pub struct Apns {
    inner: Inner,
}

enum Inner {
    Live(Box<Live>),
    NotConfigured,
}

struct Live {
    http: Arc<dyn HttpClient>,
    clock: Arc<dyn Clock>,
    signer: Es256Signer,
    key_id: String,
    team_id: String,
    topic: String,
    host: ApnsHost,
    /// One provider token for the whole adapter, hence the `()` key
    /// (VAPID is the variant that keys per push-service origin).
    jwt: CachedToken<()>,
}

impl Apns {
    /// Builds a live adapter, parsing the `.p8` up front so a malformed key is
    /// reported at construction rather than on the first send.
    ///
    /// # Errors
    ///
    /// Returns [`ApnsConfigError::Key`] if `key_p8_pem` is not a PKCS#8 PEM
    /// P-256 private key.
    pub fn new(
        http: Arc<dyn HttpClient>,
        clock: Arc<dyn Clock>,
        creds: ApnsCredentials,
    ) -> Result<Self, ApnsConfigError> {
        let signer = Es256Signer::from_p8_pem(&creds.key_p8_pem)
            .map_err(|err| ApnsConfigError::Key(err.to_string()))?;
        Ok(Self {
            inner: Inner::Live(Box::new(Live {
                http,
                clock,
                signer,
                key_id: creds.key_id,
                team_id: creds.team_id,
                topic: creds.topic,
                host: creds.host,
                jwt: CachedToken::new(JWT_TTL),
            })),
        })
    }

    /// A degraded adapter that reports [`PushOutcome::NotConfigured`] without
    /// any network call — for a venture with no APNs credentials set.
    #[must_use]
    pub fn not_configured() -> Self {
        Self {
            inner: Inner::NotConfigured,
        }
    }
}

impl Live {
    /// The current provider JWT, minting and caching a new one when the cached
    /// token is missing or older than [`JWT_TTL`].
    fn provider_jwt(&self) -> String {
        self.jwt.get_or_mint(self.clock.as_ref(), &(), |now_unix| {
            self.signer.sign_jwt(
                &json!({ "alg": "ES256", "kid": self.key_id }),
                &json!({ "iss": self.team_id, "iat": now_unix }),
            )
        })
    }

    /// Invalidates the cached JWT so the next send re-signs (used when APNs
    /// reports the token expired).
    fn invalidate_jwt(&self) {
        self.jwt.invalidate(&());
    }
}

/// The `apns-priority` header value for a [`Priority`].
///
/// A silent (`content-available`) push is always `5`: Apple rejects a
/// background push sent at `10`.
fn priority_header(priority: Priority, silent: bool) -> &'static str {
    match (silent, priority) {
        (true, _) | (false, Priority::Conserve) => "5",
        (false, Priority::Immediate) => "10",
    }
}

/// `apns-expiration` for a notification's TTL. The header is an **absolute**
/// UNIX epoch, not a duration, so a TTL becomes `now + ttl`; `0` is the one
/// value APNs reads as "deliver now or drop", which is what a zero TTL means.
///
/// A sub-second TTL is rounded up to one second by
/// [`ttl_secs`](cratefield_core::ttl_secs) rather than truncated, so
/// `from_millis(900)` asks APNs to hold the notification for a second and not
/// to discard it the instant the device is offline.
fn expiration_header(ttl: Duration, now_unix: i64) -> String {
    if ttl.is_zero() {
        return "0".to_owned();
    }
    let seconds = i64::try_from(ttl_secs(ttl)).unwrap_or(i64::MAX);
    now_unix.saturating_add(seconds).to_string()
}

/// Whether a device token can be spliced into the request path as-is.
///
/// An APNs device token is the hex of the 32 bytes
/// `application:didRegisterForRemoteNotificationsWithDeviceToken:` hands over.
/// Anything else — a `/`, `?`, `#`, `%`, whitespace, the `<...>` wrapper of
/// an old `Data` description — is not a token, and interpolating it would
/// silently retarget the request (or fail far downstream as "could not build
/// request"). Hyphen and underscore are tolerated because test and staging
/// registries use them and neither can change the path's shape.
fn is_wellformed_device_token(token: &str) -> bool {
    !token.is_empty()
        && token
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

/// Builds the APNs JSON payload: an `aps` block from the notification, with the
/// caller's `data` merged in at the top level alongside it.
///
/// Fields APNs has no home for are dropped on purpose: `icon` (the icon comes
/// from the app bundle) and `collapse_id` (a header, not payload).
fn build_payload(notification: &Notification) -> Vec<u8> {
    let mut aps = Map::new();
    if notification.silent {
        // A background push carries `content-available` and **nothing else**.
        // Apple ("Pushing background updates to your app"): omit the `alert`,
        // `badge` and `sound` keys, or the notification is delivered as a
        // user-visible one and the silent wake never happens. `category` and
        // `thread-id` go with them: both only describe how an alert is shown
        // and grouped, and Apple documents neither as usable in a background
        // push — so they are dropped rather than gambled on.
        aps.insert("content-available".to_owned(), json!(1));
    } else {
        let mut alert = Map::new();
        alert.insert(
            "title".to_owned(),
            Value::String(notification.title.clone()),
        );
        alert.insert("body".to_owned(), Value::String(notification.body.clone()));
        if let Some(loc) = &notification.loc {
            // Apple's own names: the title keys are prefixed, the body keys
            // are not. Where a loc key is present the device prefers it over
            // the literal title/body, which stay as the fallback.
            //
            // `*-loc-args` are the substitutions for a `*-loc-key`, so each
            // list is nested inside its key's arm: args without a key
            // substitute into nothing and Apple defines no meaning for them.
            if let Some(key) = &loc.title_loc_key {
                alert.insert("title-loc-key".to_owned(), Value::String(key.clone()));
                if !loc.title_loc_args.is_empty() {
                    alert.insert("title-loc-args".to_owned(), json!(loc.title_loc_args));
                }
            }
            if let Some(key) = &loc.body_loc_key {
                alert.insert("loc-key".to_owned(), Value::String(key.clone()));
                if !loc.body_loc_args.is_empty() {
                    alert.insert("loc-args".to_owned(), json!(loc.body_loc_args));
                }
            }
        }
        aps.insert("alert".to_owned(), Value::Object(alert));
        if let Some(category) = &notification.category {
            aps.insert("category".to_owned(), Value::String(category.clone()));
        }
        if let Some(thread_id) = &notification.thread_id {
            aps.insert("thread-id".to_owned(), Value::String(thread_id.clone()));
        }
        if let Some(badge) = notification.badge {
            aps.insert("badge".to_owned(), json!(badge));
        }
    }

    let mut root = Map::new();
    // The app's custom payload goes in first and the adapter's own keys are
    // written over it: last write wins, so `data` can carry an "aps" or a
    // "url" without either reaching the wire in place of the real one.
    if let Value::Object(data) = &notification.data {
        for (key, value) in data {
            root.insert(key.clone(), value.clone());
        }
    }
    // APNs has no click-target of its own, so the tap URL travels in the
    // custom payload, where the app reads it — the same key Web Push and FCM
    // use. The typed field wins over a "url" in `data`: it is the field the
    // port documents, and a caller that wants its own key can use another
    // name. With no `url` set, a "url" in `data` is left alone.
    if let Some(url) = &notification.url {
        root.insert("url".to_owned(), Value::String(url.clone()));
    }
    root.insert("aps".to_owned(), Value::Object(aps));
    Value::Object(root).to_string().into_bytes()
}

/// Reads the `reason` field from an APNs error body (`{"reason":"..."}`).
fn reason(body: &[u8]) -> Option<String> {
    serde_json::from_slice::<Value>(body)
        .ok()?
        .get("reason")?
        .as_str()
        .map(str::to_owned)
}

#[async_trait]
impl Push for Apns {
    async fn send(
        &self,
        to: &Recipient,
        notification: &Notification,
    ) -> Result<PushOutcome, PushError> {
        // One transport per adapter: a venture that also speaks FCM or Web
        // Push puts a `RoutingPush` in front (ADR 0015). This is decided
        // *before* configuration is: an unconfigured APNs adapter still does
        // not serve Web Push, and answering `NotConfigured` for an FCM
        // recipient would claim a transport it will never carry — a router
        // reading that answer would stop looking for the adapter that does.
        let Recipient::Apns { device_token } = to else {
            return Err(PushError::unsupported_recipient(to));
        };
        let live = match &self.inner {
            Inner::NotConfigured => return Ok(PushOutcome::NotConfigured),
            Inner::Live(live) => live,
        };
        if !is_wellformed_device_token(device_token) {
            return Err(PushError::Rejected("malformed device token".to_owned()));
        }

        let now_unix = live.clock.now().unix_timestamp();
        let jwt = live.provider_jwt();
        let url = format!(
            "https://{}/3/device/{}",
            live.host.authority(),
            device_token
        );
        let payload = build_payload(notification);

        let mut builder = Request::builder()
            .method("POST")
            .uri(&url)
            .header(AUTHORIZATION, format!("bearer {jwt}"))
            .header("apns-topic", &live.topic)
            .header(
                "apns-push-type",
                if notification.silent {
                    "background"
                } else {
                    "alert"
                },
            )
            .header(
                "apns-priority",
                priority_header(notification.priority, notification.silent),
            );
        if let Some(collapse_id) = &notification.collapse_id {
            builder = builder.header("apns-collapse-id", collapse_id);
        }
        if let Some(ttl) = notification.ttl {
            builder = builder.header("apns-expiration", expiration_header(ttl, now_unix));
        }
        let request = builder
            .body(Bytes::from(payload))
            .map_err(|err| PushError::Rejected(format!("could not build request: {err}")))?;

        let response = live
            .http
            .send(request)
            .await
            .map_err(|err| PushError::transient(err.to_string()))?;

        let status = response.status();
        match status {
            StatusCode::OK => {
                let id = response
                    .headers()
                    .get("apns-id")
                    .and_then(|value| value.to_str().ok())
                    .map(str::to_owned);
                Ok(PushOutcome::Delivered { id })
            }
            // The device token is no longer active: the caller deletes it.
            StatusCode::GONE => Err(PushError::Unregistered),
            _ => {
                let detail = reason(response.body()).unwrap_or_else(|| status.as_u16().to_string());
                // An expired/invalid provider token is our JWT, not the
                // request: drop the cache so the next send re-signs, and ask
                // the caller to retry.
                if status == StatusCode::FORBIDDEN
                    && (detail == "ExpiredProviderToken" || detail == "InvalidProviderToken")
                {
                    live.invalidate_jwt();
                    return Err(PushError::transient(format!(
                        "provider token rejected: {detail}"
                    )));
                }
                if status == StatusCode::TOO_MANY_REQUESTS || status.is_server_error() {
                    Err(PushError::transient_after(
                        format!("apns {}: {detail}", status.as_u16()),
                        cratefield_core::retry_after(response.headers(), live.clock.as_ref()),
                    ))
                } else {
                    Err(PushError::Rejected(format!(
                        "apns {}: {detail}",
                        status.as_u16()
                    )))
                }
            }
        }
    }
}
