//! `cratefield-adapter-fcm`: the [`Push`] port over Firebase Cloud Messaging
//! (issue #179), on the **HTTP v1** API. Uses the runtime's [`HttpClient`]
//! and [`Clock`] ports — no Firebase Admin SDK (there is none for Rust and
//! none is needed), no `reqwest`, no OpenSSL — so the same adapter runs on
//! Workers (`worker::Fetch`) and natively.
//!
//! **Why v1 only.** Google shut the legacy `fcm/send` API down in June 2024.
//! `POST /v1/projects/{project_id}/messages:send` with an OAuth 2.0 bearer
//! token is the only supported server path, and it is plain HTTPS and JSON.
//!
//! **Recipients.** It serves [`Recipient::Fcm`] and returns
//! [`PushError::unsupported_recipient`] for APNs and Web Push. Google-free
//! Android is *not* this adapter: that is UnifiedPush, which the Web Push
//! adapter carries. A venture with more than one transport wires
//! [`RoutingPush`](cratefield_core::RoutingPush), which dispatches by variant
//! (ADR 0015).
//!
//! **Authentication.** A Google service account signs an RS256 assertion —
//! `{iss: client_email, scope: firebase.messaging, aud: token_uri, iat, exp}`
//! — and trades it at `oauth2.googleapis.com/token` for a bearer token good
//! for an hour. Signing is [`Rs256Signer`] and the token is held in a
//! [`CachedToken`], both from [`cratefield_push_auth`] (issue #178), so this
//! crate re-implements no JWT. The bearer token is cached for the lifetime
//! Google states less a five-minute safety margin, capped by
//! [`ACCESS_TOKEN_TTL`]. A `401 UNAUTHENTICATED` drops the cached token and
//! retries the send **once**, mirroring the APNs expired-provider-token path.
//!
//! **Degraded mode.** [`Fcm::not_configured`] reports
//! [`PushOutcome::NotConfigured`] without any network call, the same contract
//! [`Resend`](cratefield_core::Mailer) uses when its key is absent, so a
//! venture with no Firebase credentials still builds and runs. It answers
//! that only for the transport it serves: an APNs or Web Push recipient is
//! still [`PushError::unsupported_recipient`], configured or not.
//!
//! **Verification.** Token exchange, payload mapping and error mapping are
//! unit-tested here against a scripted [`HttpClient`]. The live path against
//! a real Firebase project and a real Android device is `needs-human`
//! (issue #186) and is **not** a blocker for merging this crate: it needs a
//! service-account key, a project and a handset, none of which live in the
//! repo.
#![doc = include_str!("../README.md")]
#![forbid(unsafe_code)]

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use bytes::Bytes;
use cratefield_core::{
    Clock, HttpClient, Notification, Priority, Push, PushError, PushOutcome, Recipient, ttl_secs,
};
use cratefield_push_auth::{CachedToken, Rs256Signer};
use http::header::{AUTHORIZATION, CONTENT_TYPE};
use http::{HeaderMap, Request, StatusCode};
use serde::Deserialize;
use serde_json::{Map, Value, json};

/// The ceiling on how long an exchanged bearer token is reused. Google issues
/// them for an hour; the adapter keeps `expires_in` less
/// [`EXPIRY_MARGIN`], and never longer than this, so a token is always
/// re-exchanged with minutes to spare.
#[allow(clippy::duration_suboptimal_units)] // `from_mins` is not const-stable on 1.98
pub const ACCESS_TOKEN_TTL: Duration = Duration::from_secs(3_300);

/// How far short of Google's stated expiry a token is retired, so a send that
/// starts just before the boundary cannot finish just after it.
#[allow(clippy::duration_suboptimal_units)] // `from_mins` is not const-stable on 1.98
pub const EXPIRY_MARGIN: Duration = Duration::from_secs(300);

/// How long the signed service-account assertion claims to be valid. Google's
/// documented maximum for the JWT-bearer grant is one hour; the assertion is
/// spent immediately on the token endpoint, so this is a bound, not a cache.
const ASSERTION_TTL_SECS: i64 = 3_600;

/// The OAuth scope FCM sends are authorised under.
const SCOPE: &str = "https://www.googleapis.com/auth/firebase.messaging";

/// The `grant_type` for RFC 7523's JWT-bearer flow.
const JWT_BEARER_GRANT: &str = "urn:ietf:params:oauth:grant-type:jwt-bearer";

/// Google's token endpoint, and the default when a service-account JSON does
/// not carry a `token_uri` of its own.
pub const DEFAULT_TOKEN_URI: &str = "https://oauth2.googleapis.com/token";

/// The FCM HTTP v1 host.
const FCM_BASE: &str = "https://fcm.googleapis.com";

// The `errorCode` values of `google.firebase.fcm.v1.FcmError`. Mapping keys
// off these rather than the HTTP status, because the status alone cannot tell
// a dead registration token (404 `UNREGISTERED`, prune it) from a project
// that does not exist (404, a configuration bug), nor a wrong-project token
// (403 `SENDER_ID_MISMATCH`) from a missing APNs credential
// (401 `THIRD_PARTY_AUTH_ERROR`).
const UNREGISTERED: &str = "UNREGISTERED";
const INVALID_ARGUMENT: &str = "INVALID_ARGUMENT";
const SENDER_ID_MISMATCH: &str = "SENDER_ID_MISMATCH";
const THIRD_PARTY_AUTH_ERROR: &str = "THIRD_PARTY_AUTH_ERROR";
/// The pre-rename spelling of [`THIRD_PARTY_AUTH_ERROR`]; Google still emits
/// it for some projects.
const APNS_AUTH_ERROR: &str = "APNS_AUTH_ERROR";
const QUOTA_EXCEEDED: &str = "QUOTA_EXCEEDED";
const UNAVAILABLE: &str = "UNAVAILABLE";
const INTERNAL: &str = "INTERNAL";

/// The credentials a venture reads from its secrets to reach FCM.
///
/// [`Self::from_service_account_json`] takes the file Firebase hands over
/// whole, which is the simplest thing for an operator to paste into a secret.
///
/// [`Debug`](#impl-Debug-for-FcmCredentials) is hand-written and never prints
/// the private key: core's log redaction keys off the *field name*
/// ([`is_secret_field`](cratefield_core::is_secret_field)) and cannot see
/// inside a `{:?}` of this struct.
#[derive(Clone)]
pub struct FcmCredentials {
    /// The service account's address (`…@….iam.gserviceaccount.com`), the
    /// assertion's `iss`.
    pub client_email: String,
    /// The service account's RSA private key, PEM. Google ships PKCS#8
    /// (`BEGIN PRIVATE KEY`); the legacy PKCS#1 form is accepted too.
    pub private_key_pem: String,
    /// The Firebase project id, which is the `{project_id}` in the send URL.
    pub project_id: String,
    /// Google's token endpoint. Comes from the service-account JSON's
    /// `token_uri`; [`DEFAULT_TOKEN_URI`] when it has none.
    pub token_uri: String,
}

impl FcmCredentials {
    /// Parses a Google service-account JSON file — the whole thing, as
    /// downloaded from the Firebase console.
    ///
    /// # Errors
    ///
    /// [`FcmConfigError::ServiceAccount`] if the JSON does not parse or is
    /// missing `client_email`, `private_key` or `project_id`.
    pub fn from_service_account_json(json: &str) -> Result<Self, FcmConfigError> {
        #[derive(Deserialize)]
        struct ServiceAccount {
            client_email: Option<String>,
            private_key: Option<String>,
            project_id: Option<String>,
            token_uri: Option<String>,
        }

        let account: ServiceAccount = serde_json::from_str(json)
            .map_err(|err| FcmConfigError::ServiceAccount(err.to_string()))?;
        let field = |name: &str, value: Option<String>| {
            value
                .filter(|value| !value.trim().is_empty())
                .ok_or_else(|| FcmConfigError::ServiceAccount(format!("missing \"{name}\"")))
        };
        Ok(Self {
            client_email: field("client_email", account.client_email)?,
            private_key_pem: field("private_key", account.private_key)?,
            project_id: field("project_id", account.project_id)?,
            token_uri: account
                .token_uri
                .filter(|uri| !uri.trim().is_empty())
                .unwrap_or_else(|| DEFAULT_TOKEN_URI.to_owned()),
        })
    }
}

impl std::fmt::Debug for FcmCredentials {
    /// Never prints the private key.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FcmCredentials")
            .field("client_email", &self.client_email)
            .field("private_key_pem", &"[redacted]")
            .field("project_id", &self.project_id)
            .field("token_uri", &self.token_uri)
            .finish()
    }
}

/// Google's token-endpoint reply. `expires_in` is defaulted rather than
/// required: a reply without it is still a usable token, it just gets no
/// cache lifetime and is exchanged again on the next send.
#[derive(Deserialize)]
struct TokenResponse {
    access_token: String,
    #[serde(default)]
    expires_in: u64,
}

/// Building an [`Fcm`] adapter failed.
#[derive(Debug, thiserror::Error)]
pub enum FcmConfigError {
    /// The service-account JSON did not parse, or a field was missing.
    #[error("invalid FCM service account: {0}")]
    ServiceAccount(String),
    /// `private_key` was not an RSA private key in either PEM form.
    #[error("invalid FCM service-account key: {0}")]
    Key(String),
    /// `project_id` is spliced into the send URL, so it has to be a project
    /// id and not a path.
    #[error("invalid FCM project id: {0}")]
    ProjectId(String),
    /// `token_uri` is where the service account's assertion — a bearer
    /// credential — is sent, so it must be HTTPS.
    #[error("invalid FCM token endpoint: {0}")]
    TokenUri(String),
}

/// [`Push`] over `POST https://fcm.googleapis.com/v1/projects/{id}/messages:send`.
pub struct Fcm {
    inner: Inner,
}

enum Inner {
    Live(Box<Live>),
    NotConfigured,
}

struct Live {
    http: Arc<dyn HttpClient>,
    clock: Arc<dyn Clock>,
    signer: Rs256Signer,
    client_email: String,
    token_uri: String,
    send_url: String,
    /// One bearer token for the whole adapter, hence the `()` key (VAPID is
    /// the variant that keys per push-service origin).
    token: CachedToken<()>,
}

impl Fcm {
    /// Builds a live adapter, parsing the private key up front so a malformed
    /// one is reported at construction rather than on the first send.
    ///
    /// # Errors
    ///
    /// - [`FcmConfigError::Key`] if `private_key_pem` is not an RSA private
    ///   key (PKCS#8 or PKCS#1 PEM).
    /// - [`FcmConfigError::ProjectId`] if the project id is empty or carries
    ///   anything but ASCII alphanumerics, `-` or `_`.
    /// - [`FcmConfigError::TokenUri`] if the token endpoint is not HTTPS.
    pub fn new(
        http: Arc<dyn HttpClient>,
        clock: Arc<dyn Clock>,
        creds: FcmCredentials,
    ) -> Result<Self, FcmConfigError> {
        if !is_wellformed_project_id(&creds.project_id) {
            return Err(FcmConfigError::ProjectId(format!(
                "{:?} is not a project id",
                creds.project_id
            )));
        }
        if !creds.token_uri.starts_with("https://") {
            return Err(FcmConfigError::TokenUri(format!(
                "{:?} is not https",
                creds.token_uri
            )));
        }
        let signer = Rs256Signer::from_pem(&creds.private_key_pem)
            .map_err(|err| FcmConfigError::Key(err.to_string()))?;
        Ok(Self {
            inner: Inner::Live(Box::new(Live {
                http,
                clock,
                signer,
                client_email: creds.client_email,
                token_uri: creds.token_uri,
                send_url: format!("{FCM_BASE}/v1/projects/{}/messages:send", creds.project_id),
                token: CachedToken::new(ACCESS_TOKEN_TTL),
            })),
        })
    }

    /// Builds a live adapter from a Google service-account JSON file.
    ///
    /// # Errors
    ///
    /// Everything [`Self::new`] returns, plus
    /// [`FcmConfigError::ServiceAccount`] when the JSON does not parse or is
    /// missing a field.
    pub fn from_service_account_json(
        http: Arc<dyn HttpClient>,
        clock: Arc<dyn Clock>,
        json: &str,
    ) -> Result<Self, FcmConfigError> {
        Self::new(
            http,
            clock,
            FcmCredentials::from_service_account_json(json)?,
        )
    }

    /// A degraded adapter that reports [`PushOutcome::NotConfigured`] without
    /// any network call — for a venture with no Firebase credentials set.
    #[must_use]
    pub fn not_configured() -> Self {
        Self {
            inner: Inner::NotConfigured,
        }
    }
}

impl std::fmt::Debug for Fcm {
    /// Names the endpoint it would post to and nothing else: no key, no
    /// bearer token, no service-account address.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self.inner {
            Inner::Live(live) => f
                .debug_struct("Fcm")
                .field("send_url", &live.send_url)
                .finish_non_exhaustive(),
            Inner::NotConfigured => f.write_str("Fcm::not_configured()"),
        }
    }
}

/// Whether a project id can be spliced into the request path as-is.
///
/// A Firebase project id is lowercase letters, digits and hyphens; a project
/// *number* is digits. Anything else — a `/`, a `..`, whitespace, a `%` — is
/// not an id, and interpolating it would silently retarget the request at
/// another project's endpoint (or fail far downstream as "could not build
/// request"). Underscore and uppercase are tolerated because emulator and
/// staging projects use them and neither can change the path's shape.
fn is_wellformed_project_id(id: &str) -> bool {
    !id.is_empty()
        && id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

impl Live {
    /// The current bearer token: the cached one while it lives, otherwise a
    /// fresh exchange at Google's token endpoint.
    ///
    /// The cache is read and written around the `await` rather than across it
    /// ([`CachedToken::cached`] / [`CachedToken::store`]): the exchange is an
    /// HTTP call and no lock may be held over one. Two sends racing a cold
    /// cache therefore cost one extra exchange — Google issues both tokens
    /// and either works, unlike Apple's once-per-20-minutes provider JWT,
    /// which is why *that* adapter mints under the lock instead.
    async fn access_token(&self) -> Result<String, PushError> {
        if let Some(token) = self.token.cached(self.clock.as_ref(), &()) {
            return Ok(token);
        }
        let (token, lifetime) = self.exchange().await?;
        self.token
            .store(self.clock.as_ref(), &(), token.clone(), lifetime);
        Ok(token)
    }

    /// Signs a service-account assertion and trades it for a bearer token,
    /// returning the token and how long it may be reused.
    async fn exchange(&self) -> Result<(String, Duration), PushError> {
        let now_unix = self.clock.now().unix_timestamp();
        let assertion = self.signer.sign_jwt(
            &json!({ "alg": "RS256", "typ": "JWT" }),
            &json!({
                "iss": self.client_email,
                "scope": SCOPE,
                "aud": self.token_uri,
                "iat": now_unix,
                "exp": now_unix.saturating_add(ASSERTION_TTL_SECS),
            }),
        );
        let form = serde_urlencoded::to_string([
            ("grant_type", JWT_BEARER_GRANT),
            ("assertion", assertion.as_str()),
        ])
        .map_err(|err| PushError::transient(format!("could not encode token request: {err}")))?;

        let request = Request::builder()
            .method("POST")
            .uri(&self.token_uri)
            .header(CONTENT_TYPE, "application/x-www-form-urlencoded")
            .body(Bytes::from(form))
            .map_err(|err| PushError::Rejected(format!("could not build token request: {err}")))?;
        let response = self
            .http
            .send(request)
            .await
            .map_err(|err| PushError::transient(err.to_string()))?;

        let status = response.status();
        if !status.is_success() {
            // Every failure here is the adapter's own credential, not the
            // caller's notification, so it is retryable the way an expired
            // APNs provider token is: clock skew and a briefly unavailable
            // token endpoint both land here, and a permanently broken key
            // shows up in the logs rather than by discarding the send.
            return Err(PushError::transient_after(
                format!(
                    "fcm token exchange {}: {}",
                    status.as_u16(),
                    oauth_error(response.body())
                ),
                retry_after(response.headers()),
            ));
        }

        let token: TokenResponse = serde_json::from_slice(response.body())
            .map_err(|err| PushError::transient(format!("unparseable token response: {err}")))?;
        if token.access_token.is_empty() {
            return Err(PushError::transient("token response carried no token"));
        }
        // Retire the token early: `expires_in` is when Google stops accepting
        // it, and a send that starts a second before that finishes after it.
        let lifetime = Duration::from_secs(token.expires_in).saturating_sub(EXPIRY_MARGIN);
        Ok((token.access_token, lifetime))
    }

    /// One `messages:send` attempt with the bearer token it is handed.
    async fn post_message(
        &self,
        token: &str,
        body: Bytes,
    ) -> Result<http::Response<Bytes>, PushError> {
        let request = Request::builder()
            .method("POST")
            .uri(&self.send_url)
            .header(AUTHORIZATION, format!("Bearer {token}"))
            .header(CONTENT_TYPE, "application/json")
            .body(body)
            .map_err(|err| PushError::Rejected(format!("could not build request: {err}")))?;
        self.http
            .send(request)
            .await
            .map_err(|err| PushError::transient(err.to_string()))
    }
}

/// `message.android.priority` for a [`Priority`].
///
/// Unlike APNs, FCM allows a high-priority data-only message — that is how an
/// Android app is woken — so `silent` does not force the value down.
fn priority_value(priority: Priority) -> &'static str {
    match priority {
        Priority::Immediate => "HIGH",
        Priority::Conserve => "NORMAL",
    }
}

/// Whether a value names something to fetch rather than something bundled.
///
/// `message.notification.image` is a URL the device downloads;
/// `android.notification.icon` is the name of a drawable resource *inside the
/// app*. The port has one `icon` field for both, so which one it means is
/// decided by whether it looks like a URL — putting a URL in `icon` shows no
/// icon at all, and a drawable name in `image` shows no image.
fn is_url(value: &str) -> bool {
    value.starts_with("https://") || value.starts_with("http://")
}

/// FCM data values must be **strings**. A caller's nested JSON is serialised
/// rather than dropped or rejected: `{"room": {"id": 42}}` travels as
/// `"{\"id\":42}"`, which the app parses back. A string is passed through as
/// itself, so `"42"` does not become `"\"42\""`.
fn data_value(value: &Value) -> String {
    match value {
        Value::String(text) => text.clone(),
        other => other.to_string(),
    }
}

/// The `message.data` map: the caller's `data` object with every value
/// stringified, plus `url` where the notification carries one.
fn build_data(notification: &Notification) -> Map<String, Value> {
    let mut data = Map::new();
    // A non-object `data` has no key-value shape to flatten, so there is
    // nothing to send; the same rule the APNs adapter applies when merging.
    if let Value::Object(object) = &notification.data {
        for (key, value) in object {
            data.insert(key.clone(), Value::String(data_value(value)));
        }
    }
    // `click_action` only exists on the notification block, which a silent
    // message does not have — so the tap target also travels in `data`, the
    // same key the APNs and Web Push adapters use. The typed field wins over
    // a "url" in `data`: it is the field the port documents.
    if let Some(url) = &notification.url {
        data.insert("url".to_owned(), Value::String(url.clone()));
    }
    data
}

/// `message.android.notification`: the fields that describe how Android shows
/// an alert. Absent entirely on a silent message.
fn build_android_notification(notification: &Notification) -> Map<String, Value> {
    let mut block = Map::new();
    if let Some(category) = &notification.category {
        // FCM's channel_id is the Android notification channel, which is what
        // a category names on this platform.
        block.insert("channel_id".to_owned(), json!(category));
    }
    if let Some(thread_id) = &notification.thread_id {
        block.insert("tag".to_owned(), json!(thread_id));
    }
    if let Some(url) = &notification.url {
        block.insert("click_action".to_owned(), json!(url));
    }
    if let Some(icon) = notification.icon.as_deref().filter(|icon| !is_url(icon)) {
        block.insert("icon".to_owned(), json!(icon));
    }
    if let Some(loc) = &notification.loc {
        // `*_loc_args` are the substitutions for a `*_loc_key`, so each list
        // is nested inside its key's arm: args without a key substitute into
        // nothing and FCM defines no meaning for them.
        if let Some(key) = &loc.title_loc_key {
            block.insert("title_loc_key".to_owned(), json!(key));
            if !loc.title_loc_args.is_empty() {
                block.insert("title_loc_args".to_owned(), json!(loc.title_loc_args));
            }
        }
        if let Some(key) = &loc.body_loc_key {
            block.insert("body_loc_key".to_owned(), json!(key));
            if !loc.body_loc_args.is_empty() {
                block.insert("body_loc_args".to_owned(), json!(loc.body_loc_args));
            }
        }
    }
    block
}

/// The whole `{"message": {…}}` request body.
///
/// A silent notification is a **data-only** message: no `notification` block
/// and no `android.notification` block, which is what stops Android from
/// displaying anything and delivers the payload to the app instead.
fn build_message(registration_token: &str, notification: &Notification) -> Value {
    let mut message = Map::new();
    message.insert("token".to_owned(), json!(registration_token));

    if !notification.silent {
        let mut visible = Map::new();
        visible.insert("title".to_owned(), json!(notification.title));
        visible.insert("body".to_owned(), json!(notification.body));
        if let Some(image) = notification.icon.as_deref().filter(|icon| is_url(icon)) {
            visible.insert("image".to_owned(), json!(image));
        }
        message.insert("notification".to_owned(), Value::Object(visible));
    }

    let mut android = Map::new();
    android.insert(
        "priority".to_owned(),
        json!(priority_value(notification.priority)),
    );
    if let Some(ttl) = notification.ttl {
        // FCM writes a TTL as a duration string, unlike the absolute epoch
        // APNs takes. A sub-second TTL rounds up to one second through
        // `ttl_secs` rather than truncating to `0s`, which would mean the
        // opposite ("deliver now or drop").
        android.insert("ttl".to_owned(), json!(format!("{}s", ttl_secs(ttl))));
    }
    if let Some(collapse_id) = &notification.collapse_id {
        android.insert("collapse_key".to_owned(), json!(collapse_id));
    }
    if !notification.silent {
        let block = build_android_notification(notification);
        if !block.is_empty() {
            android.insert("notification".to_owned(), Value::Object(block));
        }
    }
    message.insert("android".to_owned(), Value::Object(android));

    let data = build_data(notification);
    if !data.is_empty() {
        message.insert("data".to_owned(), Value::Object(data));
    }

    json!({ "message": Value::Object(message) })
}

/// The `errorCode` of the `google.firebase.fcm.v1.FcmError` detail, which is
/// the only field in an FCM error body that identifies the failure precisely.
fn fcm_error_code(body: &[u8]) -> Option<String> {
    let value: Value = serde_json::from_slice(body).ok()?;
    value
        .get("error")?
        .get("details")?
        .as_array()?
        .iter()
        .find_map(|detail| detail.get("errorCode")?.as_str().map(str::to_owned))
}

/// A human-readable detail for an FCM error body: the `errorCode` where there
/// is one, else `error.status`, else `error.message`.
fn fcm_detail(body: &[u8], code: Option<&str>) -> String {
    if let Some(code) = code {
        return code.to_owned();
    }
    let Ok(value) = serde_json::from_slice::<Value>(body) else {
        return "no error detail".to_owned();
    };
    let Some(error) = value.get("error") else {
        return "no error detail".to_owned();
    };
    error
        .get("status")
        .and_then(Value::as_str)
        .or_else(|| error.get("message").and_then(Value::as_str))
        .unwrap_or("no error detail")
        .to_owned()
}

/// The `error`/`error_description` of an OAuth 2.0 error body (RFC 6749
/// §5.2), which is what the token endpoint returns rather than an FCM error.
fn oauth_error(body: &[u8]) -> String {
    let Ok(value) = serde_json::from_slice::<Value>(body) else {
        return "no error detail".to_owned();
    };
    let code = value.get("error").and_then(Value::as_str);
    let description = value.get("error_description").and_then(Value::as_str);
    match (code, description) {
        (Some(code), Some(description)) => format!("{code}: {description}"),
        (Some(code), None) => code.to_owned(),
        (None, Some(description)) => description.to_owned(),
        (None, None) => "no error detail".to_owned(),
    }
}

/// `Retry-After` as a duration, so the outbox can honour it. Only the
/// delta-seconds form is read; the HTTP-date form needs a parsed clock the
/// port does not promise, and its absence just means "retry on your own
/// schedule".
fn retry_after(headers: &HeaderMap) -> Option<Duration> {
    headers
        .get("retry-after")?
        .to_str()
        .ok()?
        .trim()
        .parse::<u64>()
        .ok()
        .map(Duration::from_secs)
}

/// Maps an FCM failure to the port's error.
///
/// The `errorCode` decides where there is one, because the HTTP status alone
/// is ambiguous: a `404` is `UNREGISTERED` (prune the token) *or* a project
/// that does not exist (a configuration bug), and `THIRD_PARTY_AUTH_ERROR` —
/// the missing-APNs-credential case, which is a rejection and not an auth
/// failure of ours — arrives as a `401`. Status is the fallback for a body
/// with no recognisable detail, which is what a proxy or an outage returns.
fn map_error(
    status: StatusCode,
    code: Option<&str>,
    detail: &str,
    retry_after: Option<Duration>,
) -> PushError {
    let message = format!("fcm {}: {detail}", status.as_u16());
    match code {
        Some(UNREGISTERED) => PushError::Unregistered,
        Some(INVALID_ARGUMENT | SENDER_ID_MISMATCH | THIRD_PARTY_AUTH_ERROR | APNS_AUTH_ERROR) => {
            PushError::Rejected(message)
        }
        Some(QUOTA_EXCEEDED | UNAVAILABLE | INTERNAL) => {
            PushError::transient_after(message, retry_after)
        }
        // UNSPECIFIED_ERROR, anything Google adds later, and a body with no
        // recognisable detail at all: the status is what is left.
        _ => map_by_status(status, &message, retry_after),
    }
}

/// The fallback mapping, on HTTP status alone.
fn map_by_status(status: StatusCode, message: &str, retry_after: Option<Duration>) -> PushError {
    if status == StatusCode::NOT_FOUND {
        // v1 answers a registration token it does not know with a plain 404.
        return PushError::Unregistered;
    }
    if status == StatusCode::TOO_MANY_REQUESTS || status.is_server_error() {
        return PushError::transient_after(message.to_owned(), retry_after);
    }
    PushError::Rejected(message.to_owned())
}

#[async_trait]
impl Push for Fcm {
    async fn send(
        &self,
        to: &Recipient,
        notification: &Notification,
    ) -> Result<PushOutcome, PushError> {
        // One transport per adapter: a venture that also speaks APNs or Web
        // Push puts a `RoutingPush` in front (ADR 0015). This is decided
        // *before* configuration is: an unconfigured FCM adapter still does
        // not serve Web Push, and answering `NotConfigured` for a Web Push
        // recipient would claim a transport it will never carry — a router
        // reading that answer would stop looking for the adapter that does.
        let Recipient::Fcm { registration_token } = to else {
            return Err(PushError::unsupported_recipient(to));
        };
        let live = match &self.inner {
            Inner::NotConfigured => return Ok(PushOutcome::NotConfigured),
            Inner::Live(live) => live,
        };
        if registration_token.trim().is_empty() {
            return Err(PushError::Rejected(
                "malformed registration token".to_owned(),
            ));
        }

        let body = Bytes::from(build_message(registration_token, notification).to_string());

        // At most two attempts, and the second only after a 401 that says our
        // bearer token — not the caller's request — is the problem.
        let mut reauthenticated = false;
        loop {
            let token = live.access_token().await?;
            let response = live.post_message(&token, body.clone()).await?;
            let status = response.status();

            if status.is_success() {
                // `{"name": "projects/{id}/messages/{message_id}"}`.
                let id = serde_json::from_slice::<Value>(response.body())
                    .ok()
                    .and_then(|value| value.get("name")?.as_str().map(str::to_owned));
                return Ok(PushOutcome::Delivered { id });
            }

            let code = fcm_error_code(response.body());
            // `THIRD_PARTY_AUTH_ERROR` is also a 401, and re-minting our own
            // token cannot fix a missing APNs key in the Firebase project —
            // so it is excluded here and rejected below.
            let ours = status == StatusCode::UNAUTHORIZED
                && !matches!(
                    code.as_deref(),
                    Some(THIRD_PARTY_AUTH_ERROR | APNS_AUTH_ERROR)
                );
            if ours && !reauthenticated {
                tracing::debug!("fcm rejected the bearer token; re-exchanging and retrying once");
                live.token.invalidate(&());
                reauthenticated = true;
                continue;
            }

            let detail = fcm_detail(response.body(), code.as_deref());
            let retry_after = retry_after(response.headers());
            if ours {
                // A freshly exchanged token was refused too. Retryable, like
                // the APNs expired-provider-token path: clock skew and a
                // key mid-rotation both land here, and an outbox backing off
                // is a better answer than discarding the notification.
                return Err(PushError::transient_after(
                    format!("fcm 401: {detail} (a freshly exchanged token was refused)"),
                    retry_after,
                ));
            }
            return Err(map_error(status, code.as_deref(), &detail, retry_after));
        }
    }
}
