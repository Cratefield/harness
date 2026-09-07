//! `cratefield-adapter-apns`: the [`Push`] port over Apple Push Notification
//! service (issue #104). Uses the runtime's [`HttpClient`] and [`Clock`] ports
//! — no vendor SDK, no `reqwest`, no `openssl` — so the same adapter runs on
//! Workers (`worker::Fetch`) and natively.
//!
//! **Authentication.** APNs takes a provider JWT signed ES256 with the `.p8`
//! key from the Apple developer portal. The token is minted once and reused:
//! Apple rejects regenerating it more than once per ~20 minutes
//! (`TooManyProviderTokenUpdates`) and accepts it for up to 60, so the adapter
//! caches it for [`JWT_TTL`] and re-mints past that. Signing is pure-Rust
//! P-256 ECDSA with a deterministic RFC6979 nonce, so it needs no RNG on the
//! isolate.
//!
//! **Degraded mode.** [`Apns::not_configured`] reports
//! [`PushOutcome::NotConfigured`] without any network call, the same contract
//! [`Resend`](cratefield_core::Mailer) uses when its key is absent, so a
//! venture with no APNs credentials still builds and runs.
//!
//! **Verification.** Signing and payload construction are unit-tested here,
//! but the live path against Apple's sandbox is `needs-human` (issue #104
//! acceptance): it needs a real `.p8`, a bundle id, and a device token, none
//! of which live in the repo.
#![doc = include_str!("../README.md")]
#![forbid(unsafe_code)]
// The JWT cache is not request state: it is the adapter's own provider token,
// shared across sends for its TTL (ADR 0007 allows a scoped, justified Mutex).
#![allow(clippy::disallowed_types)]

use std::sync::Arc;
use std::sync::Mutex;
use std::time::Duration;

use async_trait::async_trait;
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use bytes::Bytes;
use cratefield_core::{Clock, HttpClient, Notification, Priority, Push, PushError, PushOutcome};
use http::header::AUTHORIZATION;
use http::{Request, StatusCode};
use p256::ecdsa::SigningKey;
use p256::ecdsa::signature::Signer;
use p256::pkcs8::DecodePrivateKey;
use serde_json::{Map, Value, json};

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
    key: SigningKey,
    key_id: String,
    team_id: String,
    topic: String,
    host: ApnsHost,
    cache: Mutex<Option<CachedJwt>>,
}

struct CachedJwt {
    token: String,
    minted_unix: i64,
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
        let key = SigningKey::from_pkcs8_pem(&creds.key_p8_pem)
            .map_err(|err| ApnsConfigError::Key(err.to_string()))?;
        Ok(Self {
            inner: Inner::Live(Box::new(Live {
                http,
                clock,
                key,
                key_id: creds.key_id,
                team_id: creds.team_id,
                topic: creds.topic,
                host: creds.host,
                cache: Mutex::new(None),
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
    fn provider_jwt(&self, now_unix: i64) -> String {
        {
            let cache = self.cache.lock().expect("apns jwt cache");
            let ttl = i64::try_from(JWT_TTL.as_secs()).unwrap_or(i64::MAX);
            if let Some(cached) = cache.as_ref()
                && now_unix.saturating_sub(cached.minted_unix) < ttl
            {
                return cached.token.clone();
            }
        }
        let token = self.mint_jwt(now_unix);
        *self.cache.lock().expect("apns jwt cache") = Some(CachedJwt {
            token: token.clone(),
            minted_unix: now_unix,
        });
        token
    }

    /// Invalidates the cached JWT so the next send re-signs (used when APNs
    /// reports the token expired).
    fn invalidate_jwt(&self) {
        *self.cache.lock().expect("apns jwt cache") = None;
    }

    fn mint_jwt(&self, now_unix: i64) -> String {
        let header = json!({ "alg": "ES256", "kid": self.key_id });
        let payload = json!({ "iss": self.team_id, "iat": now_unix });
        let signing_input = format!(
            "{}.{}",
            URL_SAFE_NO_PAD.encode(header.to_string()),
            URL_SAFE_NO_PAD.encode(payload.to_string()),
        );
        // ES256: a fixed 64-byte r||s signature — exactly JWT's encoding.
        let signature: p256::ecdsa::Signature = self.key.sign(signing_input.as_bytes());
        let signature = URL_SAFE_NO_PAD.encode(signature.to_bytes());
        format!("{signing_input}.{signature}")
    }
}

/// The `apns-priority` header value for a [`Priority`].
fn priority_header(priority: Priority) -> &'static str {
    match priority {
        Priority::Immediate => "10",
        Priority::Conserve => "5",
    }
}

/// Builds the APNs JSON payload: an `aps` block from the notification, with the
/// caller's `data` merged in at the top level alongside it.
fn build_payload(notification: &Notification) -> Vec<u8> {
    let mut aps = Map::new();
    aps.insert(
        "alert".to_owned(),
        json!({ "title": notification.title, "body": notification.body }),
    );
    if let Some(category) = &notification.category {
        aps.insert("category".to_owned(), Value::String(category.clone()));
    }
    if let Some(thread_id) = &notification.thread_id {
        aps.insert("thread-id".to_owned(), Value::String(thread_id.clone()));
    }

    let mut root = Map::new();
    // Merge the app's custom payload first, then write `aps`, so a caller can
    // never clobber the `aps` block by putting an "aps" key in `data`.
    if let Value::Object(data) = &notification.data {
        for (key, value) in data {
            if key != "aps" {
                root.insert(key.clone(), value.clone());
            }
        }
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
        device_token: &str,
        notification: &Notification,
    ) -> Result<PushOutcome, PushError> {
        let live = match &self.inner {
            Inner::NotConfigured => return Ok(PushOutcome::NotConfigured),
            Inner::Live(live) => live,
        };

        let now_unix = live.clock.now().unix_timestamp();
        let jwt = live.provider_jwt(now_unix);
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
            .header("apns-push-type", "alert")
            .header("apns-priority", priority_header(notification.priority));
        if let Some(collapse_id) = &notification.collapse_id {
            builder = builder.header("apns-collapse-id", collapse_id);
        }
        let request = builder
            .body(Bytes::from(payload))
            .map_err(|err| PushError::Rejected(format!("could not build request: {err}")))?;

        let response = live
            .http
            .send(request)
            .await
            .map_err(|err| PushError::Transient(err.to_string()))?;

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
                    return Err(PushError::Transient(format!(
                        "provider token rejected: {detail}"
                    )));
                }
                if status.is_server_error() {
                    Err(PushError::Transient(format!(
                        "apns {}: {detail}",
                        status.as_u16()
                    )))
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
