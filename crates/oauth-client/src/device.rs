//! Device authorization (RFC 8628): a client with no browser asks for a
//! `user_code`, the human types it at `verification_uri`, and the client
//! polls the token endpoint until the venture issues the credential.
//!
//! The credential the venture mints is its own business — a bearer token,
//! an API key, a session — so [`poll`] returns the raw JSON and leaves the
//! shape to the caller ([`poll_as`] when it has a type). Time comes from
//! the [`Clock`] port, never a timer of its own, so the loop runs unchanged
//! on Workers and native (RFC 8628 §3.5's `slow_down` included).

use bytes::Bytes;
use cratefield_core::{Clock, HttpClient, HttpError, timeout};
use http::{Method, Request, header};
use serde::Deserialize;
use std::time::Duration;
use thiserror::Error;

use crate::config::form_encode;

/// The device authorization endpoint's answer (RFC 8628 §3.2).
#[derive(Deserialize)]
pub struct DeviceAuthorization {
    /// The secret the client polls with; never printed by `Debug`.
    pub device_code: String,
    /// The short code the human types — meant to be shown, so it is not
    /// redacted.
    pub user_code: String,
    /// Where the human goes, e.g. `https://example.com/device`.
    pub verification_uri: String,
    /// The same URI with the code baked in, when the provider offers it.
    pub verification_uri_complete: Option<String>,
    /// How long the `device_code` stays valid, in seconds.
    pub expires_in: u64,
    /// Minimum seconds between polls; RFC 8628 §3.5 default of 5.
    #[serde(default = "default_interval")]
    pub interval: u64,
}

/// RFC 8628 §3.5: a missing `interval` means poll every five seconds.
fn default_interval() -> u64 {
    5
}

impl std::fmt::Debug for DeviceAuthorization {
    /// Device codes end up in logs; the human-facing fields may show, the
    /// `device_code` never does.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DeviceAuthorization")
            .field("device_code", &"<redacted>")
            .field("user_code", &self.user_code)
            .field("verification_uri", &self.verification_uri)
            .field("verification_uri_complete", &self.verification_uri_complete)
            .field("expires_in", &self.expires_in)
            .field("interval", &self.interval)
            .finish()
    }
}

/// What a device authorization call can end as.
#[derive(Debug, Error)]
pub enum DeviceFlowError {
    /// The network, or a port failure (cap, deadline, refused destination).
    #[error("transport: {0}")]
    Transport(#[from] HttpError),
    /// A success whose body was not the JSON the contract says.
    #[error("unexpected device response: {0}")]
    Decode(String),
    /// The human refused at `verification_uri` (RFC 8628 §3.5
    /// `access_denied`). Not retryable — the request is over.
    #[error("the user denied the device authorization")]
    Denied,
    /// The `device_code` expired before approval, or the deadline passed
    /// while polling.
    #[error("the device code expired before it was approved")]
    Expired,
    /// Any other RFC 6749 §5.2 refusal from the token endpoint.
    #[error("provider answered {error}: {description}")]
    OAuth {
        /// The `error` code, empty when the body was not JSON.
        error: String,
        /// The `error_description`, empty when absent.
        description: String,
    },
}

/// Asks the device authorization endpoint for a code (RFC 8628 §3.1):
/// `POST`s `client_id`, and `scope` / `name` when given, form-encoded.
///
/// # Errors
///
/// A refused send as [`DeviceFlowError::Transport`], a non-success answer
/// as [`DeviceFlowError::OAuth`], and an unparseable success body as
/// [`DeviceFlowError::Decode`].
pub async fn request_code(
    http: &dyn HttpClient,
    endpoint: &str,
    client_id: &str,
    scope: Option<&str>,
    name: Option<&str>,
) -> Result<DeviceAuthorization, DeviceFlowError> {
    let mut params = vec![("client_id", client_id)];
    if let Some(scope) = scope {
        params.push(("scope", scope));
    }
    if let Some(name) = name {
        params.push(("name", name));
    }
    let response = post(http, endpoint, &params).await?;
    if !response.status().is_success() {
        return Err(failure(&response));
    }
    serde_json::from_slice(response.body()).map_err(|err| {
        DeviceFlowError::Decode(format!("device authorization did not parse: {err}"))
    })
}

/// RFC 8628 §3.4: polls the token endpoint until the venture issues the
/// credential. Waits `interval` seconds between calls, honours `slow_down`
/// by adding five, and stops once the authorization's `expires_in` has
/// passed on `clock`.
///
/// The body is returned untyped because what the venture issues is the
/// venture's own contract — see [`poll_as`] to take it as a type.
///
/// # Errors
///
/// [`DeviceFlowError::Denied`] when the human refuses,
/// [`DeviceFlowError::Expired`] for `expired_token` or a passed deadline,
/// [`DeviceFlowError::OAuth`] for any other refusal, plus the transport
/// and decode failures.
pub async fn poll(
    http: &dyn HttpClient,
    clock: &dyn Clock,
    token_endpoint: &str,
    client_id: &str,
    authorization: &DeviceAuthorization,
) -> Result<serde_json::Value, DeviceFlowError> {
    let expires = i64::try_from(authorization.expires_in).unwrap_or(i64::MAX);
    let deadline = clock.now().unix_timestamp().saturating_add(expires);
    // Never busy-loop on a provider that sends `interval: 0`.
    let mut interval = authorization.interval.max(1);
    loop {
        if clock.now().unix_timestamp() >= deadline {
            return Err(DeviceFlowError::Expired);
        }
        sleep(clock, interval).await;
        let response = post(
            http,
            token_endpoint,
            &[
                ("grant_type", GRANT_TYPE),
                ("device_code", &authorization.device_code),
                ("client_id", client_id),
            ],
        )
        .await?;
        if response.status().is_success() {
            return serde_json::from_slice(response.body()).map_err(|err| {
                DeviceFlowError::Decode(format!("token response did not parse: {err}"))
            });
        }
        match failure(&response) {
            DeviceFlowError::OAuth { ref error, .. } if error == "authorization_pending" => {}
            DeviceFlowError::OAuth { ref error, .. } if error == "slow_down" => {
                interval += 5;
            }
            other => return Err(other),
        }
    }
}

/// [`poll`] for a caller that knows the credential's shape.
///
/// # Errors
///
/// Everything [`poll`] returns, and [`DeviceFlowError::Decode`] when the
/// body does not fit `T`.
pub async fn poll_as<T: serde::de::DeserializeOwned>(
    http: &dyn HttpClient,
    clock: &dyn Clock,
    token_endpoint: &str,
    client_id: &str,
    authorization: &DeviceAuthorization,
) -> Result<T, DeviceFlowError> {
    let value = poll(http, clock, token_endpoint, client_id, authorization).await?;
    serde_json::from_value(value)
        .map_err(|err| DeviceFlowError::Decode(format!("token response did not fit: {err}")))
}

/// RFC 8628 §3.4's grant type.
const GRANT_TYPE: &str = "urn:ietf:params:oauth:grant-type:device_code";

/// The form body, escaped the one way the crate escapes form bodies.
fn encode(params: &[(&str, &str)]) -> String {
    params
        .iter()
        .map(|(name, value)| format!("{name}={}", form_encode(value)))
        .collect::<Vec<_>>()
        .join("&")
}

async fn post(
    http: &dyn HttpClient,
    url: &str,
    params: &[(&str, &str)],
) -> Result<http::Response<Bytes>, DeviceFlowError> {
    let request = Request::builder()
        .method(Method::POST)
        .uri(url)
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .header(header::ACCEPT, "application/json")
        .body(Bytes::from(encode(params)))
        .map_err(|err| DeviceFlowError::Transport(HttpError::Transport(err.to_string())))?;
    Ok(http.send(request).await?)
}

/// Waits `interval` seconds on the caller's clock. The `Clock` port has no
/// `sleep`, so the port's own timeout races a future that never resolves:
/// `timeout` returns `None` exactly when the interval elapses, on native
/// (tokio) and Workers (`worker::Delay`) alike.
async fn sleep(clock: &dyn Clock, interval: u64) {
    let _ = timeout(
        clock,
        std::future::pending::<()>(),
        Duration::from_secs(interval),
    )
    .await;
}

/// Reads a refusal into the error the caller branches on. `access_denied`
/// and `expired_token` (RFC 8628 §3.5) become their own variants;
/// `authorization_pending` and `slow_down` stay in the `error` field
/// because [`poll`] is the only caller that treats them as progress, and
/// anything else (including a non-JSON body) is an [`DeviceFlowError::OAuth`].
fn failure(response: &http::Response<Bytes>) -> DeviceFlowError {
    let parsed = serde_json::from_slice::<ErrorBody>(response.body()).unwrap_or_default();
    let error = parsed.error.unwrap_or_default();
    match error.as_str() {
        "access_denied" => DeviceFlowError::Denied,
        "expired_token" => DeviceFlowError::Expired,
        _ => DeviceFlowError::OAuth {
            error,
            description: parsed.error_description.unwrap_or_default(),
        },
    }
}

#[derive(Default, Deserialize)]
struct ErrorBody {
    error: Option<String>,
    error_description: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use futures_core::future::BoxFuture;
    use std::any::Any;
    use std::sync::RwLock;

    const CODES: &str = r#"{"device_code":"dc-critical-do-not-log","user_code":"WDJB-MJHT",
        "verification_uri":"https://example.com/device",
        "verification_uri_complete":"https://example.com/device?user_code=WDJB-MJHT",
        "expires_in":600,"interval":5}"#;

    /// Answers sends from a script, in order, and keeps the requests so the
    /// form body a call actually sent can be read back.
    struct Scripted {
        replies: Vec<(u16, String)>,
        next: RwLock<usize>,
        seen: RwLock<Vec<Request<Bytes>>>,
    }

    impl Scripted {
        fn new(replies: Vec<(u16, &str)>) -> Self {
            Self {
                replies: replies
                    .into_iter()
                    .map(|(status, body)| (status, body.to_owned()))
                    .collect(),
                next: RwLock::new(0),
                seen: RwLock::new(Vec::new()),
            }
        }

        fn form_of(&self, index: usize) -> String {
            let seen = self.seen.read().expect("lock");
            String::from_utf8_lossy(seen[index].body()).into_owned()
        }
    }

    #[async_trait]
    impl HttpClient for Scripted {
        async fn send(&self, request: Request<Bytes>) -> Result<http::Response<Bytes>, HttpError> {
            let index = {
                let mut next = self.next.write().expect("lock");
                let index = *next;
                *next += 1;
                index
            };
            self.seen.write().expect("lock").push(request);
            let (status, body) = self.replies[index].clone();
            Ok(http::Response::builder()
                .status(status)
                .body(Bytes::from(body))
                .expect("body"))
        }
    }

    /// A clock that never really waits: every `timeout_any` records the
    /// interval, advances the wall clock by it, and reports the timeout —
    /// exactly the `None` that ends [`sleep`]'s pending future.
    struct FakeClock {
        now: RwLock<time::OffsetDateTime>,
        waits: RwLock<Vec<u64>>,
    }

    impl Default for FakeClock {
        fn default() -> Self {
            Self {
                now: RwLock::new(time::OffsetDateTime::UNIX_EPOCH),
                waits: RwLock::new(Vec::new()),
            }
        }
    }

    impl FakeClock {
        fn waits(&self) -> Vec<u64> {
            self.waits.read().expect("lock").clone()
        }
    }

    #[async_trait]
    impl Clock for FakeClock {
        fn now(&self) -> time::OffsetDateTime {
            *self.now.read().expect("lock")
        }

        async fn timeout_any(
            &self,
            _fut: BoxFuture<'static, Box<dyn Any + Send>>,
            after: Duration,
        ) -> Option<Box<dyn Any + Send>> {
            self.waits.write().expect("lock").push(after.as_secs());
            let seconds = i64::try_from(after.as_secs()).unwrap_or(i64::MAX);
            let mut now = self.now.write().expect("lock");
            *now += time::Duration::seconds(seconds);
            None
        }
    }

    fn authorization() -> DeviceAuthorization {
        serde_json::from_str(CODES).expect("the documented shape parses")
    }

    #[pollster::test]
    async fn request_code_sends_the_form_and_parses_the_answer() {
        let http = Scripted::new(vec![(200, CODES)]);
        let auth = request_code(
            &http,
            "https://api.example.com/v1/device/code",
            "client-1",
            Some("read write"),
            Some("Test Device"),
        )
        .await
        .expect("the endpoint answers");
        assert_eq!(auth.user_code, "WDJB-MJHT");
        assert_eq!(auth.interval, 5);
        let form = http.form_of(0);
        for piece in ["client_id=client-1", "scope=read+write", "name=Test+Device"] {
            assert!(form.contains(piece), "{piece:?} missing from {form}");
        }
    }

    /// RFC 8628 §3.1: `scope` and the extra parameters are optional; the
    /// required `client_id` is always there.
    #[pollster::test]
    async fn request_code_omits_absent_options() {
        let http = Scripted::new(vec![(200, CODES)]);
        request_code(
            &http,
            "https://api.example.com/device",
            "client-1",
            None,
            None,
        )
        .await
        .expect("parses");
        let form = http.form_of(0);
        assert_eq!(form, "client_id=client-1");
    }

    /// RFC 8628 §3.5: a missing `interval` means five seconds.
    #[pollster::test]
    async fn a_missing_interval_defaults_to_five() {
        let http = Scripted::new(vec![(
            200,
            r#"{"device_code":"dc","user_code":"UC","verification_uri":"https://x",
                "expires_in":60}"#,
        )]);
        let auth = request_code(&http, "https://x/device", "c", None, None)
            .await
            .expect("parses");
        assert_eq!(auth.interval, 5);
    }

    #[pollster::test]
    async fn pending_then_pending_then_success() {
        let http = Scripted::new(vec![
            (400, r#"{"error":"authorization_pending"}"#),
            (400, r#"{"error":"authorization_pending"}"#),
            (200, r#"{"api_key":"issued-once"}"#),
        ]);
        let clock = FakeClock::default();
        let token = poll(
            &http,
            &clock,
            "https://api.example.com/v1/device/token",
            "client-1",
            &authorization(),
        )
        .await
        .expect("the third poll is approved");
        assert_eq!(token["api_key"], "issued-once");
        assert_eq!(clock.waits(), vec![5, 5, 5]);
        let form = http.form_of(0);
        for piece in [
            "grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Adevice_code",
            "device_code=dc-critical-do-not-log",
            "client_id=client-1",
        ] {
            assert!(form.contains(piece), "{piece:?} missing from {form}");
        }
    }

    /// RFC 8628 §3.5: `slow_down` means add five seconds to every
    /// subsequent poll.
    #[pollster::test]
    async fn slow_down_stretches_the_interval_by_five() {
        let http = Scripted::new(vec![
            (400, r#"{"error":"authorization_pending"}"#),
            (400, r#"{"error":"slow_down"}"#),
            (200, r#"{"token":"t"}"#),
        ]);
        let clock = FakeClock::default();
        poll(&http, &clock, "https://x/token", "c", &authorization())
            .await
            .expect("approved");
        assert_eq!(clock.waits(), vec![5, 5, 10]);
    }

    #[pollster::test]
    async fn access_denied_ends_the_flow() {
        let http = Scripted::new(vec![(400, r#"{"error":"access_denied"}"#)]);
        let error = poll(
            &http,
            &FakeClock::default(),
            "https://x/token",
            "c",
            &authorization(),
        )
        .await
        .expect_err("denied");
        assert!(matches!(error, DeviceFlowError::Denied), "{error:?}");
    }

    #[pollster::test]
    async fn expired_token_ends_the_flow() {
        let http = Scripted::new(vec![(400, r#"{"error":"expired_token"}"#)]);
        let error = poll(
            &http,
            &FakeClock::default(),
            "https://x/token",
            "c",
            &authorization(),
        )
        .await
        .expect_err("expired");
        assert!(matches!(error, DeviceFlowError::Expired), "{error:?}");
    }

    /// The clock may pass the deadline before the provider ever answers
    /// `expired_token`; the wait must not outlive the authorization.
    #[pollster::test]
    async fn the_deadline_stops_a_still_pending_poll() {
        let http = Scripted::new(vec![
            (400, r#"{"error":"authorization_pending"}"#),
            (400, r#"{"error":"authorization_pending"}"#),
        ]);
        let clock = FakeClock::default();
        let auth = {
            let mut auth = authorization();
            auth.expires_in = 10;
            auth
        };
        let error = poll(&http, &clock, "https://x/token", "c", &auth)
            .await
            .expect_err("the deadline passes");
        assert!(matches!(error, DeviceFlowError::Expired), "{error:?}");
        assert_eq!(clock.waits(), vec![5, 5]);
    }

    #[pollster::test]
    async fn an_unknown_error_is_reported_verbatim() {
        let http = Scripted::new(vec![(
            400,
            r#"{"error":"invalid_client","error_description":"no such client"}"#,
        )]);
        let error = poll(
            &http,
            &FakeClock::default(),
            "https://x/token",
            "c",
            &authorization(),
        )
        .await
        .expect_err("refused");
        assert!(
            matches!(&error, DeviceFlowError::OAuth { error, description }
                if error == "invalid_client" && description == "no such client"),
            "{error:?}"
        );
    }

    #[pollster::test]
    async fn poll_as_reads_the_credential_into_a_type() {
        #[derive(Deserialize)]
        struct Credential {
            api_key: String,
        }
        let http = Scripted::new(vec![(200, r#"{"api_key":"issued-once"}"#)]);
        let credential: Credential = poll_as(
            &http,
            &FakeClock::default(),
            "https://x/token",
            "c",
            &authorization(),
        )
        .await
        .expect("fits");
        assert_eq!(credential.api_key, "issued-once");
    }

    /// The device code is the secret the poll carries; logs must not.
    #[test]
    fn the_debug_of_a_device_authorization_hides_the_device_code() {
        let debug = format!("{:?}", authorization());
        assert!(!debug.contains("dc-critical-do-not-log"), "{debug}");
        assert!(debug.contains("WDJB-MJHT"), "{debug}");
    }
}
