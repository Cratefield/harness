//! External subject-data providers (issue #653): the data a venture holds
//! **outside** the harness — a warehouse, a CRM, another product's database —
//! reached over one signed HTTP contract.
//!
//! A provider answers three POSTs, each carrying the subject and a shared
//! request id and each signed with HMAC-SHA256 under a secret read from the
//! config port at call time:
//!
//! - `{url}/export` -> `{"sections":[{"name": str, "description"?: str, "data": any}]}`
//! - `{url}/erase/plan` -> `{"sections":[{"name": str, "action": "delete"|"anonymise"|"retain", "reason"?: str}]}`
//! - `{url}/erase/apply` -> any 2xx means applied
//!
//! Nothing a provider sends back reaches a caller: a failure is one of four
//! words ([`ProviderError`]), because an upstream's status text or body may
//! quote the subject's data, and an erasure receipt is not the place for it.

use cratefield_core::{Config, HttpClient, HttpError, HttpPolicy};
use hmac::{Hmac, KeyInit, Mac};
use http::header::CONTENT_TYPE;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::sync::Arc;
use std::time::Duration;

use crate::handlers::unix_now;

/// The header every provider call carries, under the in-repo signing idiom
/// (`module-webhooks` signs deliveries the same way, so one receiver-side
/// verifier covers both).
pub const SIGNATURE_HEADER: &str = "Cratefield-Signature";

/// The deadline for one provider call when the builder sets none; clamped to
/// the port ceiling at send time.
const DEFAULT_TIMEOUT: Duration = Duration::from_secs(10);

/// The response cap for one provider call when the builder sets none: a
/// section list about one subject, not a file download.
const DEFAULT_MAX_RESPONSE_BYTES: usize = 1024 * 1024;

/// Why a provider call did not succeed, in the four words a caller renders.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ProviderError {
    /// Transport failure, timeout, or a 5xx.
    Unavailable,
    /// A 4xx: the provider refused the call.
    Rejected,
    /// An oversize or malformed body, or a schema mismatch.
    InvalidResponse,
    /// No signing secret is configured.
    NotConfigured,
}

impl ProviderError {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::Unavailable => "unavailable",
            Self::Rejected => "rejected",
            Self::InvalidResponse => "invalid_response",
            Self::NotConfigured => "not_configured",
        }
    }
}

/// One external system holding data about a subject; built with
/// [`HttpProvider::new`] and registered with [`Privacy::provider`].
#[derive(Debug, Clone)]
pub struct HttpProvider {
    name: String,
    url: String,
    secret_env: Option<String>,
    timeout: Duration,
    max_response_bytes: usize,
}

impl HttpProvider {
    /// A provider named `name`, reached at `url`, whose `/export`,
    /// `/erase/plan` and `/erase/apply` paths are appended to `url`.
    #[must_use]
    pub fn new(name: impl Into<String>, url: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            url: url.into(),
            secret_env: None,
            timeout: DEFAULT_TIMEOUT,
            max_response_bytes: DEFAULT_MAX_RESPONSE_BYTES,
        }
    }

    /// The config/env variable holding this provider's HMAC secret, read
    /// through the config port at call time. None, missing or empty reports
    /// `not_configured` — a call this module cannot sign is not one it sends.
    #[must_use]
    pub fn secret_env(mut self, name: impl Into<String>) -> Self {
        self.secret_env = Some(name.into());
        self
    }

    /// The deadline for one call, clamped up to the port ceiling at send time.
    #[must_use]
    pub fn timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// The most bytes of a response this module will read, clamped to the
    /// port ceiling. A larger response is `invalid_response`.
    #[must_use]
    pub fn max_response_bytes(mut self, max_response_bytes: usize) -> Self {
        self.max_response_bytes = max_response_bytes;
        self
    }

    /// The provider's name, as a caller's response reports it.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// The signing secret, read from `config` now.
    pub(crate) fn secret(&self, config: &dyn Config) -> Result<String, ProviderError> {
        let name = self
            .secret_env
            .as_deref()
            .ok_or(ProviderError::NotConfigured)?;
        config
            .get(name)
            .filter(|secret| !secret.trim().is_empty())
            .ok_or(ProviderError::NotConfigured)
    }

    /// `POST {url}/export`, signed.
    pub(crate) async fn export(
        &self,
        http: &Arc<dyn HttpClient>,
        config: &dyn Config,
        subject: &str,
        request_id: &str,
    ) -> Result<Vec<Value>, ProviderError> {
        let secret = self.secret(config)?;
        let body = request_body(subject, request_id);
        let response = self.post(http, "export", &secret, &body).await?;
        provider_sections(response.body())
    }

    /// `POST {url}/erase/plan`, signed.
    pub(crate) async fn erase_plan(
        &self,
        http: &Arc<dyn HttpClient>,
        config: &dyn Config,
        subject: &str,
        request_id: &str,
    ) -> Result<Vec<Value>, ProviderError> {
        let secret = self.secret(config)?;
        let body = request_body(subject, request_id);
        let response = self.post(http, "erase/plan", &secret, &body).await?;
        plan_sections(response.body())
    }

    /// `POST {url}/erase/apply`, signed, with a secret already resolved (the
    /// retry path reuses this so it re-signs with a fresh timestamp).
    pub(crate) async fn apply_signed(
        &self,
        http: &Arc<dyn HttpClient>,
        secret: &str,
        body: &bytes::Bytes,
    ) -> Result<(), ProviderError> {
        self.post(http, "erase/apply", secret, body).await?;
        Ok(())
    }

    async fn post(
        &self,
        http: &Arc<dyn HttpClient>,
        path: &str,
        secret: &str,
        body: &bytes::Bytes,
    ) -> Result<http::Response<bytes::Bytes>, ProviderError> {
        let policy = HttpPolicy {
            max_response_bytes: self.max_response_bytes,
            timeout: self.timeout,
        }
        .clamped();
        let url = format!("{}/{path}", self.url.trim_end_matches('/'));
        let mut request = http::Request::builder()
            .method(http::Method::POST)
            .uri(&url)
            .header(CONTENT_TYPE, "application/json")
            .header(SIGNATURE_HEADER, signature_header(secret, unix_now(), body))
            .body(body.clone())
            .map_err(|_| ProviderError::Unavailable)?;
        request.extensions_mut().insert(policy);
        let response = http.send(request).await.map_err(|err| match err {
            // A body over the cap is a malformed answer, not an outage.
            HttpError::ResponseTooLarge { .. } => ProviderError::InvalidResponse,
            _ => ProviderError::Unavailable,
        })?;
        check_status(&response)?;
        // The runtime wraps `ports.http` in `BoundedHttpClient`, but this
        // module does not rely on the wrapper being there: an oversize body
        // is refused here too, before anything parses it.
        if response.body().len() > policy.max_response_bytes {
            return Err(ProviderError::InvalidResponse);
        }
        Ok(response)
    }
}

/// The shared body both sides sign.
pub(crate) fn request_body(subject: &str, request_id: &str) -> bytes::Bytes {
    bytes::Bytes::from(
        serde_json::to_vec(&json!({ "subject": subject, "request_id": request_id }))
            .expect("a JSON object serialises"),
    )
}

/// `t=<unix secs>,v1=<lowercase hex HMAC-SHA256(secret, "{t}.{body}")>` — the
/// layout `cratefield_core::StripeStyle` verifies.
fn signature_header(secret: &str, signed_at: u64, body: &[u8]) -> String {
    let mut mac =
        Hmac::<Sha256>::new_from_slice(secret.as_bytes()).expect("HMAC accepts any key length");
    mac.update(signed_at.to_string().as_bytes());
    mac.update(b".");
    mac.update(body);
    format!(
        "t={signed_at},v1={}",
        hex::encode(mac.finalize().into_bytes())
    )
}

/// 2xx is success; a 4xx is the provider refusing the call; anything else (a
/// 5xx, a stray 3xx) is an outage.
fn check_status(response: &http::Response<bytes::Bytes>) -> Result<(), ProviderError> {
    let status = response.status();
    if status.is_success() {
        Ok(())
    } else if status.is_client_error() {
        Err(ProviderError::Rejected)
    } else {
        Err(ProviderError::Unavailable)
    }
}

/// Each entry of a response's `sections` array, rendered by `render`.
fn sections(
    body: &[u8],
    render: impl Fn(&Value) -> Result<Value, ProviderError>,
) -> Result<Vec<Value>, ProviderError> {
    let value: Value = serde_json::from_slice(body).map_err(|_| ProviderError::InvalidResponse)?;
    let Value::Object(mut object) = value else {
        return Err(ProviderError::InvalidResponse);
    };
    let Some(Value::Array(sections)) = object.remove("sections") else {
        return Err(ProviderError::InvalidResponse);
    };
    sections.iter().map(render).collect()
}

/// An export response's sections: `{name, description?, data}`, rebuilt so no
/// unrequested field rides through to the caller.
fn provider_sections(body: &[u8]) -> Result<Vec<Value>, ProviderError> {
    sections(body, |section| {
        let name = section
            .get("name")
            .and_then(Value::as_str)
            .ok_or(ProviderError::InvalidResponse)?;
        let data = section.get("data").ok_or(ProviderError::InvalidResponse)?;
        let mut rendered = json!({ "name": name, "data": data });
        match section.get("description") {
            None => {}
            Some(Value::String(description)) => rendered["description"] = json!(description),
            Some(_) => return Err(ProviderError::InvalidResponse),
        }
        Ok(rendered)
    })
}

/// A plan response's sections: `{name, action, reason?}`, with `reason`
/// required when the action is `retain` — "we are keeping this" without a
/// reason is the one thing a subject is most entitled to.
fn plan_sections(body: &[u8]) -> Result<Vec<Value>, ProviderError> {
    sections(body, |section| {
        let name = section
            .get("name")
            .and_then(Value::as_str)
            .ok_or(ProviderError::InvalidResponse)?;
        match section.get("action").and_then(Value::as_str) {
            Some(action @ ("delete" | "anonymise")) => {
                Ok(json!({ "name": name, "action": action }))
            }
            Some("retain") => {
                let reason = section
                    .get("reason")
                    .and_then(Value::as_str)
                    .filter(|reason| !reason.is_empty())
                    .ok_or(ProviderError::InvalidResponse)?;
                Ok(json!({ "name": name, "action": "retain", "reason": reason }))
            }
            _ => Err(ProviderError::InvalidResponse),
        }
    })
}

/// The request id an erasure shares between plan, confirm and every retry,
/// derived from the confirm token so all three agree with no stored state.
pub(crate) fn erase_request_id(token: &str) -> String {
    format!("erase_{}", &digest_hex(token.as_bytes())[..32])
}

/// The request id one export carries, derived from the subject and the
/// moment it ran.
pub(crate) fn export_request_id(subject: &str, now: u64) -> String {
    let seed = format!("{subject}:{now}");
    format!("export_{}", &digest_hex(seed.as_bytes())[..32])
}

/// Lowercase hex of `SHA-256(bytes)`.
fn digest_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_signature_is_t_and_lowercase_hex_v1() {
        let header = signature_header("secret", 1_800_000_000, b"{}");
        let (t, sig) = header.split_once(",v1=").expect("t=…,v1=…");
        assert_eq!(t, "t=1800000000");
        assert_eq!(sig.len(), 64);
        assert!(
            sig.bytes()
                .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
        );
    }

    #[test]
    fn response_sections_are_validated_and_rebuilt() {
        // Malformed envelopes, an export section with no `data`, a non-string
        // description.
        for body in [
            b"not json".as_slice(),
            b"{}".as_slice(),
            br#"{"sections":[{"name":"a"}]}"#.as_slice(),
            br#"{"sections":[{"name":"a","data":1,"description":2}]}"#.as_slice(),
        ] {
            assert_eq!(provider_sections(body), Err(ProviderError::InvalidResponse));
        }
        // An unknown action, and a `retain` with no (or an empty) reason.
        for body in [
            br#"{"sections":[{"name":"x","action":"shred"}]}"#.as_slice(),
            br#"{"sections":[{"name":"invoices","action":"retain"}]}"#.as_slice(),
            br#"{"sections":[{"name":"invoices","action":"retain","reason":""}]}"#.as_slice(),
        ] {
            assert_eq!(plan_sections(body), Err(ProviderError::InvalidResponse));
        }

        // A valid plan renders action and reason, dropping unknown fields.
        let body = br#"{"sections":[
            {"name":"profile","action":"delete"},
            {"name":"invoices","action":"retain","reason":"Tax law."}
        ],"extra":"dropped"}"#;
        let sections = plan_sections(body).expect("valid");
        assert_eq!(sections[0], json!({"name":"profile","action":"delete"}));
        assert_eq!(
            sections[1],
            json!({"name":"invoices","action":"retain","reason":"Tax law."})
        );
    }
}
