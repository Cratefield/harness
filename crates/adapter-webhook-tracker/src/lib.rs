//! `cratefield-adapter-webhook-tracker`: the [`Tracker`] port over a
//! tenant-configured webhook (issue #432). It POSTs the ticket as a JSON
//! document signed with HMAC-SHA256, through the runtime's [`HttpClient`]
//! and [`Clock`] ports — no vendor SDK — so the same adapter runs on Workers
//! and natively (ADR 0002: the port lives in core, the vendor client here).
//!
//! **The URL is attacker-adjacent, so it is never fetched directly.** A
//! webhook destination comes from tenant config, which is exactly the kind
//! of value an SSRF rides in on. It goes out through the [`HttpClient`]
//! port, whose contract refuses non-`http(s)` schemes, userinfo, and
//! loopback, private, link-local and cloud-metadata destinations —
//! re-vetting every redirect hop — and reports a refusal as
//! [`HttpError::BlockedDestination`], which this adapter maps to
//! [`TrackerError::Rejected`]: a blocked destination is a config error, not
//! weather a retry fixes.
//!
//! **Idempotency is delegated.** A webhook cannot be searched the way the
//! sibling `cratefield-adapter-github-issues` searches a repository, so the
//! *receiver* dedupes on the draft's `idempotency_key`, which the payload
//! carries. There is no tracker-side id to learn back, so the [`Filed`]
//! this adapter returns reports the key as the id and `deduplicated: false`.

#![doc = include_str!("../README.md")]
#![forbid(unsafe_code)]

use async_trait::async_trait;
use bytes::Bytes;
use cratefield_core::{
    Clock, Destination, Filed, HttpClient, HttpError, TicketDraft, Tracker, TrackerError,
    retry_after,
};
use hmac::{Hmac, KeyInit, Mac};
use http::header::CONTENT_TYPE;
use http::{Request, StatusCode};
use sha2::Sha256;
use std::fmt::Write as _;
use std::sync::Arc;

/// The one header a delivery is verified by, Stripe-style:
/// `t=<unix seconds>,v1=<lowercase hex>`.
const SIGNATURE_HEADER: &str = "Cratefield-Signature";

/// `Tracker` over a tenant-configured webhook URL.
///
/// No `Debug` derive: the struct holds the shared signing secret, and a
/// derived `Debug` would print it wherever a log line or a panic message
/// met the adapter.
pub struct WebhookTracker {
    http: Arc<dyn HttpClient>,
    /// Stamps the payload and the signature. A constructor argument rather
    /// than a builder default so a deployment that forgets it fails to
    /// compile instead of silently signing with a different time than it
    /// serialised.
    clock: Arc<dyn Clock>,
    secret: String,
}

impl std::fmt::Debug for WebhookTracker {
    /// Never prints the signing secret.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WebhookTracker")
            .field("secret", &"[redacted]")
            // The http and clock ports are struct fields too; nothing about
            // either belongs in a log line.
            .finish_non_exhaustive()
    }
}

impl WebhookTracker {
    /// An adapter for one shared signing secret — the same secret the
    /// receiver verifies the `Cratefield-Signature` header with.
    pub fn new(
        http: Arc<dyn HttpClient>,
        clock: Arc<dyn Clock>,
        secret: impl Into<String>,
    ) -> Self {
        Self {
            http,
            clock,
            secret: secret.into(),
        }
    }

    /// Maps a receiver status onto the port's error taxonomy. The table is
    /// the issue's, the same one the GitHub Issues adapter applies:
    /// `401`/`403` say the shared secret is wrong; `404` and `422` say the
    /// endpoint is gone or refused the ticket itself — neither is fixed by
    /// retrying; `429` and the `5xx` family are the receiver having a
    /// moment. For the rest, the defensible rule is that a `4xx` is a fact
    /// about *our* request (`Rejected`) and nothing else is: a stray `3xx`
    /// a proxy produced is weather, not a verdict on the draft.
    fn map_status(
        status: StatusCode,
        body: &str,
        retry_after: Option<std::time::Duration>,
    ) -> TrackerError {
        let detail = match serde_json::from_str::<ErrorResponse>(body) {
            Ok(parsed) if !parsed.message.is_empty() => parsed.message,
            _ => body.to_string(),
        };
        match status {
            StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN => TrackerError::Unauthorized,
            StatusCode::NOT_FOUND | StatusCode::UNPROCESSABLE_ENTITY => {
                TrackerError::Rejected(format!("webhook {status}: {detail}"))
            }
            // `429` and the `5xx` family are the receiver having a moment:
            // retry, and not before `retry_after` where it named one.
            // (`retry_after` reads both header forms and answers `None` when
            // no header came, so a bare 500 stays unscheduled.)
            status if status.is_server_error() || status == StatusCode::TOO_MANY_REQUESTS => {
                TrackerError::transient_after(format!("webhook {status}: {detail}"), retry_after)
            }
            // The rest of the `4xx` family reads the same way as `404` and
            // `422`: a fact about our request, which a retry will not fix.
            status if status.is_client_error() => {
                TrackerError::Rejected(format!("webhook {status}: {detail}"))
            }
            // A stray `3xx` an unfollowing proxy produced is weather, not a
            // verdict on the draft.
            status => {
                TrackerError::transient_after(format!("webhook {status}: {detail}"), retry_after)
            }
        }
    }
}

#[async_trait]
impl Tracker for WebhookTracker {
    async fn file(&self, draft: &TicketDraft) -> Result<Filed, TrackerError> {
        let url = match &draft.destination {
            Destination::Webhook { url } => url,
            Destination::GitHubIssues { .. } => {
                return Err(TrackerError::Rejected(
                    "destination is GitHubIssues; this adapter files webhooks only".to_owned(),
                ));
            }
            // `#[non_exhaustive]`: a destination a later core adds is
            // refused here, named, rather than silently doing nothing.
            _ => {
                return Err(TrackerError::Rejected(
                    "this adapter files webhooks only".to_owned(),
                ));
            }
        };

        // One read of the clock stamps both the payload and the signature,
        // so the two cannot disagree. (`std::time::SystemTime` is not
        // available here: this adapter runs on Workers, and the `Clock`
        // port is the only timer it is allowed.)
        let signed_at = self.clock.now().unix_timestamp();
        let payload = TicketPayload {
            title: &draft.title,
            body: &draft.body,
            labels: &draft.labels,
            idempotency_key: &draft.idempotency_key,
            filed_at: signed_at,
        };
        // Built once: the exact bytes signed are the exact bytes sent. A
        // re-serialisation between signing and sending would be a gap a
        // verifier could fall into.
        let raw_body =
            serde_json::to_vec(&payload).map_err(|err| TrackerError::transient(err.to_string()))?;

        let request = Request::builder()
            .method(http::Method::POST)
            .uri(url.as_str())
            .header(CONTENT_TYPE, "application/json")
            .header(
                SIGNATURE_HEADER,
                signature_header(&self.secret, signed_at, &raw_body)?,
            )
            .body(Bytes::from(raw_body))
            .map_err(|err| TrackerError::transient(err.to_string()))?;
        let response = self.http.send(request).await.map_err(|err: HttpError| {
            match err {
                // The port's SSRF vetting refused the tenant-configured URL
                // (a scheme, userinfo, or a loopback / private / link-local /
                // metadata destination, re-vetted per redirect hop). That is
                // a config error, not weather: retrying will not fix it.
                HttpError::BlockedDestination(detail) => {
                    TrackerError::Rejected(format!("webhook destination refused: {detail}"))
                }
                // Any other transport failure is weather — retry.
                other => TrackerError::transient(other.to_string()),
            }
        })?;

        let status = response.status();
        if !status.is_success() {
            // One parser for both `Retry-After` forms (issue #214/#278); the
            // date form needs the clock this adapter is constructed with.
            let text = String::from_utf8_lossy(response.body()).to_string();
            let delay = retry_after(response.headers(), self.clock.as_ref());
            return Err(Self::map_status(status, &text, delay));
        }

        // A webhook answers "received", not "here is your ticket": there is
        // no tracker-side id to learn back, so the idempotency key *is* the
        // id, and `deduplicated` is `false` — whether the receiver created
        // the ticket or answered a repeat delivery from its own dedupe is
        // its knowledge, not ours.
        tracing::info!(
            provider = "webhook",
            outcome = "accepted",
            idempotency = %draft.idempotency_key,
            "tracker outcome"
        );
        Ok(Filed::created(draft.idempotency_key.clone(), None))
    }
}

/// The ticket as the webhook carries it: the draft's own fields, the
/// idempotency key the receiver dedupes on, and the filing timestamp the
/// signature binds.
#[derive(serde::Serialize)]
struct TicketPayload<'a> {
    title: &'a str,
    body: &'a str,
    labels: &'a [String],
    idempotency_key: &'a str,
    /// Unix seconds at filing — the same instant that stamps the
    /// `Cratefield-Signature` header.
    filed_at: i64,
}

/// Signs `body` at `signed_at` and renders the `Cratefield-Signature`
/// header value: `t=<unix seconds>,v1=<lowercase hex>`, Stripe-style, both
/// parts in one header.
///
/// The MAC is HMAC-SHA256 over the bytes `{signed_at}.{body}` — the
/// timestamp is bound INTO the signature, so a captured delivery cannot be
/// replayed with a fresh timestamp: the re-stamp invalidates the MAC. That
/// is the reason for this scheme over a separate, unsigned timestamp
/// header, which a replay would carry untouched.
fn signature_header(secret: &str, signed_at: i64, body: &[u8]) -> Result<String, TrackerError> {
    // HMAC-SHA256 over `{t}.{body}` — the in-repo idiom, as in the Stripe
    // adapter's own webhook verification.
    let mut mac = Hmac::<Sha256>::new_from_slice(secret.as_bytes())
        .map_err(|err| TrackerError::transient(err.to_string()))?;
    mac.update(signed_at.to_string().as_bytes());
    mac.update(b".");
    mac.update(body);
    let mac_hex = lower_hex(&mac.finalize().into_bytes());
    Ok(format!("t={signed_at},v1={mac_hex}"))
}

/// Lowercase hex, the case the Stripe-style verifiers expect.
fn lower_hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        // Writing to a String cannot fail.
        let _ = write!(out, "{byte:02x}");
    }
    out
}

#[derive(serde::Deserialize)]
struct ErrorResponse {
    #[serde(default)]
    message: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_signature_header_carries_a_bound_timestamp_and_lowercase_hex() {
        let header =
            signature_header("a test secret", 1_234, b"body bytes").expect("hmac accepts any key");
        assert!(header.starts_with("t=1234,v1="), "{header}");
        let hex = header.trim_start_matches("t=1234,v1=");
        assert_eq!(hex.len(), 64, "SHA-256 in hex: {header}");
        assert!(
            hex.chars()
                .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()),
            "the hex is lowercase: {header}"
        );
    }

    #[test]
    fn debug_of_the_adapter_redacts_the_secret() {
        let adapter = WebhookTracker::new(
            Arc::new(NoHttp),
            Arc::new(cratefield_core::SystemClock),
            "whsec_super_secret_signing_key",
        );
        let printed = format!("{adapter:?}");
        assert!(printed.contains("WebhookTracker"), "{printed}");
        assert!(
            !printed.contains("whsec_super_secret_signing_key"),
            "{printed}"
        );
        assert!(printed.contains("[redacted]"), "{printed}");
    }

    /// The transport is never reached by the `Debug` test above.
    struct NoHttp;

    #[async_trait]
    impl HttpClient for NoHttp {
        async fn send(&self, _request: Request<Bytes>) -> Result<http::Response<Bytes>, HttpError> {
            Err(HttpError::Transport("not used".to_owned()))
        }
    }
}
