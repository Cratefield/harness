//! Telegram's inbound webhooks: verify the delivery, then parse it. The
//! inbound sibling of [`HttpTelegramBot`](crate::HttpTelegramBot), which
//! sends.
//!
//! **Verify first, parse second — always.** [`parse_verified`] compares the
//! `X-Telegram-Bot-Api-Secret-Token` header against the configured secret
//! over the **raw body bytes** before any JSON is read, and returns
//! [`WebhookError::Unverified`] without touching them when it does not
//! match. Parsing first and verifying after is the vulnerability this shape
//! exists to prevent. The check is core's [`WebhookVerifier`] under the
//! [`SharedTokenScheme`] — the header carries the secret itself, so the
//! comparison is constant-time and nothing is hashed.
//!
//! **Deduplicate on [`Update::update_id`](crate::Update::update_id).** A
//! shared token proves the sender, but it signs nothing: a captured
//! delivery replays forever. Telegram redelivers, so claim each
//! `update_id` through a dedup ledger ([`Inbox`](cratefield_core::Inbox))
//! before acting on it.
//!
//! ```
//! use cratefield_adapter_telegram::webhook::{parse_verified, SECRET_HEADER};
//! use http::HeaderMap;
//!
//! let mut headers = HeaderMap::new();
//! headers.insert(SECRET_HEADER, "cratefield-secret-1".parse().unwrap());
//! // The right token but a body no update could ever parse: verification
//! // passes, parsing fails — which is why the two errors are distinct.
//! let parsed = parse_verified("cratefield-secret-1", &headers, b"not json", 0);
//! assert!(matches!(parsed, Err(cratefield_adapter_telegram::webhook::WebhookError::Malformed)));
//! ```

use cratefield_core::{SharedTokenScheme, WebhookVerifier};
use http::HeaderMap;

use crate::update::{Update, parse_update};

/// The header Telegram stamps every webhook delivery with, carrying the
/// secret `set_webhook` registered: `X-Telegram-Bot-Api-Secret-Token`.
pub const SECRET_HEADER: &str = "X-Telegram-Bot-Api-Secret-Token";

/// The webhook verifier: a [`SharedTokenScheme`] reading
/// [`SECRET_HEADER`]. Built fresh per check — it holds only the scheme,
/// and the scheme is a const-compatible struct.
#[must_use]
pub fn verifier() -> WebhookVerifier {
    WebhookVerifier::new(SharedTokenScheme {
        header: SECRET_HEADER,
    })
}

/// Whether `secret` is a secret Telegram would have accepted at
/// `setWebhook`: 1–256 characters of `A-Z a-z 0-9 _ -`. A configuration
/// check — run it where the secret is set, so a bad one fails there
/// instead of silently refusing every delivery later.
#[must_use]
pub fn is_valid_secret(secret: &str) -> bool {
    (1..=256).contains(&secret.len())
        && secret
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
}

/// Why a delivery was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WebhookError {
    /// The secret header was missing or did not match. The body was not
    /// parsed, so this says nothing about its content.
    Unverified,
    /// The delivery verified but is not a well-formed update. Carries
    /// nothing: the body was tampered with, so quoting it back would quote
    /// attacker-chosen bytes.
    Malformed,
}

impl std::fmt::Display for WebhookError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unverified => f.write_str("telegram webhook secret did not verify"),
            Self::Malformed => f.write_str("malformed telegram webhook body"),
        }
    }
}

impl std::error::Error for WebhookError {}

/// Verifies `body` against `headers`, then parses it. `now_unix` is the
/// current Unix time, which a shared-token scheme does not use but the
/// verifier's signature asks for — pass `clock.now().unix_timestamp()`.
///
/// # Errors
///
/// [`WebhookError::Unverified`] if verification fails — returned before
/// the body is read, so an unverified delivery is never parsed. Otherwise
/// [`WebhookError::Malformed`] if the verified body is not a well-formed
/// update.
pub fn parse_verified(
    secret: &str,
    headers: &HeaderMap,
    body: &[u8],
    now_unix: i64,
) -> Result<Update, WebhookError> {
    if !verifier().verify(secret, headers, body, now_unix) {
        return Err(WebhookError::Unverified);
    }
    parse_update(body).map_err(|_| WebhookError::Malformed)
}
