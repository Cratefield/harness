//! The `Push` port (issue #104): a notification to a phone. Mail reaches an
//! inbox through [`Mailer`](crate::Mailer); nothing else reached a device until
//! this. APNs today (a booking confirmed, a room starting in ten minutes),
//! FCM later.
//!
//! The device-token registry is venture code — each venture decides what a
//! token belongs to — but the port defines the [`PushError::Unregistered`]
//! contract so a module knows when to prune a dead token.

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use thiserror::Error;

/// How urgently the notification should be delivered. Maps to APNs priority
/// `10` (deliver now, may wake the device) and `5` (deliver to save power).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Priority {
    /// Deliver immediately.
    #[default]
    Immediate,
    /// Deliver when convenient, to conserve power.
    Conserve,
}

/// One notification. `data` is the custom key-value payload the app reads;
/// `collapse_id` coalesces notifications the user has not seen yet.
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub collapse_id: Option<String>,
    #[serde(default)]
    pub priority: Priority,
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
    NotConfigured,
}

/// Push failures. `Unregistered` is separated because the caller must act on
/// it — the device token is dead and should be pruned — where the others are
/// transient or a bad request.
#[derive(Debug, Clone, Error)]
pub enum PushError {
    /// The provider says the token is no longer valid (APNs `410`): delete it.
    #[error("device token is no longer registered; delete it")]
    Unregistered,
    /// The provider rejected the request (a `4xx` that is not `410`); not
    /// retryable without a change.
    #[error("push rejected: {0}")]
    Rejected(String),
    /// A transient failure (a `5xx`, a transport error): retry later.
    #[error("push failed, retryable: {0}")]
    Transient(String),
}

/// Sends notifications to a device. APNs today, FCM later; both over the
/// runtime's `HttpClient`.
#[async_trait]
pub trait Push: Send + Sync {
    /// Sends `notification` to `device_token`.
    async fn send(
        &self,
        device_token: &str,
        notification: &Notification,
    ) -> Result<PushOutcome, PushError>;
}
