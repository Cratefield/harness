//! The kill switch: the one control that beats every other answer. `check`
//! consults it first and [`GuardedSigner::sign`](crate::GuardedSigner::sign)
//! consults it again, so a job holding an already-issued approval is stopped
//! at signing time, not merely at policy time.

use async_trait::async_trait;
use serde::{Deserialize, Serialize};

/// How wide a kill switch engagement reaches.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Scope {
    /// Everything this guardrails instance guards.
    Global,
    /// Every subject of one venture.
    Venture(String),
    /// One subject.
    Subject(String),
}

impl Scope {
    /// Stable string form, for keys, logs and audit entries.
    #[must_use]
    pub fn key(&self) -> String {
        match self {
            Scope::Global => "global".to_owned(),
            Scope::Venture(v) => format!("venture:{v}"),
            Scope::Subject(s) => format!("subject:{s}"),
        }
    }

    /// Every scope a decision for `venture` / `subject` is checked against,
    /// widest first.
    #[must_use]
    pub fn for_actor(venture: &str, subject: &str) -> [Scope; 3] {
        [
            Scope::Global,
            Scope::Venture(venture.to_owned()),
            Scope::Subject(subject.to_owned()),
        ]
    }
}

/// Why the kill switch could not answer or act.
#[derive(Debug, Clone, thiserror::Error)]
#[error("kill switch: {0}")]
pub struct KillSwitchError(pub String);

/// Where engagements live. Backed by durable state in production; the
/// in-memory fake in [`crate::fakes::MemoryKillSwitch`] exists for tests.
#[async_trait]
pub trait KillSwitch: Send + Sync {
    /// Whether the scope is engaged.
    ///
    /// # Errors
    ///
    /// When the backing state cannot be read; the engine treats an error as
    /// engaged — fail closed.
    async fn engaged(&self, scope: &Scope) -> Result<bool, KillSwitchError>;

    /// Engages the scope, recording why.
    ///
    /// # Errors
    ///
    /// When the engagement cannot be persisted.
    async fn engage(&self, scope: Scope, reason: &str) -> Result<(), KillSwitchError>;

    /// Releases the scope.
    ///
    /// # Errors
    ///
    /// When the release cannot be persisted.
    async fn release(&self, scope: &Scope) -> Result<(), KillSwitchError>;
}

/// The kill switch rendered as a Turnkey policy body, so the remote signer
/// refuses even if this process is bypassed, crashed or compromised: two
/// independent enforcement points, one intent.
///
/// The result is one policy entry with `"effect": "EFFECT_DENY"`. The global
/// scope denies unconditionally (`"true"`); a venture or subject scope denies
/// on a condition over `TRACING_TAGS`, which the adapter is responsible for
/// stamping onto the activity it creates. `None` means the scope's id is not
/// a plain `[A-Za-z0-9._:-]+` string — such an id would survive into the
/// condition unquoted and could rewrite it, so it is refused here rather
/// than escaped into a language this crate does not parse.
#[must_use]
pub fn turnkey_deny_policy(scope: &Scope) -> Option<serde_json::Value> {
    let plain = |id: &str| {
        !id.is_empty()
            && id
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b':' | b'-'))
    };
    let condition = match scope {
        Scope::Global => "true".to_owned(),
        Scope::Venture(v) if plain(v) => format!(r#"TRACING_TAGS.venture == "{v}""#),
        Scope::Subject(s) if plain(s) => format!(r#"TRACING_TAGS.subject == "{s}""#),
        _ => return None,
    };
    Some(serde_json::json!({ "effect": "EFFECT_DENY", "condition": condition }))
}
