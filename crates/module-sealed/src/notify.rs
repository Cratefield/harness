//! The "blob unlocked" notification: a small port, because a download is
//! worth telling the subject about and nothing else in the harness fires on
//! one.
//!
//! The port is deliberately narrow: one method, one notice. A notification
//! is best-effort by contract — the download route logs a failure and serves
//! the record anyway, because refusing to hand somebody their own ciphertext
//! because a mailer hiccuped would put the mailer in front of the data.

use async_trait::async_trait;
use thiserror::Error;

/// A download happened. `email` is the subject's **verified** address from
/// the `Auth` port; the caller sends a notice only when it has one, so
/// implementations may rely on it being present.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Notice {
    pub subject: String,
    pub email: String,
    pub blob_id: String,
    pub purpose: String,
}

/// Why a notice did not go out. The download does not care; this exists so a
/// caller that does (an operator dashboard) can log something actionable.
#[derive(Debug, Clone, Error)]
#[error("the unlock notice was not sent: {0}")]
pub struct NotifyError(pub String);

/// Fires on every download of one of the subject's blobs.
#[async_trait]
pub trait UnlockNotifier: Send + Sync {
    async fn blob_unlocked(&self, notice: &Notice) -> Result<(), NotifyError>;
}

/// The default: acknowledges everything, sends nothing. A venture that has
/// not wired a notifier still downloads.
#[derive(Debug, Default, Clone, Copy)]
pub struct NoopNotifier;

#[async_trait]
impl UnlockNotifier for NoopNotifier {
    async fn blob_unlocked(&self, _notice: &Notice) -> Result<(), NotifyError> {
        Ok(())
    }
}

/// Sends the notice through the harness `Mailer` port. `from` is the venture's
/// sending address; a mailer that reports
/// [`SendOutcome::NotConfigured`](cratefield_core::SendOutcome::NotConfigured) is
/// recorded as "nothing sent" rather than an error, which is what it is.
pub struct MailNotifier {
    mailer: std::sync::Arc<dyn cratefield_core::Mailer>,
    from: String,
}

impl MailNotifier {
    #[must_use]
    pub fn new(
        mailer: std::sync::Arc<dyn cratefield_core::Mailer>,
        from: impl Into<String>,
    ) -> Self {
        Self {
            mailer,
            from: from.into(),
        }
    }
}

#[async_trait]
impl UnlockNotifier for MailNotifier {
    async fn blob_unlocked(&self, notice: &Notice) -> Result<(), NotifyError> {
        let subject = format!("Your sealed blob \"{}\" was opened", notice.blob_id);
        let text = format!(
            "Your sealed blob `{}` (purpose `{}`) was downloaded. If this was you, \
             nothing to do; if it was not, rotate that blob's unlocks now.",
            notice.blob_id, notice.purpose
        );
        match self
            .mailer
            .send(cratefield_core::Message::new(
                notice.email.as_str(),
                self.from.as_str(),
                subject,
                text.clone(),
                format!(
                    "<p>{}</p>",
                    text.replace("rotate", "<strong>rotate</strong>")
                ),
            ))
            .await
        {
            Ok(
                cratefield_core::SendOutcome::Sent { .. }
                | cratefield_core::SendOutcome::NotConfigured,
            ) => Ok(()),
            Err(err) => Err(NotifyError(err.to_string())),
        }
    }
}

/// The recording fake the tests (and a venture's own) drive: every notice,
/// in order.
#[derive(Debug, Default, Clone)]
pub struct RecordingNotifier {
    // A recording fixture, not request state (ADR 0007) — the same scoped
    // `Mutex` allow the harness's own fakes carry.
    #[allow(clippy::disallowed_types)]
    recorded: std::sync::Arc<std::sync::Mutex<Vec<Notice>>>,
}

impl RecordingNotifier {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Every notice it accepted, in order.
    ///
    /// # Panics
    ///
    /// Only if the fixture mutex was poisoned, which no caller can cause —
    /// nothing a test does with a notice panics.
    #[must_use]
    pub fn recorded(&self) -> Vec<Notice> {
        self.recorded.lock().expect("uncontended").clone()
    }
}

#[async_trait]
impl UnlockNotifier for RecordingNotifier {
    async fn blob_unlocked(&self, notice: &Notice) -> Result<(), NotifyError> {
        self.recorded
            .lock()
            .expect("uncontended")
            .push(notice.clone());
        Ok(())
    }
}

/// The conformance every [`UnlockNotifier`] passes: it accepts a notice with
/// every field set, one with an address that is not a deliverable form, and
/// answers `Ok` for both — a notification is best-effort, so an
/// implementation whose happy path is an error has the contract backwards.
///
/// # Panics
///
/// With a message naming the property that failed.
pub async fn conformance(notifier: &dyn UnlockNotifier) {
    let notice = Notice {
        subject: "subject-a".into(),
        email: "a@example.test".into(),
        blob_id: "blob-1".into(),
        purpose: "vault".into(),
    };
    notifier
        .blob_unlocked(&notice)
        .await
        .expect("a notice with every field set is accepted");
    let odd = Notice {
        email: "not-an-address".into(),
        ..notice.clone()
    };
    notifier
        .blob_unlocked(&odd)
        .await
        .expect("address validation is the caller's job, not the notifier's");
}
