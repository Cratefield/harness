//! What a caller hands [`notify`](crate::Notifier::notify): text it has
//! already written, or a message id the delivery renders per recipient
//! (issue #190).
//!
//! # Why the language is not chosen here
//!
//! Because the caller cannot know it. One account can have an English
//! browser and a Bahasa phone, so there is no single answer at the moment
//! a booking is confirmed — there is one answer per device, one for the
//! inbox and one for the mailbox, and three of them are not known until
//! the row is drained.
//!
//! So a caller names a message instead of writing one, and the drain
//! resolves the language against the subscription, then the account, then
//! the venture's default.
//!
//! # A venture with one language pays nothing
//!
//! [`Message::Rendered`] is today's path, unchanged: `notify` takes
//! `impl Into<Message>` and `Notification` converts, so every existing
//! call site compiles and behaves exactly as it did. No catalog is built,
//! no locale is read, and the notification reaches the device as written.

use cratefield_core::{LocKeys, Notification};
use cratefield_i18n::Args;
use serde::{Deserialize, Serialize};
use serde_json::Value;

/// What a notification says, and who decides.
#[derive(Debug, Clone, PartialEq)]
pub enum Message {
    /// Text the caller wrote. Delivered as given, in every channel, to
    /// every device — the path a single-language venture uses and the one
    /// that existed before localisation.
    Rendered(Box<Notification>),
    /// A message id in the venture's catalog, rendered per recipient at
    /// delivery.
    Localizable(Box<Localizable>),
}

impl From<Notification> for Message {
    fn from(notification: Notification) -> Self {
        Message::Rendered(Box::new(notification))
    }
}

impl From<Localizable> for Message {
    fn from(localizable: Localizable) -> Self {
        Message::Localizable(Box::new(localizable))
    }
}

/// A message named rather than written.
///
/// `key` is a Fluent message id whose attributes are `.title`, `.body` and
/// optionally `.subject` (mail only); `args` are its placeables.
///
/// Everything a [`Notification`] carries that is *not* language — the tap
/// target, the icon, the custom payload — is here too, because those do
/// not change with the recipient's locale.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Localizable {
    /// The catalog message id: `booking-confirmed`.
    pub key: String,
    /// Its placeables: `{ $coach }`, `{ $count }`.
    ///
    /// **Personal data.** A coach's name, a place, a reference — these are
    /// the caller's values about a person, so they belong in the message
    /// that is delivered and nowhere else. Nothing in this module puts one
    /// in a log, an event payload or an error.
    #[serde(default, skip_serializing_if = "Args::is_empty")]
    pub args: Args,
    /// Where a tap should take the recipient.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    /// The custom payload the app reads.
    #[serde(default, skip_serializing_if = "Value::is_null")]
    pub data: Value,
    /// An icon for the notification (Web Push).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub icon: Option<String>,
    /// A badge count, for a category that declared `badge(true)`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub badge: Option<u32>,
    /// Coalesces with an undelivered notification carrying the same id.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub collapse_id: Option<String>,
    /// The **app's own** localisation keys, for a category whose
    /// [`RenderMode`] is not [`RenderMode::Server`].
    ///
    /// These are not this catalog's ids: they name strings compiled into
    /// the iOS and Android apps, which only the app knows. The module
    /// cannot invent them, so a caller that wants native rendering passes
    /// them, and APNs and FCM get them alongside (or instead of) the
    /// server's text. Web Push has no such mechanism and never sees them.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub loc: Option<LocKeys>,
}

impl Localizable {
    /// A message naming `key`, with no arguments.
    #[must_use]
    pub fn new(key: impl Into<String>) -> Self {
        Self {
            key: key.into(),
            ..Self::default()
        }
    }

    /// Adds one placeable.
    ///
    /// A number must arrive as a number: Fluent selects the plural form
    /// from it, and `"2"` as a string selects `other` in every language —
    /// which reads correctly in English and wrongly in Polish.
    #[must_use]
    pub fn arg(mut self, name: impl Into<String>, value: impl Into<Value>) -> Self {
        self.args.insert(name.into(), value.into());
        self
    }

    /// Where a tap should take the recipient.
    #[must_use]
    pub fn url(mut self, url: impl Into<String>) -> Self {
        self.url = Some(url.into());
        self
    }

    /// The custom payload the app reads.
    #[must_use]
    pub fn data(mut self, data: Value) -> Self {
        self.data = data;
        self
    }

    /// An icon for the notification.
    #[must_use]
    pub fn icon(mut self, icon: impl Into<String>) -> Self {
        self.icon = Some(icon.into());
        self
    }

    /// A badge count, honoured only by a category that declared
    /// `badge(true)`.
    #[must_use]
    pub fn badge(mut self, badge: u32) -> Self {
        self.badge = Some(badge);
        self
    }

    /// Coalesces with an undelivered notification carrying the same id.
    #[must_use]
    pub fn collapse_id(mut self, id: impl Into<String>) -> Self {
        self.collapse_id = Some(id.into());
        self
    }

    /// The app's own localisation keys — see [`Localizable::loc`].
    #[must_use]
    pub fn loc(mut self, loc: LocKeys) -> Self {
        self.loc = Some(loc);
        self
    }

    /// The notification this message becomes once its title and body are
    /// rendered: everything that does not depend on the language, filled
    /// in from here.
    pub(crate) fn shape(&self, title: String, body: String) -> Notification {
        let mut notification = Notification::new(title, body);
        notification.url.clone_from(&self.url);
        notification.icon.clone_from(&self.icon);
        notification.data = self.data.clone();
        notification.badge = self.badge;
        notification.collapse_id.clone_from(&self.collapse_id);
        notification
    }
}

/// Who renders the strings a device shows, per category.
///
/// Only ever applies to a [`Message::Localizable`]. A caller that passes a
/// rendered `Notification` gets exactly what it wrote, `loc` included — the
/// native passthrough documented before this issue keeps working untouched.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RenderMode {
    /// The server renders, in the recipient's own language. The default,
    /// and the only thing a browser can be sent.
    #[default]
    Server,
    /// The app renders, from strings it ships. APNs and FCM get the
    /// caller's [`Localizable::loc`] keys, and the text beside them is the
    /// **venture's default locale** — a fallback for a device whose app is
    /// too old to have the key, nothing more.
    Native,
    /// Both: the app's keys *and* the server's text in the recipient's own
    /// language. The OS uses the app's strings where the key exists and
    /// falls back to ours where it does not.
    Both,
}

impl RenderMode {
    /// Whether a token transport should be sent the app's own keys.
    #[must_use]
    pub fn sends_loc_keys(self) -> bool {
        matches!(self, RenderMode::Native | RenderMode::Both)
    }

    /// Whether the text beside those keys is rendered in the recipient's
    /// language, or in the venture's default.
    #[must_use]
    pub fn renders_for_recipient(self) -> bool {
        matches!(self, RenderMode::Server | RenderMode::Both)
    }

    /// The name a report or a config value uses.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            RenderMode::Server => "server",
            RenderMode::Native => "native",
            RenderMode::Both => "both",
        }
    }
}

impl std::fmt::Display for RenderMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_rendered_notification_converts_without_the_caller_saying_so() {
        // The whole "a single-language venture pays nothing" claim, in one
        // line: `notify(.., notification)` keeps compiling.
        let message: Message = Notification::new("Booked", "See you Tuesday").into();
        match message {
            Message::Rendered(notification) => {
                assert_eq!(notification.title, "Booked");
            }
            Message::Localizable(_) => panic!("a Notification is rendered text"),
        }
    }

    #[test]
    fn the_builder_keeps_a_number_a_number() {
        let message = Localizable::new("booking-confirmed")
            .arg("count", 2)
            .arg("coach", "Sari");
        assert!(
            message.args["count"].is_number(),
            "a string never selects a plural category"
        );
        assert_eq!(message.args["coach"], "Sari");
    }

    #[test]
    fn a_payload_round_trips_and_omits_what_was_not_set() {
        let message = Localizable::new("booking-confirmed").arg("coach", "Sari");
        let json = serde_json::to_string(&message).expect("serialises");
        assert!(!json.contains("\"url\""), "{json}");
        assert!(!json.contains("\"loc\""), "{json}");
        let back: Localizable = serde_json::from_str(&json).expect("round trips");
        assert_eq!(back, message);
    }

    #[test]
    fn the_modes_say_what_each_one_does() {
        assert!(!RenderMode::Server.sends_loc_keys());
        assert!(RenderMode::Native.sends_loc_keys());
        assert!(RenderMode::Both.sends_loc_keys());
        assert!(RenderMode::Server.renders_for_recipient());
        assert!(
            !RenderMode::Native.renders_for_recipient(),
            "native means the app owns the language; the text is only a fallback"
        );
        assert!(RenderMode::Both.renders_for_recipient());
        assert_eq!(RenderMode::default(), RenderMode::Server);
    }

    #[test]
    fn the_shape_carries_everything_that_is_not_language() {
        let message = Localizable::new("booking-confirmed")
            .url("https://example.test/b/1")
            .icon("bell")
            .badge(3)
            .collapse_id("b-1")
            .data(serde_json::json!({ "booking_id": "b-1" }));
        let notification = message.shape("Booked".to_owned(), "Tuesday".to_owned());
        assert_eq!(notification.title, "Booked");
        assert_eq!(
            notification.url.as_deref(),
            Some("https://example.test/b/1")
        );
        assert_eq!(notification.icon.as_deref(), Some("bell"));
        assert_eq!(notification.badge, Some(3));
        assert_eq!(notification.collapse_id.as_deref(), Some("b-1"));
        assert_eq!(notification.data["booking_id"], "b-1");
    }
}
