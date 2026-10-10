//! The inbound half: one webhook delivery body, parsed into a typed
//! [`Update`]. The twin of [`client`](crate::client), which sends.
//!
//! Telegram counts entity offsets and lengths in **UTF-16 code units**, not
//! bytes and not characters, so a link sliced out of a text that opens with
//! an emoji lands two units further along than a naive `char_indices` walk
//! would place it. Everything here slices through `encode_utf16` and
//! decodes the slice back.
//!
//! Unknown fields are ignored: the wire grows, this struct does not have
//! to.

use serde::Deserialize;

/// Parses one delivery body into an [`Update`].
///
/// # Errors
///
/// [`UpdateError::Malformed`] when the body is not JSON or does not carry
/// the fields every update has (`update_id`, and one of the known
/// payloads). A message this crate does not know the shape of is never an
/// error — it is [`UpdateKind::Other`].
pub fn parse_update(body: &[u8]) -> Result<Update, UpdateError> {
    let raw: RawUpdate =
        serde_json::from_slice(body).map_err(|error| UpdateError::Malformed(error.to_string()))?;
    let kind = if let Some(callback) = raw.callback_query {
        UpdateKind::CallbackQuery(build_callback(callback))
    } else if let Some(post) = raw.channel_post {
        UpdateKind::ChannelPost(ChannelPost {
            message: build_message(post),
            edited: false,
        })
    } else if let Some(post) = raw.edited_channel_post {
        UpdateKind::ChannelPost(ChannelPost {
            message: build_message(post),
            edited: true,
        })
    } else if let Some(message) = raw.message {
        as_command_or_message(message)
    } else {
        // `edited_message` and every payload this crate does not model.
        UpdateKind::Other
    };
    Ok(Update {
        update_id: raw.update_id,
        kind,
    })
}

/// Why a body could not be read.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum UpdateError {
    /// The body is not JSON, or not an update shape. Carries the serde
    /// message only — never the body itself.
    Malformed(String),
}

impl std::fmt::Display for UpdateError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Malformed(detail) => write!(f, "malformed telegram update body: {detail}"),
        }
    }
}

impl std::error::Error for UpdateError {}

/// One delivery: its id — the dedup key against Telegram's at-least-once
/// redelivery — and what it carries.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Update {
    /// Telegram's monotonically increasing delivery id. Claim it through a
    /// dedup ledger (`cratefield_core::Inbox`) before acting: the
    /// secret-token webhook proves the sender but nothing stops a replay.
    pub update_id: i64,
    /// What the delivery carries.
    pub kind: UpdateKind,
}

/// What one delivery carries.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UpdateKind {
    /// A plain message — one without a leading `/command`.
    Message(Message),
    /// A message whose text starts with a `/command`.
    Command(Command),
    /// An inline-keyboard press.
    CallbackQuery(CallbackQuery),
    /// A post in a channel the bot is in, possibly an edit of one.
    ChannelPost(ChannelPost),
    /// Anything else — `edited_message`, shipping events, whatever Telegram
    /// grows. The `update_id` still dedups it.
    Other,
}

/// A Telegram user, as the update carries them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct User {
    /// The user's id, stable across their username changes.
    pub id: i64,
    /// Whether this "user" is another bot.
    pub is_bot: bool,
    /// The `@username`, absent when the user has none or hides it.
    pub username: Option<String>,
    /// The display name — the one field Telegram always sends.
    pub first_name: String,
    /// The client language, when the user shares it: an IETF tag like `en`.
    pub language_code: Option<String>,
}

/// What kind of chat a message arrived in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChatKind {
    /// A one-to-one conversation with the bot.
    Private,
    /// A basic group.
    Group,
    /// A supergroup — the form basic groups migrate into.
    Supergroup,
    /// A channel, where only admins post.
    Channel,
    /// A type this crate does not know.
    Other,
}

/// The chat a message arrived in.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Chat {
    /// The chat id, negative for groups, supergroups and channels.
    pub id: i64,
    /// Private, group, supergroup, channel, or other.
    pub kind: ChatKind,
    /// The group or channel title; absent for a private chat.
    pub title: Option<String>,
    /// The public `@username`, when the chat has one.
    pub username: Option<String>,
}

/// A plain message. `text` is the message's `text`, or its `caption` when
/// the message carries media instead; `links` gathers the URLs from both
/// the `entities` and the `caption_entities`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Message {
    /// The message's id within its chat — what `edit_message` and
    /// `delete_message` address.
    pub message_id: i64,
    /// Where the message arrived.
    pub chat: Chat,
    /// Who sent it. Absent on channel posts and on messages Telegram
    /// attributes to the channel itself.
    pub from: Option<User>,
    /// When the message was sent, as a Unix timestamp.
    pub date: i64,
    /// The text, or the caption of a media message.
    pub text: Option<String>,
    /// Every URL the message names: `url` entities sliced out of the text
    /// by their UTF-16 offsets, then `text_link` entities' own `url`s, in
    /// wire order.
    pub links: Vec<String>,
}

/// A message whose text starts with a `/command`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Command {
    /// The whole message, command included.
    pub message: Message,
    /// The command name: lowercase, without the leading `/` and without
    /// any `@bot` suffix — `/start` and `/Start@MyBot` are both `start`.
    pub name: String,
    /// The bot the command was addressed to, from `/command@bot` — a group
    /// with several bots disambiguates this way.
    pub bot: Option<String>,
    /// Everything after the command word, trimmed. Empty when there was
    /// nothing after it.
    pub args: String,
}

/// An inline-keyboard press: the `data` an [`InlineButton`](crate::InlineButton) carried, plus
/// who pressed it and where.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CallbackQuery {
    /// What `answer_callback` acknowledges.
    pub id: String,
    /// Who pressed the button.
    pub from: User,
    /// The chat the button lives in, when Telegram still exposes the
    /// message to the bot.
    pub chat_id: Option<i64>,
    /// The message the button lives on, same caveat.
    pub message_id: Option<i64>,
    /// The button's `data`, when it was a callback button.
    pub data: Option<String>,
}

/// A post in a channel the bot is in.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChannelPost {
    /// The post itself.
    pub message: Message,
    /// Whether this delivery edited an earlier post
    /// (`edited_channel_post`) rather than posted a new one.
    pub edited: bool,
}

/// A message that is not a channel post: a leading `bot_command` entity
/// makes it a [`UpdateKind::Command`], anything else is a plain message.
fn as_command_or_message(raw: RawMessage) -> UpdateKind {
    match command_parts(&raw) {
        Some((name, bot, args)) => UpdateKind::Command(Command {
            message: build_message(raw),
            name,
            bot,
            args,
        }),
        None => UpdateKind::Message(build_message(raw)),
    }
}

/// Splits `/name@bot args` out of a message whose text opens with a
/// `bot_command` entity, or `None` when it does not.
fn command_parts(raw: &RawMessage) -> Option<(String, Option<String>, String)> {
    // A command rides `text`; an entity over a caption names nothing.
    let text = raw.text.as_deref()?;
    let entity = raw
        .entities
        .iter()
        .find(|entity| entity.entity_type == "bot_command" && entity.offset == 0)?;
    let length = usize::try_from(entity.length).ok()?;
    let units: Vec<u16> = text.encode_utf16().collect();
    if length == 0 || length > units.len() || units[0] != u16::from(b'/') {
        return None;
    }
    let word = String::from_utf16_lossy(&units[1..length]);
    let (name, bot) = match word.split_once('@') {
        Some((name, bot)) if !name.is_empty() => (name, Some(bot.to_owned())),
        Some(_) => return None,
        None => (word.as_str(), None),
    };
    let args = String::from_utf16_lossy(&units[length..]).trim().to_owned();
    Some((name.to_ascii_lowercase(), bot, args))
}

fn build_message(raw: RawMessage) -> Message {
    // Collected before the moves: the entities borrow `raw`.
    let mut links = Vec::new();
    collect_links(raw.text.as_deref(), &raw.entities, &mut links);
    collect_links(raw.caption.as_deref(), &raw.caption_entities, &mut links);
    Message {
        message_id: raw.message_id,
        chat: build_chat(raw.chat),
        from: raw.from.map(build_user),
        date: raw.date,
        // A media message has no `text`, only a `caption`; keep the words
        // either way.
        text: raw.text.or(raw.caption),
        links,
    }
}

fn build_chat(raw: RawChat) -> Chat {
    Chat {
        id: raw.id,
        kind: match raw.chat_type.as_deref() {
            Some("private") => ChatKind::Private,
            Some("group") => ChatKind::Group,
            Some("supergroup") => ChatKind::Supergroup,
            Some("channel") => ChatKind::Channel,
            _ => ChatKind::Other,
        },
        title: raw.title,
        username: raw.username,
    }
}

fn build_user(raw: RawUser) -> User {
    User {
        id: raw.id,
        is_bot: raw.is_bot,
        username: raw.username,
        first_name: raw.first_name,
        language_code: raw.language_code,
    }
}

fn build_callback(raw: RawCallbackQuery) -> CallbackQuery {
    let (chat_id, message_id) = raw.message.map_or((None, None), |message| {
        (Some(message.chat.id), Some(message.message_id))
    });
    CallbackQuery {
        id: raw.id,
        from: build_user(raw.from),
        chat_id,
        message_id,
        data: raw.data,
    }
}

/// Collects the URLs `entities` name in `source` — `url` entities sliced
/// out of the text by their UTF-16 offsets, `text_link` entities by their
/// own `url` field. Out-of-range entities are skipped, not fatal: Telegram
/// computed them, but the text and the entities ride separate fields and a
/// parse here must never fail a delivery that verified.
fn collect_links(source: Option<&str>, entities: &[RawEntity], links: &mut Vec<String>) {
    let Some(text) = source else {
        return;
    };
    let units: Vec<u16> = text.encode_utf16().collect();
    for entity in entities {
        match entity.entity_type.as_str() {
            "url" => {
                let (Ok(start), Ok(length)) = (
                    usize::try_from(entity.offset),
                    usize::try_from(entity.length),
                ) else {
                    continue;
                };
                let Some(end) = start.checked_add(length).filter(|&end| end <= units.len()) else {
                    continue;
                };
                links.push(String::from_utf16_lossy(&units[start..end]));
            }
            "text_link" => {
                if let Some(url) = &entity.url {
                    links.push(url.clone());
                }
            }
            _ => {}
        }
    }
}

// ---------------------------------------------------------------------------
// The wire

#[derive(Deserialize)]
struct RawUpdate {
    update_id: i64,
    #[serde(default)]
    message: Option<RawMessage>,
    // `edited_message` is deliberately absent: serde ignores unknown
    // fields, so an edit arrives with no known payload and falls through
    // to `UpdateKind::Other` below.
    #[serde(default)]
    channel_post: Option<RawMessage>,
    #[serde(default)]
    edited_channel_post: Option<RawMessage>,
    #[serde(default)]
    callback_query: Option<RawCallbackQuery>,
}

#[derive(Deserialize)]
struct RawMessage {
    message_id: i64,
    chat: RawChat,
    #[serde(default)]
    from: Option<RawUser>,
    #[serde(default)]
    date: i64,
    #[serde(default)]
    text: Option<String>,
    #[serde(default)]
    caption: Option<String>,
    #[serde(default)]
    entities: Vec<RawEntity>,
    #[serde(default)]
    caption_entities: Vec<RawEntity>,
}

#[derive(Deserialize)]
struct RawChat {
    id: i64,
    #[serde(rename = "type")]
    chat_type: Option<String>,
    #[serde(default)]
    title: Option<String>,
    #[serde(default)]
    username: Option<String>,
}

#[derive(Deserialize)]
struct RawUser {
    id: i64,
    #[serde(default)]
    is_bot: bool,
    #[serde(default)]
    username: Option<String>,
    #[serde(default)]
    first_name: String,
    #[serde(default)]
    language_code: Option<String>,
}

#[derive(Deserialize)]
struct RawEntity {
    #[serde(rename = "type")]
    entity_type: String,
    offset: i64,
    length: i64,
    #[serde(default)]
    url: Option<String>,
}

#[derive(Deserialize)]
struct RawCallbackQuery {
    id: String,
    from: RawUser,
    #[serde(default)]
    message: Option<RawMessage>,
    #[serde(default)]
    data: Option<String>,
}
