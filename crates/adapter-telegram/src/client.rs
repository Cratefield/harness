//! The outbound half: the [`TelegramBot`] port and its HTTP implementation
//! [`HttpTelegramBot`], plus the local rate budgets.
//!
//! Telegram authenticates a bot by the URL path — `POST {base}/bot{token}/{method}`
//! — so the token rides the one place most HTTP clients quote verbatim in an
//! error. Every string that reaches a [`TelegramError`], a `Display`, a
//! `Debug` or a tracing line goes through [`HttpTelegramBot::scrub`] first,
//! and the client's own `Debug` prints a placeholder where the token would
//! be. Nothing here formats the endpoint into a log line at all.

use std::collections::HashMap;
use std::fmt;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use bytes::Bytes;
use cratefield_core::{Clock, HttpClient, retry_after};
use http::header::CONTENT_TYPE;
use http::{HeaderMap, Method, Request, StatusCode};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::Value as Json;

/// Telegram's own API root; `with_base` overrides it for tests pointed at a
/// fake.
const DEFAULT_BASE: &str = "https://api.telegram.org";

/// Telegram's cap on `callback_data`, in bytes. Longer data is refused at
/// construction rather than spent against the rate budget on a call that
/// would 400.
const MAX_CALLBACK_DATA_BYTES: usize = 64;

// ---------------------------------------------------------------------------
// Outbound data types

/// One button in an inline keyboard row.
///
/// Construct through [`InlineButton::callback`] and [`InlineButton::url`];
/// the fields are public so tests (and a module with needs this crate did
/// not anticipate) can build values directly — `send_message` re-validates
/// what the constructors guarantee, so a hand-built button that Telegram
/// would refuse is refused locally instead.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InlineButton {
    /// The text on the button.
    pub text: String,
    /// What pressing it does.
    pub kind: ButtonKind,
}

/// What pressing an [`InlineButton`] does.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ButtonKind {
    /// Sends `data` back to the bot as a callback query — the string
    /// `answer_callback` then acknowledges. Telegram caps the data at
    /// 1..=64 bytes.
    Callback(String),
    /// Opens `url` in the client.
    Url(String),
}

impl InlineButton {
    /// A callback button. `data` is what the bot receives when it is
    /// pressed — by convention a short machine-readable tag like
    /// `"deploy:ack"`.
    ///
    /// # Errors
    ///
    /// [`TelegramError::Invalid`] when `data` is empty or longer than 64
    /// bytes — Telegram's cap, refused here so it never costs an HTTP call.
    pub fn callback(
        text: impl Into<String>,
        data: impl Into<String>,
    ) -> Result<Self, TelegramError> {
        let button = Self {
            text: text.into(),
            kind: ButtonKind::Callback(data.into()),
        };
        button.validate()?;
        Ok(button)
    }

    /// A button that opens `url`. Telegram checks the URL at press time,
    /// so there is nothing local to refuse here.
    #[must_use]
    pub fn url(text: impl Into<String>, url: impl Into<String>) -> Self {
        Self {
            text: text.into(),
            kind: ButtonKind::Url(url.into()),
        }
    }

    /// The constructor guarantee, re-checked by `send_message`/`edit_message`
    /// against hand-built buttons.
    fn validate(&self) -> Result<(), TelegramError> {
        if let ButtonKind::Callback(data) = &self.kind {
            let size = data.len();
            if !(1..=MAX_CALLBACK_DATA_BYTES).contains(&size) {
                return Err(TelegramError::Invalid(format!(
                    "callback_data must be 1..={MAX_CALLBACK_DATA_BYTES} bytes, got {size}"
                )));
            }
        }
        Ok(())
    }
}

/// A message to send: text, optionally an inline keyboard, optionally with
/// the link preview suppressed.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct OutgoingMessage {
    /// Where the message goes: a user or chat id, negative for groups and
    /// channels.
    pub chat_id: i64,
    /// The message text, 1..=4096 characters. Sent verbatim; formatting is
    /// out of scope for this adapter.
    pub text: String,
    /// The inline keyboard, row by row.
    pub buttons: Vec<Vec<InlineButton>>,
    /// Whether the link preview is suppressed. Sent as
    /// `link_preview_options.is_disabled` only when true.
    pub disable_link_preview: bool,
}

impl OutgoingMessage {
    /// A plain text message to `chat_id` — no buttons, preview enabled.
    #[must_use]
    pub fn new(chat_id: i64, text: impl Into<String>) -> Self {
        Self {
            chat_id,
            text: text.into(),
            buttons: Vec::new(),
            disable_link_preview: false,
        }
    }

    /// Appends one row of buttons to the inline keyboard.
    #[must_use]
    pub fn row(mut self, buttons: Vec<InlineButton>) -> Self {
        self.buttons.push(buttons);
        self
    }
}

/// A message Telegram accepted: the chat it landed in and the id every
/// later `edit_message`/`delete_message` call addresses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SentMessage {
    /// The chat the message landed in, echoed back.
    pub chat_id: i64,
    /// The new message's id, positive.
    pub message_id: i64,
}

// ---------------------------------------------------------------------------
// The port

/// The outbound chat port: the four Bot API calls a module needs. Object
/// safe, so a module holds an `Arc<dyn TelegramBot>` and tests substitute
/// [`fake::FakeTelegramBot`](crate::fake::FakeTelegramBot).
#[async_trait]
pub trait TelegramBot: Send + Sync {
    /// Sends a text message, with any buttons, and reports where it landed.
    ///
    /// # Errors
    ///
    /// [`TelegramError::Invalid`] for a local refusal (empty text, a
    /// `callback_data` outside 1..=64 bytes) or a 400 from Telegram,
    /// [`TelegramError::RateLimited`] when a local budget is exhausted or
    /// Telegram answered 429, [`TelegramError::Unauthorized`] for 401,
    /// [`TelegramError::Forbidden`] for 403, [`TelegramError::Transient`]
    /// for 5xx, transport failures and unparseable responses.
    async fn send_message(&self, message: &OutgoingMessage) -> Result<SentMessage, TelegramError>;

    /// Edits a message this bot previously sent, replacing the text and the
    /// inline keyboard (an empty `buttons` removes the keyboard).
    ///
    /// # Errors
    ///
    /// The same mapping as [`TelegramBot::send_message`]; editing an unknown
    /// or too-old message is Telegram's `Invalid`.
    async fn edit_message(
        &self,
        chat_id: i64,
        message_id: i64,
        text: &str,
        buttons: &[Vec<InlineButton>],
    ) -> Result<(), TelegramError>;

    /// Deletes a message this bot previously sent.
    ///
    /// # Errors
    ///
    /// The same mapping as [`TelegramBot::send_message`]; deleting an
    /// unknown message is Telegram's `Invalid`.
    async fn delete_message(&self, chat_id: i64, message_id: i64) -> Result<(), TelegramError>;

    /// Acknowledges a callback query, optionally showing `text` as a toast
    /// to the user who pressed the button.
    ///
    /// # Errors
    ///
    /// The same mapping as [`TelegramBot::send_message`].
    async fn answer_callback(
        &self,
        callback_query_id: &str,
        text: Option<&str>,
    ) -> Result<(), TelegramError>;
}

// ---------------------------------------------------------------------------
// Errors

/// Why a call to Telegram failed.
///
/// `Debug` is derived, so no variant ever carries the bot token: every
/// string built from an external message is scrubbed of the token before
/// it becomes an error.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TelegramError {
    /// A local rate budget is exhausted, or Telegram answered 429. Wait at
    /// least `retry_after` before trying the same call again.
    RateLimited {
        /// How long until the call may be retried.
        retry_after: Duration,
    },
    /// 401: the bot token is wrong or revoked.
    Unauthorized,
    /// 403: the recipient blocked the bot, or the bot is no longer in the
    /// chat. Carries Telegram's description.
    Forbidden(String),
    /// A 400/404 from Telegram, or a local refusal (bad `callback_data`,
    /// empty text). Carries the description.
    Invalid(String),
    /// A 5xx, a transport failure, or a response this adapter cannot read.
    /// Worth retrying later; carries what is known about the failure.
    Transient(String),
}

impl TelegramError {
    /// How long to wait before retrying, when the error said.
    #[must_use]
    pub fn retry_after(&self) -> Option<Duration> {
        match self {
            Self::RateLimited { retry_after } => Some(*retry_after),
            _ => None,
        }
    }

    /// Whether the call is worth retrying as-is later: rate limits clear
    /// with time and transient failures often clear on their own. An
    /// `Unauthorized`, `Forbidden` or `Invalid` needs a human or a
    /// different input first.
    #[must_use]
    pub fn is_transient(&self) -> bool {
        matches!(self, Self::RateLimited { .. } | Self::Transient(_))
    }
}

impl fmt::Display for TelegramError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::RateLimited { retry_after } => {
                write!(
                    f,
                    "telegram rate limited the call; retry after {retry_after:?}"
                )
            }
            Self::Unauthorized => f.write_str("telegram rejected the bot token (401)"),
            Self::Forbidden(description) => {
                write!(f, "telegram refused the call (403): {description}")
            }
            Self::Invalid(description) => write!(f, "telegram rejected the call: {description}"),
            Self::Transient(detail) => write!(f, "telegram call failed transiently: {detail}"),
        }
    }
}

impl std::error::Error for TelegramError {}

// ---------------------------------------------------------------------------
// Rate limits

/// The local rate budgets `HttpTelegramBot` enforces before it sends, as
/// token buckets fed by the injected `Clock`.
///
/// They approximate Telegram's documented budgets — 30 calls/second per bot,
/// 1/second per private chat, 20/minute per group — but **per client
/// instance**: in wasm terms, per isolate. A deployment running several
/// isolates shares nothing here, and Telegram's budget is per bot; gate the
/// fan-out through the runtime's `RateLimiter` port if the sum matters.
///
/// A zero disables that limit rather than refusing everything.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RateLimits {
    /// Whole-bot calls per second. Default 30.
    pub global_per_sec: u32,
    /// Calls per second per private chat (`chat_id >= 0`). Default 1.
    pub private_chat_per_sec: u32,
    /// Calls per minute per group or channel (`chat_id < 0`). Default 20.
    pub group_per_min: u32,
}

impl Default for RateLimits {
    /// Telegram's documented budgets: 30/s globally, 1/s per private chat,
    /// 20/min per group.
    fn default() -> Self {
        Self {
            global_per_sec: 30,
            private_chat_per_sec: 1,
            group_per_min: 20,
        }
    }
}

/// One token bucket, held in nano-tokens (`1e9` = one call) so a refill
/// stays integer arithmetic and a `ManualClock` advance of exactly one
/// period lands exactly on a whole token.
struct Bucket {
    /// The bucket's size, in nano-tokens.
    capacity: u128,
    /// Tokens on hand, in nano-tokens.
    tokens: u128,
    /// When the bucket was last touched, in nanoseconds since the epoch.
    last_nanos: Option<u128>,
}

/// Nano-tokens per whole call.
const NANOS_PER_TOKEN: u128 = 1_000_000_000;

/// The per-chat maps grow one bucket per chat the bot ever messages, so
/// past this many [`RateState::prune`] drops the ones nothing can reach
/// through: buckets idle past [`BUCKET_IDLE_NANOS`] and the 429 deadlines
/// whose moment has passed.
const CHAT_BUCKETS_HIGH_WATER: usize = 1024;

/// How long a per-chat bucket must go untouched before the sweep may drop
/// it. A bucket's tokens refill lazily — inside `take`, from `last_nanos` —
/// so what the map stores is what the bucket held when it was last used,
/// not what it is worth now. But the slowest refill any configured rate can
/// name is a minute (20 per minute), so a bucket idle for twice that has
/// refilled to full regardless of configuration, and dropping it is
/// indistinguishable from never having messaged that chat: it comes back
/// full.
const BUCKET_IDLE_NANOS: u128 = 120 * NANOS_PER_TOKEN;

impl Bucket {
    /// A full bucket of `capacity` calls.
    fn new(capacity: u32) -> Self {
        let capacity = u128::from(capacity) * NANOS_PER_TOKEN;
        Self {
            capacity,
            tokens: capacity,
            last_nanos: None,
        }
    }

    /// Puts one token back. Only valid immediately after a **granted**
    /// [`Bucket::take`] on the same bucket: a granted take leaves the bucket
    /// a whole token below what it held after its refill, so
    /// `tokens + NANOS_PER_TOKEN` cannot exceed `capacity` and the `min` is
    /// a no-op guard. The bucket ends exactly as the granted take began.
    fn untake(&mut self) {
        self.tokens = self.capacity.min(self.tokens + NANOS_PER_TOKEN);
    }

    /// Grants one token (`None`), or reports how long the next token needs
    /// (`Some`). `per_sec` is the refill rate as (units, denominator) calls
    /// per second; the caller skips zero rates, so the division is safe.
    fn take(&mut self, now_nanos: u128, per_sec: (u64, u64)) -> Option<Duration> {
        if per_sec.0 == 0 {
            return Some(Duration::MAX); // unreachable through the callers
        }
        let units = u128::from(per_sec.0);
        let last = self.last_nanos.unwrap_or(now_nanos);
        let elapsed = now_nanos.saturating_sub(last);
        self.last_nanos = Some(now_nanos);
        // Ceil the refill so a clock advanced by exactly one period never
        // falls a nano-token short of a whole call.
        let refill = ceil_div(elapsed.saturating_mul(units), u128::from(per_sec.1));
        self.tokens = self.capacity.min(self.tokens.saturating_add(refill));
        if self.tokens >= NANOS_PER_TOKEN {
            self.tokens -= NANOS_PER_TOKEN;
            return None;
        }
        // Nanoseconds until one more token: the missing fraction of a call,
        // times the seconds one call takes.
        let missing = NANOS_PER_TOKEN - self.tokens;
        Some(duration_from_nanos(ceil_div(
            missing.saturating_mul(u128::from(per_sec.1)),
            units,
        )))
    }
}

/// `numerator / denominator`, rounded up. `denominator` is never zero at
/// the call sites.
fn ceil_div(numerator: u128, denominator: u128) -> u128 {
    numerator / denominator + u128::from(!numerator.is_multiple_of(denominator))
}

/// Narrows nanoseconds into a `Duration`, saturating at `u64::MAX` — a
/// wait that long is "not in this deployment's lifetime" anyway.
fn duration_from_nanos(nanos: u128) -> Duration {
    Duration::from_nanos(u64::try_from(nanos).unwrap_or(u64::MAX))
}

/// The mutable half of the budgets: the global bucket, one bucket per chat
/// actually messaged, and the not-before deadlines a Telegram 429 set.
struct RateState {
    global: Bucket,
    chats: HashMap<i64, Bucket>,
    not_before: HashMap<i64, u128>,
}

impl RateState {
    fn new(limits: &RateLimits) -> Self {
        Self {
            global: Bucket::new(limits.global_per_sec),
            chats: HashMap::new(),
            not_before: HashMap::new(),
        }
    }

    /// Drops the chat state nothing can reach any more, once the per-chat
    /// map has grown past [`CHAT_BUCKETS_HIGH_WATER`]: buckets idle past
    /// [`BUCKET_IDLE_NANOS`] — long enough to have refilled to full, so a
    /// dropped one would be recreated identically — and 429 deadlines whose
    /// moment has passed. A recently used bucket keeps the refill credit it
    /// has accrued, and a chat under a live deadline keeps its bucket,
    /// whatever its age.
    fn prune(&mut self, now: u128) {
        if self.chats.len() < CHAT_BUCKETS_HIGH_WATER {
            return;
        }
        self.chats.retain(|chat_id, bucket| {
            if self
                .not_before
                .get(chat_id)
                .is_some_and(|&until| now < until)
            {
                return true;
            }
            bucket
                .last_nanos
                .is_none_or(|last| now.saturating_sub(last) < BUCKET_IDLE_NANOS)
        });
        // Every deadline still in the future kept its chat's bucket above,
        // so what survives here is exactly the expired garbage.
        self.not_before.retain(|_chat_id, until| now < *until);
    }
}

// Budget bookkeeping for the local rate limits — instance state a handle
// shares across calls, not ambient request state; the scoped allow follows
// the policy documented in the workspace clippy.toml (ADR 0007).
#[allow(clippy::disallowed_types)]
type Guarded<T> = std::sync::Mutex<T>;

// ---------------------------------------------------------------------------
// The HTTP bot

/// [`TelegramBot`] over the Telegram Bot API: `POST {base}/bot{token}/{method}`
/// with a JSON body, through the runtime's [`HttpClient`] port.
///
/// No `Debug` derive: the token is a struct field, and a derived `Debug`
/// would print it wherever a log line met the adapter. The hand-written one
/// prints a placeholder instead.
pub struct HttpTelegramBot {
    http: Arc<dyn HttpClient>,
    /// Drives the rate buckets and parses a date-form `Retry-After`, the
    /// same reason the other HTTP adapters hold one. A constructor argument
    /// rather than a builder default so a deployment that forgets it fails
    /// to compile instead of silently mis-budgeting.
    clock: Arc<dyn Clock>,
    /// The bot token, interpolated into the URL path. Never `Debug`d,
    /// `Display`d or logged; scrubbed out of every error string.
    token: String,
    /// `None` — the default — posts to `https://api.telegram.org`; a value
    /// overrides it for tests pointed at a fake.
    base: Option<String>,
    /// The configured budgets; `with_limits` swaps them (and resets the
    /// accrued state).
    limits: RateLimits,
    /// The buckets and 429 deadlines behind a mutex — instance state, not
    /// request state (see the `Guarded` note above).
    budget: Guarded<RateState>,
}

impl fmt::Debug for HttpTelegramBot {
    /// The bot token is a struct field, so it is written as a placeholder:
    /// a log line that meets the adapter must never carry it.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HttpTelegramBot")
            .field("base", &self.base)
            .field("bot_token", &"[redacted]")
            // The http and clock ports and the rate state are struct fields
            // too; nothing about any of them belongs in a log line.
            .finish_non_exhaustive()
    }
}

impl HttpTelegramBot {
    /// A bot pointed at Telegram under `bot_token`.
    #[must_use]
    pub fn new(
        http: Arc<dyn HttpClient>,
        clock: Arc<dyn Clock>,
        bot_token: impl Into<String>,
    ) -> Self {
        let limits = RateLimits::default();
        Self {
            http,
            clock,
            token: bot_token.into(),
            base: None,
            limits,
            budget: Guarded::new(RateState::new(&limits)),
        }
    }

    /// Overrides the root every request is posted to — a fake in tests —
    /// instead of `https://api.telegram.org`.
    #[must_use]
    pub fn with_base(mut self, base_url: impl Into<String>) -> Self {
        self.base = Some(base_url.into());
        self
    }

    /// Replaces the rate budgets with `limits`, discarding the tokens the
    /// old budgets had accrued and any 429 deadlines. Chain after `new`.
    #[must_use]
    pub fn with_limits(mut self, limits: RateLimits) -> Self {
        self.limits = limits;
        self.budget = Guarded::new(RateState::new(&limits));
        self
    }

    /// Registers `url` as the bot's webhook with `secret_token` in
    /// [`webhook::SECRET_HEADER`](crate::webhook::SECRET_HEADER) and the
    /// named update types delivered. An empty `url` deletes the webhook.
    ///
    /// Counted against the global budget only: there is no chat to scope a
    /// per-chat bucket to, and a 429 here has nothing to remember one for.
    ///
    /// # Errors
    ///
    /// [`TelegramError::Invalid`] for a `url` that is neither `https` nor a
    /// localhost `http` (the one exception Telegram allows), a secret
    /// outside Telegram's alphabet, or a bot token that is not shaped like
    /// one; otherwise the same mapping as [`TelegramBot::send_message`].
    pub async fn set_webhook(
        &self,
        url: &str,
        secret_token: &str,
        allowed_updates: &[&str],
    ) -> Result<(), TelegramError> {
        if !url.is_empty() {
            let localhost =
                url.starts_with("http://localhost") || url.starts_with("http://127.0.0.1");
            if !url.starts_with("https://") && !localhost {
                return Err(TelegramError::Invalid(
                    "webhook url must be https (http only for localhost)".to_owned(),
                ));
            }
            if !crate::webhook::is_valid_secret(secret_token) {
                return Err(TelegramError::Invalid(
                    "webhook secret token must be 1-256 chars of A-Z a-z 0-9 '_' or '-'".to_owned(),
                ));
            }
        }
        let wire = SetWebhookWire {
            url,
            secret_token,
            allowed_updates,
        };
        self.call("setWebhook", None, &wire).await.map(|_| ())
    }

    /// Grants the call its tokens, or refuses it before any HTTP request:
    /// first a 429 deadline Telegram set for this chat, then the global
    /// bucket, then the chat's own. `answer_callback` passes `None` and is
    /// scoped by the global bucket alone. A refusal never spends a token:
    /// one is taken only when the call goes on to send, so the global
    /// token goes back when the chat's own bucket says no.
    fn acquire(&self, chat: Option<i64>) -> Result<(), TelegramError> {
        let now = self.now_nanos();
        let mut state = self.budget.lock().expect("telegram rate-limit lock");
        state.prune(now);
        if let Some(chat_id) = chat
            && let Some(&until) = state.not_before.get(&chat_id)
            && now < until
        {
            return Err(TelegramError::RateLimited {
                retry_after: duration_from_nanos(until - now),
            });
        }
        if self.limits.global_per_sec > 0 {
            let wait = state
                .global
                .take(now, (u64::from(self.limits.global_per_sec), 1));
            if let Some(retry_after) = wait {
                return Err(TelegramError::RateLimited { retry_after });
            }
        }
        if let Some(chat_id) = chat {
            let (rate, capacity) = if chat_id < 0 {
                (
                    (u64::from(self.limits.group_per_min), 60),
                    self.limits.group_per_min,
                )
            } else {
                (
                    (u64::from(self.limits.private_chat_per_sec), 1),
                    self.limits.private_chat_per_sec,
                )
            };
            if capacity > 0 {
                let bucket = state
                    .chats
                    .entry(chat_id)
                    .or_insert_with(|| Bucket::new(capacity));
                if let Some(retry_after) = bucket.take(now, rate) {
                    // No request is about to be sent, so the global token
                    // this call took goes back: a caller retrying a
                    // chat-limited chat must not be able to drain the one
                    // budget every other chat shares.
                    if self.limits.global_per_sec > 0 {
                        state.global.untake();
                    }
                    return Err(TelegramError::RateLimited { retry_after });
                }
            }
        }
        Ok(())
    }

    /// Remembers, after a Telegram 429, that `chat_id` may not be sent to
    /// again until the delay Telegram named has passed — enforced locally
    /// by [`HttpTelegramBot::acquire`], without another HTTP call.
    fn note_not_before(&self, chat_id: i64, delay: Duration) {
        let until = self.now_nanos().saturating_add(delay.as_nanos());
        let mut state = self.budget.lock().expect("telegram rate-limit lock");
        state
            .not_before
            .entry(chat_id)
            .and_modify(|held| *held = (*held).max(until))
            .or_insert(until);
    }

    /// Now, in nanoseconds since the epoch — the unit every bucket and
    /// deadline counts in.
    fn now_nanos(&self) -> u128 {
        u128::try_from(self.clock.now().unix_timestamp_nanos()).unwrap_or(0)
    }

    /// Replaces the bot token in `text` with a placeholder. Every string
    /// about to ride an error, a `Debug` or a log line goes through here:
    /// the token rides the URL path, so even a transport error quoting the
    /// request URI must not quote it verbatim.
    fn scrub(&self, text: &str) -> String {
        if self.token.is_empty() {
            return text.to_owned();
        }
        text.replace(&self.token, "[redacted]")
    }

    /// Builds the request for one Bot API method. Never called with a
    /// token-shaped-incorrect token, and the endpoint is never logged.
    fn build_request(&self, method: &str, body: &Json) -> Result<Request<Bytes>, TelegramError> {
        if !token_is_shape(&self.token) {
            return Err(TelegramError::Invalid(
                "bot token is not shaped like a Telegram token".to_owned(),
            ));
        }
        let base = self
            .base
            .as_deref()
            .unwrap_or(DEFAULT_BASE)
            .trim_end_matches('/');
        // Interpolated, never logged: the endpoint carries the token.
        let token = &self.token;
        let url = format!("{base}/bot{token}/{method}");
        let payload = serde_json::to_vec(body)
            .map_err(|error| TelegramError::Transient(error.to_string()))?;
        Request::builder()
            .method(Method::POST)
            .uri(url)
            .header(CONTENT_TYPE, "application/json")
            .body(Bytes::from(payload))
            .map_err(|error| {
                // The builder quotes the URI it refused, so scrub: a bad
                // base URL is operator configuration, not a leak.
                TelegramError::Invalid(self.scrub(&error.to_string()))
            })
    }

    /// One Bot API call: budget, send, envelope. `chat` scopes the
    /// per-chat budget and is where a 429's deadline is remembered.
    async fn call(
        &self,
        method: &str,
        chat: Option<i64>,
        body: &impl Serialize,
    ) -> Result<Envelope, TelegramError> {
        // Built before the budget is touched, so a call that cannot become
        // a request — an unshaped token, a body that does not serialise —
        // never spends a token on nothing.
        let value = serde_json::to_value(body)
            .map_err(|error| TelegramError::Transient(error.to_string()))?;
        let request = self.build_request(method, &value)?;
        self.acquire(chat)?;
        // The endpoint carries the token, so it is deliberately absent from
        // every log line; the method name says which call this was.
        tracing::debug!(method, chat = ?chat, "telegram Bot API call");
        let response = self
            .http
            .send(request)
            .await
            .map_err(|error| TelegramError::Transient(self.scrub(&error.to_string())))?;
        let (parts, bytes) = response.into_parts();
        let envelope = serde_json::from_slice::<Envelope>(&bytes).ok();
        self.settle(parts.status, &parts.headers, envelope, chat)
    }

    /// Turns a response into an envelope or the mapped error. A body that
    /// is not JSON at all is `Transient` whatever the status: never treat
    /// an unreadable answer as success.
    fn settle(
        &self,
        status: StatusCode,
        headers: &HeaderMap,
        envelope: Option<Envelope>,
        chat: Option<i64>,
    ) -> Result<Envelope, TelegramError> {
        let Some(envelope) = envelope else {
            return Err(TelegramError::Transient(
                "telegram returned an unparseable response body".to_owned(),
            ));
        };
        if status.is_success() && envelope.ok {
            return Ok(envelope);
        }
        Err(self.api_error(status, headers, envelope, chat))
    }

    /// Maps a failure to [`TelegramError`]: 429 → `RateLimited` (and a
    /// chat deadline remembered), 401 → `Unauthorized`, 403 → `Forbidden`,
    /// other 4xx (Telegram's 400s and 404s) → `Invalid`, and 5xx — or any
    /// status this mapping did not anticipate — → `Transient`.
    fn api_error(
        &self,
        status: StatusCode,
        headers: &HeaderMap,
        envelope: Envelope,
        chat: Option<i64>,
    ) -> TelegramError {
        let code = envelope.error_code.unwrap_or_else(|| status.as_u16());
        let description = self.scrub(
            envelope
                .description
                .as_deref()
                .unwrap_or("telegram returned an error without a description"),
        );
        match code {
            429 => {
                let retry_after = envelope
                    .parameters
                    .and_then(|parameters| parameters.retry_after)
                    .map(Duration::from_secs)
                    .or_else(|| retry_after(headers, &*self.clock))
                    .unwrap_or_else(|| Duration::from_secs(1));
                if let Some(chat_id) = chat {
                    self.note_not_before(chat_id, retry_after);
                }
                tracing::warn!(chat = ?chat, retry_after = ?retry_after, "telegram rate limited the bot");
                TelegramError::RateLimited { retry_after }
            }
            401 => TelegramError::Unauthorized,
            403 => TelegramError::Forbidden(description),
            400..=499 => TelegramError::Invalid(description),
            _ => TelegramError::Transient(description),
        }
    }
}

/// Whether `token` is shaped like a Telegram bot token (`<digits>:<chars>`).
/// Checked before interpolation so a stray token can never bend the URL
/// path it rides in.
fn token_is_shape(token: &str) -> bool {
    !token.is_empty()
        && token
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b':' | b'_' | b'-'))
}

/// Local refusals, decided before the budget is touched so a bad call never
/// spends a token.
fn validate_text(text: &str) -> Result<(), TelegramError> {
    if text.trim().is_empty() {
        return Err(TelegramError::Invalid("message text is empty".to_owned()));
    }
    Ok(())
}

fn validate_buttons(buttons: &[Vec<InlineButton>]) -> Result<(), TelegramError> {
    for row in buttons {
        for button in row {
            button.validate()?;
        }
    }
    Ok(())
}

fn validate_outgoing(message: &OutgoingMessage) -> Result<(), TelegramError> {
    validate_text(&message.text)?;
    validate_buttons(&message.buttons)
}

/// Reads `result` out of an ok envelope, or explains why it could not.
fn deserialize_result<T: DeserializeOwned>(
    bot: &HttpTelegramBot,
    method: &str,
    result: Option<Json>,
) -> Result<T, TelegramError> {
    let value =
        result.ok_or_else(|| TelegramError::Transient(format!("{method} returned no result")))?;
    serde_json::from_value(value).map_err(|error| {
        TelegramError::Transient(bot.scrub(&format!(
            "{method} returned a result this adapter cannot read: {error}"
        )))
    })
}

// ---------------------------------------------------------------------------
// The wire

#[derive(Serialize)]
struct WireButton<'a> {
    text: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    callback_data: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    url: Option<&'a str>,
}

#[derive(Serialize)]
struct WireKeyboard<'a> {
    inline_keyboard: Vec<Vec<WireButton<'a>>>,
}

fn keyboard(buttons: &[Vec<InlineButton>]) -> Option<WireKeyboard<'_>> {
    if buttons.is_empty() {
        return None;
    }
    Some(WireKeyboard {
        inline_keyboard: buttons
            .iter()
            .map(|row| {
                row.iter()
                    .map(|button| match &button.kind {
                        ButtonKind::Callback(data) => WireButton {
                            text: &button.text,
                            callback_data: Some(data),
                            url: None,
                        },
                        ButtonKind::Url(url) => WireButton {
                            text: &button.text,
                            callback_data: None,
                            url: Some(url),
                        },
                    })
                    .collect()
            })
            .collect(),
    })
}

#[derive(Serialize)]
struct WireLinkPreview {
    is_disabled: bool,
}

#[derive(Serialize)]
struct SendMessageWire<'a> {
    chat_id: i64,
    text: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    reply_markup: Option<WireKeyboard<'a>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    link_preview_options: Option<WireLinkPreview>,
}

#[derive(Serialize)]
struct EditMessageWire<'a> {
    chat_id: i64,
    message_id: i64,
    text: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    reply_markup: Option<WireKeyboard<'a>>,
}

#[derive(Serialize)]
struct DeleteMessageWire {
    chat_id: i64,
    message_id: i64,
}

#[derive(Serialize)]
struct AnswerCallbackWire<'a> {
    callback_query_id: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    text: Option<&'a str>,
}

#[derive(Serialize)]
struct SetWebhookWire<'a> {
    url: &'a str,
    secret_token: &'a str,
    allowed_updates: &'a [&'a str],
}

/// Telegram's response envelope: `{"ok": true, "result": …}` on success,
/// `{"ok": false, "error_code": …, "description": …,
/// "parameters": {"retry_after": …}}` on failure. Unknown fields ignored.
#[derive(Deserialize, Default)]
struct Envelope {
    /// Absent or false on a failure — the field every decision hangs on.
    #[serde(default)]
    ok: bool,
    #[serde(default)]
    result: Option<Json>,
    #[serde(default)]
    error_code: Option<u16>,
    #[serde(default)]
    description: Option<String>,
    #[serde(default)]
    parameters: Option<WireParameters>,
}

#[derive(Deserialize)]
struct WireParameters {
    #[serde(default)]
    retry_after: Option<u64>,
}

/// The `result` of a successful `sendMessage`: the message's own id and
/// chat.
#[derive(Deserialize)]
struct SentWire {
    message_id: i64,
    chat: SentChatWire,
}

#[derive(Deserialize)]
struct SentChatWire {
    id: i64,
}

#[async_trait]
impl TelegramBot for HttpTelegramBot {
    async fn send_message(&self, message: &OutgoingMessage) -> Result<SentMessage, TelegramError> {
        validate_outgoing(message)?;
        let wire = SendMessageWire {
            chat_id: message.chat_id,
            text: &message.text,
            reply_markup: keyboard(&message.buttons),
            link_preview_options: message
                .disable_link_preview
                .then_some(WireLinkPreview { is_disabled: true }),
        };
        let envelope = self
            .call("sendMessage", Some(message.chat_id), &wire)
            .await?;
        let sent: SentWire = deserialize_result(self, "sendMessage", envelope.result)?;
        Ok(SentMessage {
            chat_id: sent.chat.id,
            message_id: sent.message_id,
        })
    }

    async fn edit_message(
        &self,
        chat_id: i64,
        message_id: i64,
        text: &str,
        buttons: &[Vec<InlineButton>],
    ) -> Result<(), TelegramError> {
        validate_text(text)?;
        validate_buttons(buttons)?;
        let wire = EditMessageWire {
            chat_id,
            message_id,
            text,
            reply_markup: keyboard(buttons),
        };
        self.call("editMessageText", Some(chat_id), &wire)
            .await
            .map(|_| ())
    }

    async fn delete_message(&self, chat_id: i64, message_id: i64) -> Result<(), TelegramError> {
        let wire = DeleteMessageWire {
            chat_id,
            message_id,
        };
        self.call("deleteMessage", Some(chat_id), &wire)
            .await
            .map(|_| ())
    }

    async fn answer_callback(
        &self,
        callback_query_id: &str,
        text: Option<&str>,
    ) -> Result<(), TelegramError> {
        let wire = AnswerCallbackWire {
            callback_query_id,
            text,
        };
        // Scoped by the global budget alone: a callback query names the
        // presser, not a chat, so there is nothing to budget per chat and
        // no deadline to remember for one.
        self.call("answerCallbackQuery", None, &wire)
            .await
            .map(|_| ())
    }
}

#[cfg(test)]
mod tests {
    //! The per-chat prune, against the state no public API exposes: a bot
    //! that has messaged thousands of chats must not keep a bucket (and a
    //! 429 deadline) for each forever, and the sweep must keep everything a
    //! refusal could still reach.

    use super::*;
    use cratefield_core::HttpError;
    use time::OffsetDateTime;

    /// Never called: these tests exercise `acquire` only, which sends
    /// nothing.
    struct NeverHttp;

    #[async_trait::async_trait]
    impl HttpClient for NeverHttp {
        async fn send(&self, _request: Request<Bytes>) -> Result<http::Response<Bytes>, HttpError> {
            Err(HttpError::Transport("never sent".to_owned()))
        }
    }

    /// A clock a test moves by hand, so a sweep's "how idle is idle" has a
    /// lever.
    struct TestClock(Guarded<OffsetDateTime>);

    impl TestClock {
        fn started_at(instant: OffsetDateTime) -> Arc<Self> {
            Arc::new(Self(Guarded::new(instant)))
        }

        fn advance(&self, seconds: i64) {
            *self.0.lock().expect("clock lock") += time::Duration::seconds(seconds);
        }
    }

    impl Clock for TestClock {
        fn now(&self) -> OffsetDateTime {
            *self.0.lock().expect("clock lock")
        }
    }

    fn epoch() -> OffsetDateTime {
        OffsetDateTime::from_unix_timestamp(1_767_225_600).expect("a representable instant")
    }

    /// The global limit off — these tests watch the chat map, not the
    /// shared bucket — and the chat limit at its default.
    fn one_per_chat() -> RateLimits {
        RateLimits {
            global_per_sec: 0,
            private_chat_per_sec: 1,
            group_per_min: 20,
        }
    }

    #[test]
    fn idle_buckets_are_pruned_once_the_map_grows_past_the_high_water() {
        let clock = TestClock::started_at(epoch());
        let bot = HttpTelegramBot::new(Arc::new(NeverHttp), clock.clone(), "test-bot-token")
            .with_limits(one_per_chat());

        // A burst across more chats than the high water: every bucket was
        // touched just now, so the sweep that runs on each acquire has
        // nothing it may drop and the map keeps them all.
        let high_water = i64::try_from(CHAT_BUCKETS_HIGH_WATER).expect("fits a chat id");
        for chat in 0..high_water + 32 {
            bot.acquire(Some(chat)).expect("each chat starts full");
        }
        assert!(
            bot.budget.lock().expect("budget lock").chats.len() >= CHAT_BUCKETS_HIGH_WATER,
            "the burst itself is kept: every bucket was just used"
        );

        // Two quiet minutes later every bucket has refilled to full — the
        // idle mark — and the next acquire's sweep drops them all but the
        // chat it is about to serve.
        clock.advance(121);
        bot.acquire(Some(-1)).expect("the new chat is served");
        let state = bot.budget.lock().expect("budget lock");
        assert_eq!(
            state.chats.len(),
            1,
            "every idle bucket from the burst was pruned"
        );
        assert!(state.not_before.is_empty());
    }

    #[test]
    fn a_live_429_deadline_survives_the_sweep_and_an_expired_one_does_not() {
        let clock = TestClock::started_at(epoch());
        let bot = HttpTelegramBot::new(Arc::new(NeverHttp), clock.clone(), "test-bot-token")
            .with_limits(one_per_chat());
        // The production pairing: a 429's deadline is noted for a chat the
        // bot has just messaged, so both a bucket and a deadline exist.
        bot.acquire(Some(7)).expect("chat 7 starts full");
        bot.note_not_before(7, Duration::from_secs(10));
        bot.note_not_before(8, Duration::from_secs(1));
        // Fill the map past the high water with plain chat buckets.
        let high_water = i64::try_from(CHAT_BUCKETS_HIGH_WATER).expect("fits a chat id");
        for chat in 1000..1000 + high_water {
            bot.acquire(Some(chat)).expect("each chat starts full");
        }

        // One second later: every burst bucket is still too recent to drop,
        // chat 7's deadline is live, chat 8's has passed — one sweep on the
        // next acquire settles all three.
        clock.advance(1);
        bot.acquire(Some(99_999)).expect("a fresh chat is served");

        {
            let state = bot.budget.lock().expect("budget lock");
            assert!(
                state.chats.contains_key(&7) && state.not_before.contains_key(&7),
                "the chat under a live deadline is kept"
            );
            assert!(
                !state.not_before.contains_key(&8),
                "the expired deadline is garbage, collected"
            );
        }
        let error = bot.acquire(Some(7)).expect_err("the deadline holds");
        assert_eq!(
            error.retry_after(),
            Some(Duration::from_secs(9)),
            "the surviving deadline still governs, at its remaining time"
        );
    }
}
