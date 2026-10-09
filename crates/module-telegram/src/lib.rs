//! `cratefield-module-telegram`: Telegram in the harness — the
//! secret-token webhook, account linking, and consent buttons that never
//! move value without a passkey (issue #764).
//!
//! ```no_run
//! use cratefield_module_telegram::{Telegram, TelegramEvents};
//!
//! let module = Telegram::new(TelegramEvents::new().on_message(|message| {
//!     Box::pin(async move { Ok(()) })
//! }));
//! ```
//!
//! The module mounts at `/v1/telegram` with four routes:
//!
//! - `POST /webhook` — one verified Telegram delivery in. The
//!   `X-Telegram-Bot-Api-Secret-Token` header is checked against
//!   [`WEBHOOK_SECRET_KEY`] over the raw body before any JSON is read;
//!   without the secret configured, every delivery is refused with a
//!   `503`. Deduplication runs through the
//!   [`Inbox`](cratefield_core::Inbox) ledger on the update id, so a
//!   redelivery is a `200` no-op.
//! - `POST /link-codes` and `DELETE /link` — the signed-in app issues a
//!   one-time code (stored only as a SHA-256 hash) and can unlink again.
//! - `POST /actions/{action_id}/confirm` — the web app's passkey
//!   confirmation, the only thing that can finish a value-moving
//!   approval a Telegram tap armed.
//!
//! The security model of the buttons is in one sentence: **a tap in
//! Telegram can deny anything, approve anything harmless, and only arm
//! — never finish — anything that moves value.** See
//! [`send_action_prompt`] and [`StepUp`].

#![forbid(unsafe_code)]
#![doc = include_str!("../README.md")]

#[cfg(feature = "notifications")]
mod channel;
mod handlers;
mod prompt;
mod step_up;
mod store;
mod token;

#[cfg(feature = "notifications")]
pub use crate::channel::TelegramChannel;
pub use crate::handlers::LinkCodeResponse;
pub use crate::prompt::{
    ActionError, ActionPrompt, ActionRequest, MAX_ACTION_TTL, send_action_prompt,
};
pub use crate::step_up::StepUp;
pub use crate::token::{
    ACTION_TOKEN_PREFIX, Decision, VerifiedToken, action_key, action_token, open_action_token,
};

use std::sync::Arc;

use time::Duration as TimeDuration;

use cratefield_adapter_telegram::{CallbackQuery, ChannelPost, Command, Message, TelegramBot};
use cratefield_core::{
    AnyError, BoxFuture, Config, ConfigError, DataKind, Disposition, Migrations, Module,
    ModuleConfig, ModuleContext, PersonalDataSet, Port, RandomBytes, SignatureVerification,
    SqlMigration,
};

/// The module's name: mounted at `/v1/telegram`, config keys prefixed
/// `TELEGRAM_`.
pub const MODULE_NAME: &str = "telegram";

/// The config key holding the webhook's shared secret
/// (`X-Telegram-Bot-Api-Secret-Token`). Absent fails closed — every
/// delivery answers `503` rather than trusting unverified bytes; set but
/// blank fails [`Module::validate_config`].
pub const WEBHOOK_SECRET_KEY: &str = "TELEGRAM_WEBHOOK_SECRET";

/// The config key suffix [`WEBHOOK_SECRET_KEY`] composes from: what
/// [`SignatureVerification::Hmac`] declares and `validate_config` reads,
/// so the two cannot drift apart.
const SECRET_KEY_SUFFIX: &str = "WEBHOOK_SECRET";

/// The config key holding the bot token. Read only when no bot was
/// injected with [`Telegram::bot`]; the token is never logged, and a
/// missing one means replies are skipped with a warning — never a crash.
pub const BOT_TOKEN_KEY: &str = "TELEGRAM_BOT_TOKEN";

/// The config key holding the bot's `@username`. When set,
/// `POST /link-codes` answers a ready-to-open `https://t.me/<username>?start=<code>`
/// deep link alongside the code; when absent, the code is still issued
/// and the deep link is simply omitted.
pub const BOT_USERNAME_KEY: &str = "TELEGRAM_BOT_USERNAME";

/// The config key holding the HMAC key the action buttons' tokens are
/// signed with. Absent or blank fails closed: [`send_action_prompt`]
/// cannot issue and every tap is refused.
pub const ACTION_SECRET_KEY: &str = "TELEGRAM_ACTION_SECRET";

/// The config key holding the web app's base URL — where a value-moving
/// action's passkey confirmation happens. Telegram is told it as a URL
/// button with the action id appended to its query string (`?action=…`,
/// joined with `&` when the URL already carries a query).
pub const APPROVAL_URL_KEY: &str = "TELEGRAM_APPROVAL_URL";

/// How long a link code works: ten minutes. Long enough to switch from
/// the web app to Telegram and press send; short enough that a code
/// pasted into a group chat hours ago is dead paper.
pub const LINK_CODE_TTL: TimeDuration = TimeDuration::seconds(10 * 60);

/// The four tables the module owns (issue #764).
const TABLES: &[&str] = &[
    "telegram_inbox",
    "telegram_link_codes",
    "telegram_links",
    "telegram_actions",
];

/// The one migration: all four tables, created together.
const MIGRATION_INIT: SqlMigration = SqlMigration::new(
    "0001",
    "init",
    include_str!("../migrations/sqlite/0001_init.sql"),
);

/// A venture hook: called inline as part of handling a delivery (or a
/// confirm request). Its error is the delivery's `5xx` — which is what
/// makes Telegram retry, and what keeps the dedup key unclaimed.
pub type TelegramHook<T> = Arc<dyn Fn(T) -> BoxFuture<'static, Result<(), AnyError>> + Send + Sync>;

/// A Telegram account has been linked to a subject — the end of a
/// successful `/start <code>` in a private chat.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Linked {
    /// The subject the account is now linked to.
    pub subject: String,
    /// The Telegram user id that pressed `/start`.
    pub telegram_user_id: i64,
    /// The private chat the link was made in — where this subject's
    /// prompts and notifications go.
    pub chat_id: i64,
}

/// A consent decision, reported to the venture's `on_action` hook.
///
/// The two paths that produce one:
///
/// - a Telegram tap — Deny, or Approve of a non-value-moving action;
///   [`passkey_confirmed`](Self::passkey_confirmed) is `false`;
/// - the web app's confirm route finishing a value-moving action —
///   always [`Decision::Approve`] with
///   [`passkey_confirmed`](Self::passkey_confirmed) `true`, because a
///   fresh passkey ceremony stood behind it.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ActionDecision {
    /// The id [`send_action_prompt`] reported, and the `{action_id}` of
    /// the confirm route — stable across every path that names it.
    pub action_id: String,
    /// The account the action belonged to.
    pub subject: String,
    /// The app-defined label the request carried, verbatim.
    pub action: String,
    /// Which way it was decided.
    pub decision: Decision,
    /// Whether a fresh passkey ceremony stood behind the approval
    /// (`true` only on the confirm route's path).
    pub passkey_confirmed: bool,
}

/// The venture's hooks: `TelegramEvents::new().on_message(|message| ...)`.
///
/// Every hook is optional. An update kind with no hook is still handled
/// — linking, the action buttons and the dedup ledger all run; only the
/// venture's part is a no-op.
#[derive(Clone, Default)]
pub struct TelegramEvents {
    message: Option<TelegramHook<Message>>,
    command: Option<TelegramHook<Command>>,
    callback: Option<TelegramHook<CallbackQuery>>,
    channel_post: Option<TelegramHook<ChannelPost>>,
    linked: Option<TelegramHook<Linked>>,
    action: Option<TelegramHook<ActionDecision>>,
}

// Closures are not `Debug`; whether a hook is wired is, and the hook
// itself never is.
impl std::fmt::Debug for TelegramEvents {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TelegramEvents")
            .field("on_message", &self.message.is_some())
            .field("on_command", &self.command.is_some())
            .field("on_callback", &self.callback.is_some())
            .field("on_channel_post", &self.channel_post.is_some())
            .field("on_linked", &self.linked.is_some())
            .field("on_action", &self.action.is_some())
            .finish()
    }
}

impl TelegramEvents {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Calls `hook` with every plain message. A hook error fails the
    /// delivery with a `5xx` and leaves the dedup key unclaimed, so
    /// Telegram's redelivery re-runs it.
    #[must_use]
    pub fn on_message(
        mut self,
        hook: impl Fn(Message) -> BoxFuture<'static, Result<(), AnyError>> + Send + Sync + 'static,
    ) -> Self {
        self.message = Some(Arc::new(hook));
        self
    }

    /// Calls `hook` with every `/command` — including `/start` when it
    /// arrives without a code, or from a group chat rather than the
    /// private conversation linking happens in.
    #[must_use]
    pub fn on_command(
        mut self,
        hook: impl Fn(Command) -> BoxFuture<'static, Result<(), AnyError>> + Send + Sync + 'static,
    ) -> Self {
        self.command = Some(Arc::new(hook));
        self
    }

    /// Calls `hook` with every button press whose `data` is not one of
    /// this module's action tokens — the venture's own keyboard buttons.
    #[must_use]
    pub fn on_callback(
        mut self,
        hook: impl Fn(CallbackQuery) -> BoxFuture<'static, Result<(), AnyError>> + Send + Sync + 'static,
    ) -> Self {
        self.callback = Some(Arc::new(hook));
        self
    }

    /// Calls `hook` with every channel post (edits included, flagged).
    #[must_use]
    pub fn on_channel_post(
        mut self,
        hook: impl Fn(ChannelPost) -> BoxFuture<'static, Result<(), AnyError>> + Send + Sync + 'static,
    ) -> Self {
        self.channel_post = Some(Arc::new(hook));
        self
    }

    /// Calls `hook` when a `/start <code>` links an account. After this
    /// fires, the subject's prompts and notifications go to the chat.
    #[must_use]
    pub fn on_linked(
        mut self,
        hook: impl Fn(Linked) -> BoxFuture<'static, Result<(), AnyError>> + Send + Sync + 'static,
    ) -> Self {
        self.linked = Some(Arc::new(hook));
        self
    }

    /// Calls `hook` with every finished consent decision — a Telegram
    /// tap (`passkey_confirmed: false`) or the web app's passkey
    /// confirmation (`true`). Value-moving approvals fired **only** from
    /// the confirm route never reach Telegram taps.
    #[must_use]
    pub fn on_action(
        mut self,
        hook: impl Fn(ActionDecision) -> BoxFuture<'static, Result<(), AnyError>>
        + Send
        + Sync
        + 'static,
    ) -> Self {
        self.action = Some(Arc::new(hook));
        self
    }
}

/// What the handlers hold, once the module is composed: the hooks plus
/// the three injected seams.
#[derive(Clone)]
pub(crate) struct TelegramState {
    pub(crate) events: TelegramEvents,
    pub(crate) bot: Option<Arc<dyn TelegramBot>>,
    pub(crate) random: Option<Arc<dyn RandomBytes>>,
    pub(crate) step_up: Option<Arc<dyn StepUp>>,
}

// Closures and ports are not `Debug`; which seams are wired is.
impl std::fmt::Debug for TelegramState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TelegramState")
            .field("events", &self.events)
            .field("bot", &self.bot.is_some())
            .field("random", &self.random.is_some())
            .field("step_up", &self.step_up.is_some())
            .finish()
    }
}

/// The Telegram module: the webhook, account linking, and the consent
/// buttons.
#[derive(Default, Clone)]
pub struct Telegram {
    events: TelegramEvents,
    bot: Option<Arc<dyn TelegramBot>>,
    random: Option<Arc<dyn RandomBytes>>,
    step_up: Option<Arc<dyn StepUp>>,
}

// Ports and closures are not `Debug`; which seams are wired is.
impl std::fmt::Debug for Telegram {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Telegram")
            .field("events", &self.events)
            .field("bot", &self.bot.is_some())
            .field("random", &self.random.is_some())
            .field("step_up", &self.step_up.is_some())
            .finish()
    }
}

impl Telegram {
    /// A module with the given venture hooks; `TelegramEvents::new()` for
    /// none.
    #[must_use]
    pub fn new(events: TelegramEvents) -> Self {
        Self {
            events,
            bot: None,
            random: None,
            step_up: None,
        }
    }

    /// Injects the bot the module talks to — a
    /// [`FakeTelegramBot`](cratefield_adapter_telegram::fake::FakeTelegramBot)
    /// in tests, or the adapter's `HttpTelegramBot` in production.
    /// Without one (and without `TELEGRAM_BOT_TOKEN` to build one from),
    /// replies and prompts are skipped with a warning; the webhook keeps
    /// working.
    #[must_use]
    pub fn bot(mut self, bot: Arc<dyn TelegramBot>) -> Self {
        self.bot = Some(bot);
        self
    }

    /// Injects the entropy source link codes and action ids are drawn
    /// from. Without one, `POST /link-codes` answers `500` and no prompt
    /// can be issued; [`Module::self_check`] names the missing argument.
    #[must_use]
    pub fn random(mut self, random: impl RandomBytes + 'static) -> Self {
        self.random = Some(Arc::new(random));
        self
    }

    /// Injects the step-up verifier the confirm route requires before a
    /// value-moving action may finish. Without one, the route answers
    /// `403` — fail closed, never open.
    #[must_use]
    pub fn step_up(mut self, step_up: Arc<dyn StepUp>) -> Self {
        self.step_up = Some(step_up);
        self
    }

    fn state(&self) -> TelegramState {
        TelegramState {
            events: self.events.clone(),
            bot: self.bot.clone(),
            random: self.random.clone(),
            step_up: self.step_up.clone(),
        }
    }
}

impl Module for Telegram {
    fn name(&self) -> &'static str {
        MODULE_NAME
    }

    fn version(&self) -> &'static str {
        env!("CARGO_PKG_VERSION")
    }

    fn requires(&self) -> &'static [Port] {
        // Clock: every expiry — link codes, action prompts, token
        // expiries — is judged against it.
        &[Port::Db, Port::Clock]
    }

    fn optional(&self) -> &'static [Port] {
        // Auth: `/link-codes`, `/link` and the confirm route work for a
        // signed-in caller and refuse everyone else; without the port
        // they refuse everyone, which is the honest answer.
        // HttpClient: the bot is built from it when none was injected.
        &[Port::Auth, Port::HttpClient]
    }

    fn tables(&self) -> &'static [&'static str] {
        TABLES
    }

    fn personal_data(&self) -> &'static [PersonalDataSet] {
        const SETS: &[PersonalDataSet] = &[
            PersonalDataSet::none(
                "telegram_inbox",
                "The ids of the Telegram updates this venture has already processed — a dedup \
                 ledger, so a provider that delivers twice is processed once. It holds update \
                 ids and timestamps and nothing about a person.",
            ),
            PersonalDataSet {
                table: "telegram_link_codes",
                subject: "subject",
                kind: DataKind::Identifier,
                disposition: Disposition::Erase,
                description: "One-time codes issued so a person can connect their Telegram \
                    account, held only as SHA-256 hashes alongside who they were issued to and \
                    when they expire. Erasing a person's rows deletes their outstanding codes; \
                    an expired or used code is deleted by nothing here — the row is kept so a \
                    replay stays refused, and holds no secret.",
                redacted: &[],
                subject_via: None,
            },
            PersonalDataSet {
                table: "telegram_links",
                subject: "subject",
                kind: DataKind::Identifier,
                disposition: Disposition::Erase,
                description: "The link between an account and a Telegram user: the Telegram \
                    user id and the chat id messages are sent to, and when the link was made. \
                    Erasing a person's rows unlinks them — nothing more is sent to that chat. \
                    Messages already delivered to the chat live in Telegram, not here.",
                redacted: &[],
                subject_via: None,
            },
            PersonalDataSet {
                table: "telegram_actions",
                subject: "subject",
                kind: DataKind::Usage,
                disposition: Disposition::Erase,
                description: "The consent requests a person was shown in Telegram: what they \
                    were asked to approve, whether it moves value, and how it was decided. \
                    Erasing a person's rows deletes that record of what they were asked and \
                    answered.",
                redacted: &[],
                subject_via: None,
            },
        ];
        SETS
    }

    fn emits(&self) -> &'static [&'static str] {
        &[]
    }

    /// The route is a provider webhook guarded by Telegram's shared
    /// secret token.
    fn signature_verification(&self) -> SignatureVerification {
        SignatureVerification::Hmac {
            secret: SECRET_KEY_SUFFIX,
        }
    }

    fn migrations(&self) -> Migrations {
        const MIGRATIONS: [SqlMigration; 1] = [MIGRATION_INIT];
        const _: () = cratefield_core::assert_migration_set(&MIGRATIONS);
        Migrations::sqlite(&MIGRATIONS)
    }

    fn validate_config(&self, cfg: &dyn Config) -> Result<(), ConfigError> {
        // Absent stays legal for every key: the webhook fails closed per
        // request, the app routes answer without their niceties, and a
        // venture that mounts the module but never wires Telegram is not
        // unbootable. Set-but-blank is a typo, not a choice.
        let module = ModuleConfig::new(MODULE_NAME, cfg);
        let mut errors = ConfigError::default();

        for (suffix, full, what) in [
            (
                SECRET_KEY_SUFFIX,
                WEBHOOK_SECRET_KEY,
                "the webhook shared secret",
            ),
            ("BOT_TOKEN", BOT_TOKEN_KEY, "the bot token"),
            ("BOT_USERNAME", BOT_USERNAME_KEY, "the bot username"),
            (
                "ACTION_SECRET",
                ACTION_SECRET_KEY,
                "the action signing secret",
            ),
            ("APPROVAL_URL", APPROVAL_URL_KEY, "the approval URL"),
        ] {
            if let Some(value) = cfg.get(&module.key(suffix))
                && value.trim().is_empty()
            {
                errors.push(format!(
                    "telegram: {full} is set but blank; unset it or give {what}"
                ));
            }
        }

        // Telegram itself refuses a secret-token outside this shape, so a
        // secret the adapter's verifier accepts and Telegram rejects would
        // silently accept nothing.
        if let Some(secret) = cfg.get(&module.key(SECRET_KEY_SUFFIX))
            && !secret.trim().is_empty()
            && !cratefield_adapter_telegram::webhook::is_valid_secret(&secret)
        {
            errors.push(
                "telegram: TELEGRAM_WEBHOOK_SECRET must be 1-256 characters of A-Z a-z 0-9 _ - \
                 — Telegram refuses anything else for its secret token"
                    .to_owned(),
            );
        }

        errors.into_result()
    }

    /// The composition a build should hear about. Nothing here comes
    /// from the environment; the fix is in the composition.
    fn self_check(&self) -> Vec<String> {
        let mut problems = Vec::new();
        if self.random.is_none() {
            problems.push(
                "telegram: no entropy source is configured, so no link code or action id can \
                 be drawn — add `.random(impl RandomBytes)` to the module"
                    .to_owned(),
            );
        }
        problems
    }

    fn router(&self, ctx: ModuleContext) -> axum::Router {
        handlers::router(ctx, self.state())
    }

    fn surface(&self) -> cratefield_core::Surface {
        handlers::surface()
    }
}
