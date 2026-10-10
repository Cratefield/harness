//! Shared fixtures for the module's tests: a kit with the module's
//! Telegram bot replaced by the adapter's fake, the secret-token header
//! set the way Telegram sets it, and the update bodies the flows reply
//! to.
//!
//! The deliveries are built as Telegram builds them and verified by the
//! adapter's own `parse_verified` — no bypass, no test-only webhook.

#![allow(dead_code)]
// A test-support module, included with `mod support;` into each test
// binary in this crate. `pub` is how a helper reads here, and the lint is
// right that nothing outside can reach it — the module is private to every
// binary that includes it. Saying so once beats `pub(crate)` on forty
// helpers.
#![allow(unreachable_pub)]
// Interior mutability here records test observations — a scripted bot, a
// hook's calls, a step-up switch. It is not request state (ADR 0007); the
// scoped allow follows the policy in the workspace `clippy.toml`.
#![allow(clippy::disallowed_types)]
// Every accessor locks an unpoisoned fixture mutex; per-method `# Panics`
// sections would add noise without information.
#![allow(clippy::missing_panics_doc)]

use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, RwLock};

use axum::body::{Body, to_bytes};
use axum::http::{Method, Request, StatusCode};
use cratefield_adapter_telegram::fake::FakeTelegramBot;
use cratefield_adapter_telegram::webhook::SECRET_HEADER;
use cratefield_core::{MapConfig, RandomBytes, RandomError};
use cratefield_module_telegram::{
    ACTION_SECRET_KEY, StepUp, Telegram, TelegramEvents, WEBHOOK_SECRET_KEY,
};
use cratefield_testing::{FakeAuth, TestHarness};
use http::HeaderMap;
use serde_json::{Value, json};
use tower::ServiceExt;

/// The webhook secret the kit configures — the shape
/// `is_valid_secret` accepts.
pub const SECRET: &str = "tg-test-secret-1";
/// The kit's `FixedClock` epoch: every expiry is judged against it.
pub const NOW: i64 = 1_800_000_000;
/// The module's mount point.
pub const BASE: &str = "/v1/telegram";

/// A signed-in subject, as [`FakeAuth::subjects`] reads one: the bearer
/// token **is** the subject id.
pub const ALICE: &str = "acct-alice";
pub const BOB: &str = "acct-bob";

/// The Telegram user and private chat the fixtures speak from — one
/// person, one chat, like a real link.
pub const TG_USER: i64 = 42;
pub const CHAT: i64 = 42;

/// The action secret the kit configures, as bytes.
pub const ACTION_KEY: &[u8] = b"tg-test-action-secret";

/// Entropy a test can predict: every draw fills with the same byte. The
/// action ids and link codes stay deterministic; nothing in these tests
/// depends on their *values*, only that they were drawn.
pub struct FixedRandom(pub u8);

impl RandomBytes for FixedRandom {
    fn fill(&self, dest: &mut [u8]) -> Result<(), RandomError> {
        dest.fill(self.0);
        Ok(())
    }
}

/// A [`StepUp`] a test drives by switch: `ok` decides, and the counter
/// says whether the route asked at all.
pub struct FakeStepUp {
    pub ok: AtomicBool,
    pub calls: AtomicUsize,
}

impl FakeStepUp {
    pub fn accepting() -> Arc<Self> {
        Arc::new(Self {
            ok: AtomicBool::new(true),
            calls: AtomicUsize::new(0),
        })
    }

    pub fn refusing() -> Arc<Self> {
        Arc::new(Self {
            ok: AtomicBool::new(false),
            calls: AtomicUsize::new(0),
        })
    }

    pub fn count(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
    }
}

#[async_trait::async_trait]
impl StepUp for FakeStepUp {
    async fn passkey_verified(&self, _headers: &HeaderMap, _subject: &str) -> bool {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.ok.load(Ordering::SeqCst)
    }
}

/// What a venture hook recorded.
pub type Calls<T> = Arc<RwLock<Vec<T>>>;

/// The kit's config pairs: the webhook and action secrets always, the
/// rest as the test asks.
pub fn config(extra: Vec<(&'static str, &'static str)>) -> Vec<(&'static str, &'static str)> {
    let mut pairs = vec![
        (WEBHOOK_SECRET_KEY, SECRET),
        (ACTION_SECRET_KEY, "tg-test-action-secret"),
    ];
    pairs.extend(extra);
    pairs
}

/// A kit with the module composed over the given hooks and config, its
/// bot a [`FakeTelegramBot`] the test can inspect, its entropy
/// [`FixedRandom`], and — when `step_up` says so — the passkey verifier
/// the confirm route asks. Auth is [`FakeAuth::subjects`]: a bearer token
/// is the subject.
pub fn kit_with(
    events: TelegramEvents,
    pairs: Vec<(&'static str, &'static str)>,
    step_up: Option<Arc<dyn StepUp>>,
) -> (TestHarness, Arc<FakeTelegramBot>) {
    let bot = Arc::new(FakeTelegramBot::new());
    let mut module = Telegram::new(events)
        .bot(Arc::clone(&bot) as _)
        .random(FixedRandom(0xA5));
    if let Some(step_up) = step_up {
        module = module.step_up(step_up);
    }
    let kit = TestHarness::with_ports(vec![Box::new(module)], |ports| {
        ports.config = Arc::new(MapConfig::from_pairs(pairs));
        ports.auth = Some(Arc::new(FakeAuth::subjects()));
    });
    (kit, bot)
}

/// The everyday kit: both secrets, no bot username, no approval URL, an
/// accepting step-up.
pub fn kit(events: TelegramEvents) -> (TestHarness, Arc<FakeTelegramBot>) {
    kit_with(events, config(vec![]), Some(FakeStepUp::accepting()))
}

/// Delivers one raw webhook body with `secret` in the secret-token
/// header (`None` sends no header at all). Answers the status and the
/// problem-or-ok JSON.
pub async fn deliver(kit: &TestHarness, secret: Option<&str>, body: &[u8]) -> (StatusCode, Value) {
    let mut builder = Request::builder()
        .method(Method::POST)
        .uri(format!("{BASE}/webhook"));
    if let Some(secret) = secret {
        builder = builder.header(SECRET_HEADER, secret);
    }
    let response = kit
        .router
        .clone()
        .oneshot(
            builder
                .header("content-type", "application/json")
                .body(Body::from(body.to_vec()))
                .expect("request builds"),
        )
        .await
        .expect("router answers");
    body_of(response).await
}

/// Posts an app-route JSON body, optionally as `subject` (a bearer token
/// `FakeAuth::subjects` reads as the subject id).
pub async fn post(
    kit: &TestHarness,
    path: &str,
    subject: Option<&str>,
    body: Value,
) -> (StatusCode, Value) {
    let mut builder = Request::builder()
        .method(Method::POST)
        .uri(format!("{BASE}{path}"));
    if let Some(subject) = subject {
        builder = builder.header("authorization", format!("Bearer {subject}"));
    }
    let response = kit
        .router
        .clone()
        .oneshot(
            builder
                .header("content-type", "application/json")
                .body(Body::from(body.to_string()))
                .expect("request builds"),
        )
        .await
        .expect("router answers");
    body_of(response).await
}

/// Deletes an app route, optionally as `subject`.
pub async fn delete(kit: &TestHarness, path: &str, subject: Option<&str>) -> (StatusCode, Value) {
    let mut builder = Request::builder()
        .method(Method::DELETE)
        .uri(format!("{BASE}{path}"));
    if let Some(subject) = subject {
        builder = builder.header("authorization", format!("Bearer {subject}"));
    }
    let response = kit
        .router
        .clone()
        .oneshot(builder.body(Body::empty()).expect("request builds"))
        .await
        .expect("router answers");
    body_of(response).await
}

async fn body_of(response: axum::http::Response<Body>) -> (StatusCode, Value) {
    let status = response.status();
    let bytes = to_bytes(response.into_body(), 64 * 1024)
        .await
        .expect("body reads");
    let body = if bytes.is_empty() {
        Value::Null
    } else {
        serde_json::from_slice(&bytes)
            .unwrap_or(Value::String(String::from_utf8_lossy(&bytes).into_owned()))
    };
    (status, body)
}

// ---------------------------------------------------------------------------
// Update bodies, as Telegram sends them

/// One update: `kind` is the wire key (`"message"`, `"callback_query"`,
/// …) and `inner` its payload.
pub fn update(update_id: i64, kind: &str, inner: Value) -> Vec<u8> {
    let mut body = json!({ "update_id": update_id });
    body[kind] = inner;
    body.to_string().into_bytes()
}

/// A private-chat message from [`TG_USER`].
pub fn message(text: &str) -> Value {
    json!({
        "message_id": 11,
        "chat": { "id": CHAT, "type": "private" },
        "from": { "id": TG_USER, "is_bot": false, "first_name": "Ada" },
        "date": NOW,
        "text": text,
    })
}

/// A `/command args` from a private chat. The entity's length is the
/// command word's — what Telegram measures, and what the adapter slices
/// the name by.
pub fn command(text: &str) -> Value {
    let length = command_length(text);
    json!({
        "message_id": 12,
        "chat": { "id": CHAT, "type": "private" },
        "from": { "id": TG_USER, "is_bot": false, "first_name": "Ada" },
        "date": NOW,
        "text": text,
        "entities": [{ "type": "bot_command", "offset": 0, "length": length }],
    })
}

/// The byte length of a text's leading command word (`/start` is 6).
fn command_length(text: &str) -> usize {
    text.split([' ', '@']).next().map_or(0, str::len)
}

/// The same `/command` from a group — where linking never happens.
pub fn group_command(text: &str) -> Value {
    json!({
        "message_id": 13,
        "chat": { "id": -10099, "type": "supergroup", "title": "Ops" },
        "from": { "id": TG_USER, "is_bot": false, "first_name": "Ada" },
        "date": NOW,
        "text": text,
        "entities": [
            { "type": "bot_command", "offset": 0, "length": command_length(text) }
        ],
    })
}

/// A button press by `user_id`.
pub fn callback_from(data: &str, user_id: i64) -> Value {
    json!({
        "id": format!("cq{user_id}"),
        "from": { "id": user_id, "is_bot": false, "first_name": "Ada" },
        "message": {
            "message_id": 7,
            "chat": { "id": CHAT, "type": "private" },
        },
        "data": data,
    })
}

/// A button press by [`TG_USER`].
pub fn callback(data: &str) -> Value {
    callback_from(data, TG_USER)
}

/// A channel post.
pub fn channel_post(text: &str) -> Value {
    json!({
        "message_id": 21,
        "chat": { "id": -1001, "type": "channel", "title": "Announcements" },
        "date": NOW,
        "text": text,
    })
}

// ---------------------------------------------------------------------------
// Database reads the assertions share

/// The subjects linked in `telegram_links`, with their Telegram user ids.
pub fn linked_subjects(kit: &TestHarness) -> Vec<(String, i64)> {
    use cratefield_core::Statement;
    use sea_query::{Alias, Expr, Query};

    let mut select = Query::select();
    select
        .columns(["subject", "telegram_user_id"])
        .from(Alias::new("telegram_links"))
        .order_by_expr(
            Expr::col(Alias::new("subject")).into(),
            sea_query::Order::Asc,
        );
    let rows = pollster::block_on(kit.db.query(&Statement::render(&select)))
        .expect("links read")
        .rows;
    rows.iter()
        .map(|row| {
            (
                row.get("subject").expect("subject reads"),
                row.get::<i64>("telegram_user_id").expect("user reads"),
            )
        })
        .collect()
}

/// The `status` column of one action row.
pub fn action_status(kit: &TestHarness, action_id: &str) -> Option<String> {
    use cratefield_core::Statement;
    use sea_query::{Alias, Expr, Query};

    let mut select = Query::select();
    select
        .column(Alias::new("status"))
        .from(Alias::new("telegram_actions"))
        .and_where(Expr::col(Alias::new("action_id")).eq(action_id));
    pollster::block_on(kit.db.query(&Statement::render(&select)))
        .expect("action read")
        .first()
        .and_then(|row| row.get("status"))
}

/// The `code_hash` column of every link-code row.
pub fn stored_code_hashes(kit: &TestHarness) -> Vec<String> {
    use cratefield_core::Statement;
    use sea_query::{Alias, Query};

    let mut select = Query::select();
    select
        .column(Alias::new("code_hash"))
        .from(Alias::new("telegram_link_codes"));
    pollster::block_on(kit.db.query(&Statement::render(&select)))
        .expect("codes read")
        .rows
        .iter()
        .filter_map(|row| row.get("code_hash"))
        .collect()
}

/// The `consumed_at` of the row a code is stored under — `Some` while the
/// code is spent, `None` while it is spendable (or no row exists, which
/// no test here needs telling apart).
pub fn code_consumed_at(kit: &TestHarness, code: &str) -> Option<String> {
    use cratefield_core::Statement;
    use sea_query::{Alias, Expr, Query};

    let mut select = Query::select();
    select
        .column(Alias::new("consumed_at"))
        .from(Alias::new("telegram_link_codes"))
        .and_where(Expr::col(Alias::new("code_hash")).eq(code_hash_of(code)));
    pollster::block_on(kit.db.query(&Statement::render(&select)))
        .expect("code read")
        .first()
        .and_then(|row| row.get("consumed_at"))
}

/// The lower-case SHA-256 hex of a link code — the only form a code takes
/// in the database.
pub fn code_hash_of(code: &str) -> String {
    use sha2::{Digest, Sha256};
    hex::encode(Sha256::digest(code.as_bytes()))
}

/// Inserts a link row directly — the linking flow has its own tests;
/// these only need a subject whose account is linked.
pub fn insert_link(kit: &TestHarness, subject: &str, user_id: i64, chat_id: i64) {
    use cratefield_core::Statement;
    use sea_query::{Alias, Query};

    let mut insert = Query::insert();
    insert
        .into_table(Alias::new("telegram_links"))
        .columns(["subject", "telegram_user_id", "chat_id", "linked_at"])
        .values_panic([
            subject.into(),
            user_id.into(),
            chat_id.into(),
            rfc3339(NOW).into(),
        ]);
    let affected =
        pollster::block_on(kit.db.execute(&Statement::render(&insert))).expect("link inserts");
    assert_eq!(affected, 1);
}

/// Inserts an action row directly, with an explicit status and expiry
/// offset from `NOW` — the prompt path has its own tests.
pub fn insert_action(
    kit: &TestHarness,
    action_id: &str,
    subject: &str,
    status: &str,
    value_moving: bool,
    expires_in: i64,
) {
    use cratefield_core::Statement;
    use sea_query::{Alias, Query};

    let mut insert = Query::insert();
    insert
        .into_table(Alias::new("telegram_actions"))
        .columns([
            "action_id",
            "subject",
            "action",
            "value_moving",
            "status",
            "expires_at",
            "created_at",
        ])
        .values_panic([
            action_id.into(),
            subject.into(),
            "transfer".into(),
            i64::from(value_moving).into(),
            status.into(),
            rfc3339(NOW + expires_in).into(),
            rfc3339(NOW).into(),
        ]);
    let affected =
        pollster::block_on(kit.db.execute(&Statement::render(&insert))).expect("action inserts");
    assert_eq!(affected, 1);
}

/// Sends one action prompt for `subject` through the public API — the
/// same call a venture makes. Answers the error, for the refusal tests.
pub fn try_send_prompt(
    kit: &TestHarness,
    bot: &FakeTelegramBot,
    subject: &str,
    value_moving: bool,
) -> Result<cratefield_module_telegram::ActionPrompt, cratefield_module_telegram::ActionError> {
    use cratefield_module_telegram::{ActionRequest, send_action_prompt};

    let request = ActionRequest {
        subject: subject.to_owned(),
        action: "transfer".to_owned(),
        text: "Send 50 to the pool?".to_owned(),
        value_moving,
        ttl: std::time::Duration::from_secs(600),
    };
    pollster::block_on(send_action_prompt(
        &*kit.db,
        &kit.clock,
        &FixedRandom(0xA5),
        bot,
        ACTION_KEY,
        request,
    ))
}

/// Sends one action prompt, expecting success.
pub fn send_prompt(
    kit: &TestHarness,
    bot: &FakeTelegramBot,
    subject: &str,
    value_moving: bool,
) -> cratefield_module_telegram::ActionPrompt {
    try_send_prompt(kit, bot, subject, value_moving).expect("the prompt sends")
}

/// The callback `data` of the button labelled `label` in the last message
/// the bot was asked to send — how a test finds the token a tap replays.
pub fn callback_data(bot: &FakeTelegramBot, label: &str) -> Option<String> {
    use cratefield_adapter_telegram::ButtonKind;

    let sent = bot.sent();
    let message = sent.last()?;
    message
        .buttons
        .iter()
        .flatten()
        .find(|button| button.text == label)
        .and_then(|button| match &button.kind {
            ButtonKind::Callback(data) => Some(data.clone()),
            ButtonKind::Url(_) => None,
        })
}

/// The `Url` of the button labelled `label` in the last message the bot
/// was asked to send.
pub fn button_url(bot: &FakeTelegramBot, label: &str) -> Option<String> {
    use cratefield_adapter_telegram::ButtonKind;

    let sent = bot.sent();
    let message = sent.last()?;
    message
        .buttons
        .iter()
        .flatten()
        .find(|button| button.text == label)
        .and_then(|button| match &button.kind {
            ButtonKind::Url(url) => Some(url.clone()),
            ButtonKind::Callback(_) => None,
        })
}

/// An RFC 3339 stamp at Unix `at` — the format every expiry in the
/// module is written in.
pub fn rfc3339(at: i64) -> String {
    time::OffsetDateTime::from_unix_timestamp(at)
        .expect("a plain timestamp")
        .format(&time::format_description::well_known::Rfc3339)
        .expect("a plain timestamp formats")
}
