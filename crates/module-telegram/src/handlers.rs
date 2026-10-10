//! The module's four routes.
//!
//! `POST /webhook` is Telegram's: it verifies the
//! `X-Telegram-Bot-Api-Secret-Token` header over the raw body before any
//! JSON is read, deduplicates on the update id, then dispatches to the
//! venture's hooks and to the two flows this module owns — account
//! linking and the action buttons. A hook that fails is a `5xx` with the
//! dedup key unclaimed, and the step that already committed — the
//! decision, the spent link code — is rolled back first, so Telegram's
//! redelivery re-runs the whole step rather than finding it done.
//!
//! The other three are the venture's app-side routes: `POST /link-codes`
//! and `DELETE /link` act for the signed-in caller, and
//! `POST /actions/{action_id}/confirm` is the web app's passkey
//! confirmation that — and only that — can move a value-moving action
//! past `awaiting_passkey`.

use std::sync::Arc;

use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, post};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as BASE64URL;
use serde::Serialize;
use serde_json::json;
use sha2::{Digest, Sha256};
use time::OffsetDateTime;

use cratefield_adapter_telegram::webhook::{self, WebhookError};
use cratefield_adapter_telegram::{
    CallbackQuery, ChatKind, Command, InlineButton, OutgoingMessage, TelegramBot, UpdateKind,
};
use cratefield_core::{
    Action, Audience, Clock, DbError, Inbox, Json, ModuleContext, Outcome, Problem, ProblemDef,
    RoutePolicy, Scope, Surface, SystemClock,
};

use crate::store;
use crate::token::{self, Decision, VerifiedToken};
use crate::{
    APPROVAL_URL_KEY, BOT_USERNAME_KEY, Linked, TelegramHook, TelegramState, WEBHOOK_SECRET_KEY,
};

/// "Now" through the Clock port when present, `SystemClock` otherwise.
fn now_of(ctx: &ModuleContext) -> OffsetDateTime {
    ctx.ports
        .clock
        .as_ref()
        .map_or_else(|| SystemClock.now(), |clock| clock.now())
}

/// Now, as the Unix seconds an action token carries: past 2106 becomes
/// the far future, which reads as "already expired" — fail closed.
fn now_unix_u32(now: OffsetDateTime) -> u32 {
    u32::try_from(now.unix_timestamp()).unwrap_or(u32::MAX)
}

// ---------------------------------------------------------------------------
// Problem definitions

/// The one refusal for a delivery that does not prove itself.
const UNVERIFIED: ProblemDef = ProblemDef {
    slug: "telegram/unverified",
    status: StatusCode::UNAUTHORIZED,
    title: "Unverified delivery",
    description: "The delivery carried no secret token this deployment could verify, or one \
                  that did not hold.",
};

const UNAUTHENTICATED: ProblemDef = ProblemDef {
    slug: "telegram/unauthenticated",
    status: StatusCode::UNAUTHORIZED,
    title: "Sign in first",
    description: "This route is available only to a signed-in user.",
};

const NO_SUCH_ACTION: ProblemDef = ProblemDef {
    slug: "telegram/no-such-action",
    status: StatusCode::NOT_FOUND,
    title: "No such action",
    description: "No action with that id exists.",
};

const NOT_YOURS: ProblemDef = ProblemDef {
    slug: "telegram/action-not-yours",
    status: StatusCode::FORBIDDEN,
    title: "Not your action",
    description: "Actions are confirmed by the account they were requested for.",
};

const NOT_CONFIRMABLE: ProblemDef = ProblemDef {
    slug: "telegram/action-not-confirmable",
    status: StatusCode::CONFLICT,
    title: "Action cannot be confirmed",
    description: "The action is not awaiting passkey confirmation, or it has expired, or it \
                  was already confirmed.",
};

const STEP_UP_REQUIRED: ProblemDef = ProblemDef {
    slug: "telegram/passkey-required",
    status: StatusCode::FORBIDDEN,
    title: "Passkey confirmation required",
    description: "Approving a value-moving action needs a fresh passkey ceremony, and this \
                  request did not carry one this deployment could verify.",
};

fn internal(scope: &Scope) -> Problem {
    Problem::internal().instance(&scope.request_id)
}

/// A database failure is ours and is logged, not described to the caller.
fn db_problem(error: &DbError, scope: &Scope) -> Problem {
    tracing::error!(error = %error, "telegram: a database statement failed");
    internal(scope)
}

// ---------------------------------------------------------------------------
// State and wiring

/// What every handler holds: the module context and the composed
/// settings, together so no handler re-pairs them.
struct HandlerState {
    ctx: Arc<ModuleContext>,
    settings: TelegramState,
}

pub(crate) fn router(ctx: cratefield_core::ModuleContext, settings: TelegramState) -> axum::Router {
    axum::Router::new()
        .route("/webhook", post(receive))
        .route("/link-codes", post(create_link_code))
        .route("/link", delete(unlink))
        .route("/actions/{action_id}/confirm", post(confirm))
        .with_state(Arc::new(HandlerState {
            ctx: Arc::new(ctx),
            settings,
        }))
}

/// The dedup ledger: one row per Telegram update id.
fn inbox() -> Inbox {
    Inbox::new("telegram_inbox")
}

pub(crate) fn surface() -> Surface {
    Surface::new()
        .action(Action::post("webhook", "/webhook").policy(RoutePolicy::Signature))
        .action(
            Action::post("create-link-code", "/link-codes")
                .audience(Audience::Subject)
                .outcome(Outcome::Json)
                .output::<LinkCodeResponse>(),
        )
        .action(Action::delete("delete-link", "/link").audience(Audience::Subject))
        .action(
            Action::post("confirm-action", "/actions/{action_id}/confirm")
                .audience(Audience::Subject)
                .outcome(Outcome::Json),
        )
}

/// The bot the module talks through: the injected one, or an
/// [`HttpTelegramBot`](cratefield_adapter_telegram::HttpTelegramBot) built
/// per request from the `HttpClient` and `Clock` ports and
/// `TELEGRAM_BOT_TOKEN`. `None` — nothing injected, no ports, no token —
/// means replies are skipped with a warning; it never means a crash, and
/// the token never reaches a log line.
fn bot_of(state: &HandlerState) -> Option<Arc<dyn TelegramBot>> {
    if let Some(bot) = state.settings.bot.clone() {
        return Some(bot);
    }
    let http = state.ctx.ports.http.clone()?;
    let clock = state.ctx.ports.clock.clone()?;
    let token = state
        .ctx
        .config
        .get(crate::BOT_TOKEN_KEY)
        .filter(|token| !token.trim().is_empty())?;
    Some(Arc::new(cratefield_adapter_telegram::HttpTelegramBot::new(
        http, clock, token,
    )))
}

/// The `TELEGRAM_ACTION_SECRET` bytes; absent or blank means `None`,
/// which both issuing and tapping treat as "refuse, and say so in the
/// log".
fn action_key_of(state: &HandlerState) -> Option<Vec<u8>> {
    state
        .ctx
        .config
        .get(crate::ACTION_SECRET_KEY)
        .filter(|secret| !secret.trim().is_empty())
        .map(String::into_bytes)
}

/// Sends a message when there is a bot to send it with. Best-effort: a
/// failed reply is a warning, never a failed request — the effects are
/// already in the database, and a `5xx` would only buy a duplicate.
async fn send_message(state: &HandlerState, message: OutgoingMessage) {
    let Some(bot) = bot_of(state) else {
        tracing::warn!(
            "telegram: no bot configured (inject .bot(..) or set TELEGRAM_BOT_TOKEN); \
             the reply is skipped"
        );
        return;
    };
    if let Err(error) = bot.send_message(&message).await {
        tracing::warn!(error = %error, "telegram: the reply could not be sent");
    }
}

/// A plain text reply.
async fn send_text(state: &HandlerState, chat_id: i64, text: &str) {
    send_message(state, OutgoingMessage::new(chat_id, text)).await;
}

/// Acknowledges a callback query when there is a bot — what stops the
/// client's spinner. Best-effort, like a reply.
async fn answer_callback(state: &HandlerState, callback_query_id: &str, text: &str) {
    let Some(bot) = bot_of(state) else {
        tracing::warn!("telegram: no bot configured; the callback was not acknowledged");
        return;
    };
    if let Err(error) = bot.answer_callback(callback_query_id, Some(text)).await {
        tracing::warn!(error = %error, "telegram: answerCallbackQuery failed");
    }
}

/// The lower-case SHA-256 hex of a link code — the only form a code ever
/// takes in the database.
fn sha256_hex(input: &str) -> String {
    hex::encode(Sha256::digest(input.as_bytes()))
}

/// Calls one venture hook. Its error is the delivery's (or the route
/// response's) `5xx`, logged here because the problem the caller sees
/// never describes it.
async fn run_hook<T: Send + 'static>(
    hook: Option<&TelegramHook<T>>,
    scope: &Scope,
    payload: T,
) -> Result<(), Problem> {
    let Some(hook) = hook else {
        return Ok(());
    };
    match hook(payload).await {
        Ok(()) => Ok(()),
        Err(error) => {
            tracing::warn!(error = %error, "telegram: a venture hook failed");
            Err(internal(scope))
        }
    }
}

// ---------------------------------------------------------------------------
// POST /v1/telegram/webhook

/// `POST /v1/telegram/webhook` — one verified delivery in. Effects run
/// **before** the [`inbox()`] claim commits: a hook failure is a `5xx`
/// with the key unclaimed, so Telegram's retry re-runs the delivery —
/// at-least-once (a crash between effect and claim can double-run) beats
/// at-most-once (a swallowed update).
async fn receive(
    State(state): State<Arc<HandlerState>>,
    scope: Scope,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Result<Response, Problem> {
    let Some(secret) = state
        .ctx
        .config
        .get(WEBHOOK_SECRET_KEY)
        .filter(|secret| !secret.trim().is_empty())
    else {
        // Fail closed: without the shared token nothing can be verified,
        // and pretending otherwise would serve every forged delivery.
        tracing::error!("telegram: no webhook secret configured; every delivery is refused");
        return Err(
            Problem::not_ready("telegram has no webhook secret configured")
                .instance(&scope.request_id),
        );
    };
    let Some(db) = state.ctx.ports.db.clone() else {
        return Err(internal(&scope));
    };
    let now = now_of(&state.ctx);

    // Verify over the raw bytes before any JSON is read; the adapter owns
    // the scheme and the parse.
    let update = webhook::parse_verified(&secret, &headers, &body, now.unix_timestamp()).map_err(
        |error| match error {
            WebhookError::Unverified => Problem::new(&UNVERIFIED).instance(&scope.request_id),
            WebhookError::Malformed => {
                Problem::validation_failed("the body is not a well-formed Telegram update")
                    .instance(&scope.request_id)
            }
        },
    )?;
    let update_key = update.update_id.to_string();

    if inbox()
        .seen(&*db, &update_key)
        .await
        .map_err(|error| db_problem(&error, &scope))?
    {
        return Ok(ok());
    }

    dispatch(&state, &scope, &update.kind).await?;

    // Commits last: reaching here means every fallible step succeeded, so
    // a `false` (a concurrent delivery won the race) only means the same
    // work ran twice — still a `200`.
    inbox()
        .claim(&*db, &update_key, &store::stamp(now))
        .await
        .map_err(|error| db_problem(&error, &scope))?;
    Ok(ok())
}

/// Runs the flow one update kind belongs to. `Ok` means the update may be
/// claimed; an `Err` is the `5xx` that keeps the key unclaimed for the
/// redelivery.
async fn dispatch(state: &HandlerState, scope: &Scope, kind: &UpdateKind) -> Result<(), Problem> {
    match kind {
        // `/start <code>` from a private chat is the account-linking
        // flow; the same command anywhere else is the venture's to
        // answer, through the command hook.
        UpdateKind::Command(command)
            if command.name == "start"
                && !command.args.is_empty()
                && command.message.chat.kind == ChatKind::Private =>
        {
            link(state, scope, command).await
        }
        UpdateKind::Command(command) => {
            run_hook(
                state.settings.events.command.as_ref(),
                scope,
                command.clone(),
            )
            .await
        }
        UpdateKind::CallbackQuery(callback) => {
            let is_action = callback
                .data
                .as_deref()
                .is_some_and(|data| data.starts_with(token::ACTION_TOKEN_PREFIX));
            if is_action {
                tap(state, scope, callback).await
            } else {
                run_hook(
                    state.settings.events.callback.as_ref(),
                    scope,
                    callback.clone(),
                )
                .await
            }
        }
        UpdateKind::Message(message) => {
            run_hook(
                state.settings.events.message.as_ref(),
                scope,
                message.clone(),
            )
            .await
        }
        UpdateKind::ChannelPost(posted) => {
            run_hook(
                state.settings.events.channel_post.as_ref(),
                scope,
                posted.clone(),
            )
            .await
        }
        // `edited_message` and every payload the adapter does not model:
        // claimed without an effect, so the redelivery is a no-op.
        UpdateKind::Other => Ok(()),
    }
}

// ---------------------------------------------------------------------------
// POST /v1/telegram/link-codes

/// The response of `POST /link-codes`.
#[derive(Debug, Serialize, schemars::JsonSchema)]
pub struct LinkCodeResponse {
    /// The one-time code, 43 base64url characters — inside Telegram's
    /// 64-character `start` parameter with room to spare.
    pub code: String,
    /// `https://t.me/<bot>?start=<code>`, ready to open. Present only
    /// when `TELEGRAM_BOT_USERNAME` is configured, because the deep link
    /// names the bot; a venture that has not named it gets no deep link
    /// rather than a broken one, and the code pastes into `/start`
    /// either way.
    pub deep_link: Option<String>,
    /// When the code stops working, RFC 3339.
    pub expires_at: String,
}

/// Identifies the caller, or answers a 401 problem. An anonymous caller
/// is refused; a credential that did not verify is an error.
async fn require_subject(
    ctx: &ModuleContext,
    headers: &HeaderMap,
    scope: &Scope,
) -> Result<String, Problem> {
    let auth = ctx
        .ports
        .auth
        .clone()
        .ok_or_else(|| Problem::new(&UNAUTHENTICATED).instance(&scope.request_id))?;
    match auth.identify(headers).await {
        Ok(caller) => caller
            .id()
            .map(str::to_owned)
            .ok_or_else(|| Problem::new(&UNAUTHENTICATED).instance(&scope.request_id)),
        // Anonymous, any other caller shape, and a failing authenticator
        // are all the same answer: this module has nothing to say
        // without a session, and it does not distinguish them.
        Err(_) => Err(Problem::new(&UNAUTHENTICATED).instance(&scope.request_id)),
    }
}

/// `POST /v1/telegram/link-codes` — issues a one-time code for the
/// signed-in caller. The code exists only in the response (and the deep
/// link it is pasted into); the database holds its SHA-256 hash, so a
/// database read can never mint a link.
async fn create_link_code(
    scope: Scope,
    State(state): State<Arc<HandlerState>>,
    headers: HeaderMap,
) -> Result<Response, Problem> {
    let subject = require_subject(&state.ctx, &headers, &scope).await?;
    let Some(db) = state.ctx.ports.db.clone() else {
        return Err(internal(&scope));
    };
    // Fail closed, and loudly: a composition that cannot draw entropy
    // issues nothing. `self_check` names the missing builder argument.
    let Some(random) = state.settings.random.clone() else {
        tracing::error!("telegram: no entropy source configured; no link code can be drawn");
        return Err(internal(&scope));
    };

    let mut bytes = [0u8; 32];
    random.fill(&mut bytes).map_err(|error| {
        tracing::error!(error = %error, "telegram: the entropy source failed");
        internal(&scope)
    })?;
    let code = BASE64URL.encode(bytes);

    let now = now_of(&state.ctx);
    let expires_at = now + crate::LINK_CODE_TTL;
    store::insert_code(
        &*db,
        &sha256_hex(&code),
        &subject,
        &store::stamp(expires_at),
    )
    .await
    .map_err(|error| db_problem(&error, &scope))?;

    let deep_link = state
        .ctx
        .config
        .get(BOT_USERNAME_KEY)
        .filter(|username| !username.trim().is_empty())
        .map(|username| format!("https://t.me/{username}?start={code}"));
    let body = LinkCodeResponse {
        code,
        deep_link,
        expires_at: store::stamp(expires_at),
    };
    let value = serde_json::to_value(body).unwrap_or_default();
    Ok(Json(value).into_response())
}

/// `DELETE /v1/telegram/link` — removes the caller's link. Idempotent: a
/// subject without one still gets `200`.
async fn unlink(
    scope: Scope,
    State(state): State<Arc<HandlerState>>,
    headers: HeaderMap,
) -> Result<Response, Problem> {
    let subject = require_subject(&state.ctx, &headers, &scope).await?;
    let Some(db) = state.ctx.ports.db.clone() else {
        return Err(internal(&scope));
    };
    let deleted = store::delete_link(&*db, &subject)
        .await
        .map_err(|error| db_problem(&error, &scope))?;
    if deleted > 0 {
        // The id, never the Telegram identifiers — this line can land in
        // an operator's logs.
        tracing::info!(subject = %subject, "telegram: link removed");
    }
    Ok(ok())
}

/// `POST /v1/telegram/actions/{action_id}/confirm` — the web app's half
/// of a value-moving approval. Telegram put the action into
/// `awaiting_passkey`; this route is the only thing that can take it
/// further, and only when the configured [`StepUp`](crate::StepUp)
/// proves a fresh passkey ceremony for the owning subject.
async fn confirm(
    scope: Scope,
    State(state): State<Arc<HandlerState>>,
    headers: HeaderMap,
    Path(action_id): Path<String>,
) -> Result<Response, Problem> {
    let subject = require_subject(&state.ctx, &headers, &scope).await?;
    // Fail closed: no configured step-up means no confirmation, ever.
    let Some(step_up) = state.settings.step_up.clone() else {
        return Err(Problem::new(&STEP_UP_REQUIRED).instance(&scope.request_id));
    };
    let Some(db) = state.ctx.ports.db.clone() else {
        return Err(internal(&scope));
    };
    let Some(row) = store::action_by_id(&*db, &action_id)
        .await
        .map_err(|error| db_problem(&error, &scope))?
    else {
        return Err(Problem::new(&NO_SUCH_ACTION).instance(&scope.request_id));
    };
    if row.subject != subject {
        return Err(Problem::new(&NOT_YOURS).instance(&scope.request_id));
    }
    let now = now_of(&state.ctx);
    let now_stamp = store::stamp(now);
    // RFC 3339 with whole seconds compares lexicographically the way it
    // compares chronologically — the format every expiry in this module
    // is written in.
    if row.status != "awaiting_passkey" || row.expires_at.as_str() <= now_stamp.as_str() {
        return Err(Problem::new(&NOT_CONFIRMABLE).instance(&scope.request_id));
    }
    if !step_up.passkey_verified(&headers, &subject).await {
        return Err(Problem::new(&STEP_UP_REQUIRED).instance(&scope.request_id));
    }

    // Single-use: the update that sees one row did the confirming. The
    // conditional update is the gate — a retry that arrives while the row
    // is already `approved` is refused below, no matter how many times
    // the hook is asked.
    let confirmed = store::confirm_action(&*db, &action_id, &now_stamp)
        .await
        .map_err(|error| db_problem(&error, &scope))?;
    if confirmed != 1 {
        return Err(Problem::new(&NOT_CONFIRMABLE).instance(&scope.request_id));
    }

    // The hook runs after the commit. If it fails, the approval is rolled
    // back — but only while the row still carries the status this request
    // set — and the `5xx` goes out, so the caller's retry starts again
    // from `awaiting_passkey` and the decision can actually happen. A
    // concurrent retry that lost the conditional update was refused above
    // and touched nothing, so the rollback never fights a winner.
    let reported = run_hook(
        state.settings.events.action.as_ref(),
        &scope,
        crate::ActionDecision {
            action_id: action_id.clone(),
            subject: subject.clone(),
            action: row.action.clone(),
            decision: Decision::Approve,
            passkey_confirmed: true,
        },
    )
    .await;
    if let Err(error) = reported {
        let undone = store::revert_confirm(&*db, &action_id).await;
        log_roll_back(&action_id, "awaiting_passkey", undone);
        return Err(error);
    }

    Ok(Json(json!({ "ok": true, "status": "approved" })).into_response())
}

/// Logs the outcome of the best-effort rollback that follows a failed
/// hook. The rollback's own failure is logged and the original hook error
/// still goes out — there is nothing more this request can do, and a
/// `5xx` either way is the honest answer.
fn log_roll_back(action_id: &str, prior: &str, undone: Result<u64, DbError>) {
    match undone {
        Ok(1) => tracing::warn!(
            action_id = %action_id,
            "telegram: a failed hook rolled the action back to {prior}"
        ),
        Ok(0) => tracing::warn!(
            action_id = %action_id,
            "telegram: a failed hook could not roll the action back; the row had already moved"
        ),
        Ok(_) => tracing::error!(
            action_id = %action_id,
            "telegram: a rollback touched more than one row"
        ),
        Err(error) => tracing::error!(
            action_id = %action_id,
            error = %error,
            "telegram: the rollback after a failed hook failed too"
        ),
    }
}

// ---------------------------------------------------------------------------
// The linking flow: a `/start <code>` from a private chat

async fn link(state: &HandlerState, scope: &Scope, command: &Command) -> Result<(), Problem> {
    let Some(db) = state.ctx.ports.db.clone() else {
        return Err(internal(scope));
    };
    let now_stamp = store::stamp(now_of(&state.ctx));
    // A private chat usually names its sender; an absent one means the
    // message is not answerable by the person who must be linked.
    // Claimed with a polite reply rather than a `5xx` — nothing a retry
    // fixes.
    let Some(user) = command.message.from.as_ref() else {
        send_text(
            state,
            command.message.chat.id,
            "I could not tell who sent that. Open a private chat with me and try again.",
        )
        .await;
        return Ok(());
    };

    let code_hash = sha256_hex(command.args.trim());
    let consumed = store::consume_code(&*db, &code_hash, &now_stamp)
        .await
        .map_err(|error| db_problem(&error, scope))?;
    if consumed != 1 {
        send_text(
            state,
            command.message.chat.id,
            "That link code has expired or was already used. Start again from the app.",
        )
        .await;
        return Ok(());
    }

    // From here the code is spent. Any failure below — a database
    // statement, or the venture's `on_linked` — puts it back before the
    // `5xx` leaves, so Telegram's redelivery runs the whole flow again.
    // The link row is deliberately not undone: the upsert may have
    // replaced a previous link, which no rollback could restore, and the
    // retry's upsert writes the same values again — the "already linked
    // elsewhere" check passes, because the user now links this very
    // subject — so re-running the flow is clean.
    let flow = async {
        let Some(subject) = store::code_subject(&*db, &code_hash)
            .await
            .map_err(|error| db_problem(&error, scope))?
        else {
            // Unreachable in practice: the code existed a statement ago.
            return Err(internal(scope));
        };

        // One Telegram user stands behind at most one account. A user already
        // linked elsewhere is refused, in the chat — nobody silently
        // repoints someone else's account by forwarding a deep link.
        let existing = store::subject_of_telegram_user(&*db, user.id)
            .await
            .map_err(|error| db_problem(&error, scope))?;
        if existing.is_some_and(|linked| linked != subject) {
            tracing::warn!(
                subject = %subject,
                "telegram: a deep link for an already-linked Telegram user was refused"
            );
            send_text(
                state,
                command.message.chat.id,
                "This Telegram account is already linked to a different account. \
                 Unlink it there first, then try again.",
            )
            .await;
            return Ok(());
        }

        store::upsert_link(&*db, &subject, user.id, command.message.chat.id, &now_stamp)
            .await
            .map_err(|error| db_problem(&error, scope))?;
        send_text(state, command.message.chat.id, "linked").await;

        run_hook(
            state.settings.events.linked.as_ref(),
            scope,
            Linked {
                subject,
                telegram_user_id: user.id,
                chat_id: command.message.chat.id,
            },
        )
        .await
    };

    match flow.await {
        Ok(()) => Ok(()),
        Err(error) => {
            let undone = store::unconsume_code(&*db, &code_hash).await;
            match undone {
                Ok(1) => {
                    tracing::warn!(
                        "telegram: a failed linking step put the link code back for the redelivery"
                    );
                }
                Ok(_) => {
                    tracing::warn!(
                        "telegram: a failed linking step could not put the code back; it had \
                         already moved"
                    );
                }
                Err(rollback_error) => {
                    tracing::error!(
                        error = %rollback_error,
                        "telegram: putting the link code back after a failed step failed too"
                    );
                }
            }
            Err(error)
        }
    }
}

// ---------------------------------------------------------------------------
// The action-button flow: a callback query whose data carries a token

async fn tap(state: &HandlerState, scope: &Scope, callback: &CallbackQuery) -> Result<(), Problem> {
    let Some(db) = state.ctx.ports.db.clone() else {
        return Err(internal(scope));
    };
    let Some(key) = action_key_of(state) else {
        // Fail closed: without the HMAC key no token this deployment
        // minted could verify, and one that verifies anyway is forged.
        tracing::error!("telegram: no action secret configured; every tap is refused");
        answer_callback(
            state,
            &callback.id,
            "This button is not available right now.",
        )
        .await;
        return Ok(());
    };
    let now = now_of(&state.ctx);
    let now_stamp = store::stamp(now);

    let opened = callback
        .data
        .as_deref()
        .and_then(|data| token::open_action_token(&key, data, callback.from.id, now_unix_u32(now)));
    let Some(VerifiedToken {
        action_id,
        decision,
        ..
    }) = opened
    else {
        // Tampered, expired, or pressed by someone the button was not
        // minted for (a forwarded button). Refused and acknowledged,
        // deliberately without saying which.
        tracing::warn!("telegram: a callback token did not verify; the tap is refused");
        answer_callback(state, &callback.id, "This button is no longer valid.").await;
        return Ok(());
    };

    let Some(row) = store::action_by_id(&*db, &action_id)
        .await
        .map_err(|error| db_problem(&error, scope))?
    else {
        answer_callback(state, &callback.id, "This request no longer exists.").await;
        return Ok(());
    };
    // The tag already bound the intended Telegram user; this re-checks
    // against the link as it stands **now**, so a tap by a user who has
    // since been re-pointed to another account cannot decide this row.
    // It also resolves the chat the prompt was sent to.
    let linked = store::link_of_subject(&*db, &row.subject)
        .await
        .map_err(|error| db_problem(&error, scope))?;
    let Some((_, chat_id)) = linked.filter(|(user_id, _)| *user_id == callback.from.id) else {
        answer_callback(state, &callback.id, "This request is not yours to decide.").await;
        return Ok(());
    };

    let target = match (decision, row.value_moving) {
        (Decision::Deny, _) => "denied",
        (Decision::Approve, false) => "approved",
        // A Telegram tap alone never authorises a value-moving action:
        // it only arms the web app's passkey confirmation, and fires no
        // hook.
        (Decision::Approve, true) => "awaiting_passkey",
    };
    let decided = store::decide_action(&*db, &action_id, target, &now_stamp)
        .await
        .map_err(|error| db_problem(&error, scope))?;
    if decided != 1 {
        // A replay, the other button after a decision, or an expired
        // prompt: the spinner stops, nothing else moves.
        answer_callback(
            state,
            &callback.id,
            "This request was already decided or has expired.",
        )
        .await;
        return Ok(());
    }

    if target == "awaiting_passkey" {
        arm_passkey(state, &callback.id, chat_id, &action_id).await;
        return Ok(());
    }

    answer_callback(
        state,
        &callback.id,
        match decision {
            Decision::Approve => "Approved.",
            Decision::Deny => "Denied.",
        },
    )
    .await;

    // The hook runs after the decision commits. If it fails, the decision
    // is rolled back — but only while the row still carries the status
    // this tap set — and the `5xx` keeps the update unclaimed, so
    // Telegram's redelivery runs the tap again and the hook again. A
    // racing replay that lost the conditional update was answered above
    // and touched nothing, so the rollback never fights a winner.
    let reported = run_hook(
        state.settings.events.action.as_ref(),
        scope,
        crate::ActionDecision {
            action_id: action_id.clone(),
            subject: row.subject.clone(),
            action: row.action.clone(),
            decision,
            passkey_confirmed: false,
        },
    )
    .await;
    if let Err(error) = reported {
        let undone = store::revert_tap(&*db, &action_id, target).await;
        log_roll_back(&action_id, "pending", undone);
        return Err(error);
    }
    Ok(())
}

/// The value-moving arm of an approve tap: the row is already
/// `awaiting_passkey` — committed by the caller — and this sends the
/// instructions. The web app's confirmation URL is a button when
/// `TELEGRAM_APPROVAL_URL` is set, plain text when it is not (logged as
/// an error: a broken link is a deployment bug, not a decision to
/// forgive); the action stays armed either way, and nothing here fires
/// the venture's hook — only `/confirm` can.
async fn arm_passkey(state: &HandlerState, callback_query_id: &str, chat_id: i64, action_id: &str) {
    let instructions = "Approved here — one more step: confirm in the web app with your \
                        passkey. A tap in Telegram alone never moves value.";
    if let Some(url) = state
        .ctx
        .config
        .get(APPROVAL_URL_KEY)
        .filter(|url| !url.trim().is_empty())
    {
        // The action id rides the query string: a configured URL that
        // already carries one is joined with `&`, not a second `?`.
        let separator = if url.contains('?') { "&" } else { "?" };
        send_message(
            state,
            OutgoingMessage::new(chat_id, instructions).row(vec![InlineButton::url(
                "Confirm in the web app",
                format!("{url}{separator}action={action_id}"),
            )]),
        )
        .await;
    } else {
        tracing::error!(
            "telegram: TELEGRAM_APPROVAL_URL is not set; the passkey instructions \
             were sent without a button"
        );
        send_text(state, chat_id, instructions).await;
    }
    answer_callback(state, callback_query_id, "Now confirm in the web app.").await;
}

fn ok() -> Response {
    Json(json!({ "ok": true })).into_response()
}
