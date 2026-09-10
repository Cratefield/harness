//! The routes under `/v1/notifications` (issue #182).
//!
//! Every route here takes its account from the [`Authenticated`]
//! extractor and never from a body field, and a subscription that belongs
//! to another account answers **404**, not 403 — a 403 would confirm that
//! the id exists.
//!
//! Two routes are the exception, and both because the caller cannot hold
//! a session: the RFC 8058 one-click unsubscribe a mailbox provider posts
//! (#189), and the provider bounce delivery (#233). Each carries its own
//! proof — a signed token, a Svix signature — and the module declares
//! that with [`public_writes`] and [`public_write_policy`].
//!
//! [`public_writes`]: cratefield_core::Module::public_writes
//! [`public_write_policy`]: cratefield_core::Module::public_write_policy

use std::collections::BTreeMap;
use std::sync::Arc;

use axum::extract::{FromRequestParts, Path, Query, State};
use axum::http::request::Parts;
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, get, post, put};
use cratefield_core::{Json, ModuleConfig, ModuleContext, Problem, ProblemDef, Recipient, Scope};
use factory0_auth_client::{AuthClient, AuthState, Authenticated, UNAUTHENTICATED};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::Settings;
use crate::clock;
use crate::store::{self, Channels, Transport, Upserted};

/// A category the venture does not declare. Distinct from
/// `validation-failed` because the fix is different: the caller is not
/// malformed, it named something this deployment does not have.
pub const UNKNOWN_CATEGORY: ProblemDef = ProblemDef {
    slug: "unknown-category",
    status: StatusCode::BAD_REQUEST,
    title: "Unknown notification category",
    description: "The named category is not declared by this venture.",
};

/// This caller has taken over too many devices from other accounts inside
/// the window (`NOTIFICATIONS_REHOME_MAX_PER_HOUR`).
///
/// Its own `type` rather than the shared `rate-limited` one: nothing about
/// the request rate is wrong, and the client that legitimately hits it —
/// somebody signing into a shared tablet — needs to be told which limit it
/// met.
pub const REHOME_LIMIT: ProblemDef = ProblemDef {
    slug: "device-rehome-limit",
    status: StatusCode::TOO_MANY_REQUESTS,
    title: "Too many devices taken over",
    description: "This account has claimed too many devices that belonged to other accounts.",
};

/// How long the re-home budget counts over.
const REHOME_WINDOW_SECS: i64 = 3_600;

pub(crate) struct ModuleState {
    pub ctx: Arc<ModuleContext>,
    pub settings: Settings,
    /// `None` when the venture did not configure an auth issuer, or
    /// provides no `HttpClient` port. Every route then answers 401: the
    /// module cannot establish who is calling, and guessing is the one
    /// thing it must not do.
    pub auth: Option<Arc<AuthClient>>,
}

pub(crate) fn router(state: Arc<ModuleState>) -> axum::Router {
    axum::Router::new()
        .route("/subscriptions", put(register).get(list_subscriptions))
        .route("/subscriptions/{id}", delete(unregister))
        .route("/preferences", get(read_preferences).put(write_preferences))
        .route("/", get(list_inbox))
        .route("/unread-count", get(unread_count))
        .route("/{id}/read", post(mark_read))
        .route("/read-all", post(mark_all_read))
        .route("/{id}", delete(archive))
        .route("/email", put(set_email))
        .route(
            "/email/unsubscribe",
            get(unsubscribe_page).post(unsubscribe_one_click),
        )
        .route("/email/webhook", post(provider_webhook))
        .with_state(state)
}

/// Builds the token verifier from configuration, or `None` when this
/// deployment cannot verify tokens at all.
pub(crate) fn auth_client(ctx: &ModuleContext) -> Option<Arc<AuthClient>> {
    let cfg = ModuleConfig::new(crate::MODULE_NAME, &*ctx.config);
    let issuer = cfg.get_opt("AUTH_ISSUER")?;
    let client_id = cfg.get_opt("AUTH_CLIENT_ID")?;
    let http = ctx.ports.http.clone()?;
    let clock = ctx.ports.clock.clone()?;
    Some(Arc::new(AuthClient::new(http, clock, issuer, client_id)))
}

/// The calling account.
///
/// It exists so no handler can read an account id from anywhere else: the
/// only way to obtain one is to have presented a token this venture's auth
/// service signed for this client.
pub(crate) struct Account(pub String);

impl FromRequestParts<Arc<ModuleState>> for Account {
    type Rejection = Problem;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &Arc<ModuleState>,
    ) -> Result<Self, Self::Rejection> {
        let Some(client) = state.auth.clone() else {
            tracing::error!(
                "notifications: no token verifier — set NOTIFICATIONS_AUTH_ISSUER and \
                 NOTIFICATIONS_AUTH_CLIENT_ID and provide an HttpClient port; every route \
                 answers 401 until then"
            );
            return Err(Problem::new(&UNAUTHENTICATED));
        };
        // Delegated, not reimplemented: `factory0-auth-client` owns the
        // header parsing, the algorithm check, the JWKS cache and the one
        // refusal every failure collapses into.
        let Authenticated(claims) =
            Authenticated::from_request_parts(parts, &AuthState(client)).await?;
        Ok(Account(claims.sub))
    }
}

/// [`Account`], keeping the rest of the claims.
///
/// Only the email route needs them, and it needs them for one reason: it
/// is the only place the module can learn that an address is verified
/// without inventing its own confirmation flow. Taking `Account` *and*
/// `Authenticated` on one handler would verify the same token twice.
pub(crate) struct AccountClaims(pub factory0_auth_client::Claims);

impl FromRequestParts<Arc<ModuleState>> for AccountClaims {
    type Rejection = Problem;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &Arc<ModuleState>,
    ) -> Result<Self, Self::Rejection> {
        let Some(client) = state.auth.clone() else {
            return Err(Problem::new(&UNAUTHENTICATED));
        };
        let Authenticated(claims) =
            Authenticated::from_request_parts(parts, &AuthState(client)).await?;
        Ok(AccountClaims(claims))
    }
}

// ---------------------------------------------------------------------------
// Bodies

/// A recipient on the wire, in the port's own JSON form.
///
/// A mirror of [`Recipient`] rather than the type itself, because the port
/// does not derive `JsonSchema` and a module's body types must. The mirror
/// is byte-compatible with `Recipient`'s serialisation — including the
/// `web_push` tag, which is the port's spelling and not the `webpush` of
/// the `transport` column — and `tests/routes.rs` pins that.
#[derive(Debug, Clone, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum RecipientBody {
    Apns {
        device_token: String,
    },
    Fcm {
        registration_token: String,
    },
    WebPush {
        endpoint: String,
        p256dh: String,
        auth: String,
    },
}

impl From<RecipientBody> for Recipient {
    fn from(body: RecipientBody) -> Self {
        match body {
            RecipientBody::Apns { device_token } => Recipient::Apns { device_token },
            RecipientBody::Fcm { registration_token } => Recipient::Fcm { registration_token },
            RecipientBody::WebPush {
                endpoint,
                p256dh,
                auth,
            } => Recipient::WebPush {
                endpoint,
                p256dh,
                auth,
            },
        }
    }
}

/// `PUT /v1/notifications/subscriptions`. There is deliberately no
/// `account_id`: it comes from the token.
#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RegisterBody {
    /// Which transport the client believes it is registering. Checked
    /// against the recipient, so a client that builds the wrong shape
    /// learns at registration rather than at the first silent non-send.
    pub transport: Transport,
    pub recipient: RecipientBody,
    #[serde(default)]
    pub app_id: Option<String>,
    #[serde(default)]
    pub app_version: Option<String>,
}

/// `PUT /v1/notifications/preferences`. Omitted channels keep the value
/// the account already had (or the category's default).
#[derive(Debug, Default, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ChannelPatch {
    #[serde(default)]
    pub push: Option<bool>,
    #[serde(default)]
    pub in_app: Option<bool>,
    #[serde(default)]
    pub email: Option<bool>,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PreferencesBody {
    pub preferences: BTreeMap<String, ChannelPatch>,
}

#[derive(Debug, Serialize)]
struct SubscriptionView {
    id: String,
    transport: &'static str,
    /// The recipient, redacted to a prefix: enough to tell two devices
    /// apart, never enough to push to one.
    recipient_preview: String,
    app_id: Option<String>,
    app_version: Option<String>,
    created_at: String,
    last_seen_at: String,
}

// ---------------------------------------------------------------------------
// Handlers

fn internal(scope: &Scope) -> Problem {
    Problem::internal().instance(&scope.request_id)
}

fn now(state: &ModuleState) -> String {
    clock::now_iso(state.ctx.ports.clock.as_ref())
}

fn new_id(state: &ModuleState) -> String {
    clock::new_id(state.ctx.ports.id_gen.as_ref())
}

/// How many devices one account may take over from other accounts in an
/// hour (`NOTIFICATIONS_REHOME_MAX_PER_HOUR`, default 3; `0` refuses every
/// cross-account re-home).
fn rehome_limit(state: &ModuleState) -> usize {
    let configured = ModuleConfig::new(crate::MODULE_NAME, &*state.ctx.config)
        .get_u32("REHOME_MAX_PER_HOUR", state.settings.rehome_max_per_hour);
    usize::try_from(configured).unwrap_or(usize::MAX)
}

/// Registers a device, or re-registers one the account already has.
async fn register(
    scope: Scope,
    State(state): State<Arc<ModuleState>>,
    headers: HeaderMap,
    Account(account_id): Account,
    Json(body): Json<RegisterBody>,
) -> Result<Response, Problem> {
    let recipient: Recipient = body.recipient.into();
    let actual = Transport::of(&recipient);
    if actual != body.transport {
        return Err(Problem::validation_failed(format!(
            "transport says {} but the recipient is a {} recipient",
            body.transport, actual
        ))
        .instance(&scope.request_id));
    }
    let Some(db) = state.ctx.ports.db.clone() else {
        return Err(internal(&scope));
    };
    let user_agent = headers
        .get(header::USER_AGENT)
        .and_then(|value| value.to_str().ok());
    let at = now(&state);
    let outcome = store::upsert_subscription(
        &*db,
        &store::NewSubscription {
            id: &new_id(&state),
            account_id: &account_id,
            recipient: &recipient,
            app_id: body.app_id.as_deref(),
            app_version: body.app_version.as_deref(),
            user_agent,
            now: &at,
            rehome_cutoff: &clock::plus_secs(&at, -REHOME_WINDOW_SECS),
            rehome_limit: rehome_limit(&state),
        },
    )
    .await
    .map_err(|err| {
        tracing::error!(error = %err, "registering a subscription failed");
        internal(&scope)
    })?;

    let id = match outcome {
        Upserted::Created(id) | Upserted::Refreshed(id) => id,
        Upserted::Rehomed {
            id,
            previous_account_id,
        } => {
            // A device token is not an authenticator, and this is the one
            // write that acts on one alone. Nobody confirms it, so the
            // venture is told: the previous owner has stopped receiving
            // on a device it may well still be holding.
            tracing::warn!(
                subscription = %id,
                transport = %actual,
                "a subscription changed account"
            );
            state.ctx.events.emit_in(
                &scope,
                crate::EVENT_SUBSCRIPTION_REHOMED,
                json!({
                    "subscription_id": id,
                    "account_id": account_id,
                    "previous_account_id": previous_account_id,
                    "transport": actual.as_str(),
                    "at": at,
                }),
            );
            id
        }
        Upserted::RehomeRefused => {
            tracing::warn!(
                account = %account_id,
                transport = %actual,
                "refused a device take-over: this account has spent its re-home budget"
            );
            return Err(Problem::new(&REHOME_LIMIT)
                .with_detail(
                    "this device is registered to another account, and this account has \
                     claimed as many devices as it may in an hour",
                )
                .instance(&scope.request_id));
        }
    };
    Ok(Json(json!({ "id": id })).into_response())
}

/// The account's own subscriptions, recipients redacted.
async fn list_subscriptions(
    scope: Scope,
    State(state): State<Arc<ModuleState>>,
    Account(account_id): Account,
) -> Result<Response, Problem> {
    let Some(db) = state.ctx.ports.db.clone() else {
        return Err(internal(&scope));
    };
    let subscriptions = store::subscriptions_for_account(&*db, &account_id)
        .await
        .map_err(|err| {
            tracing::error!(error = %err, "reading subscriptions failed");
            internal(&scope)
        })?;
    let view: Vec<SubscriptionView> = subscriptions
        .into_iter()
        .map(|subscription| SubscriptionView {
            id: subscription.id,
            transport: subscription.transport.as_str(),
            recipient_preview: preview(&subscription.recipient),
            app_id: subscription.app_id,
            app_version: subscription.app_version,
            created_at: subscription.created_at,
            last_seen_at: subscription.last_seen_at,
        })
        .collect();
    Ok(Json(json!({ "subscriptions": view })).into_response())
}

/// Sign-out. Another account's id is a 404: a 403 would confirm it exists.
async fn unregister(
    scope: Scope,
    State(state): State<Arc<ModuleState>>,
    Account(account_id): Account,
    Path(id): Path<String>,
) -> Result<Response, Problem> {
    let Some(db) = state.ctx.ports.db.clone() else {
        return Err(internal(&scope));
    };
    let deleted = store::delete_subscription_for_account(&*db, &id, &account_id)
        .await
        .map_err(|err| {
            tracing::error!(error = %err, "deleting a subscription failed");
            internal(&scope)
        })?;
    if deleted {
        Ok(StatusCode::NO_CONTENT.into_response())
    } else {
        Err(Problem::not_found().instance(&scope.request_id))
    }
}

async fn read_preferences(
    scope: Scope,
    State(state): State<Arc<ModuleState>>,
    Account(account_id): Account,
) -> Result<Response, Problem> {
    let Some(db) = state.ctx.ports.db.clone() else {
        return Err(internal(&scope));
    };
    let stored = store::preferences_for_account(&*db, &account_id)
        .await
        .map_err(|err| {
            tracing::error!(error = %err, "reading preferences failed");
            internal(&scope)
        })?;
    Ok(Json(effective(&state.settings, &stored)).into_response())
}

async fn write_preferences(
    scope: Scope,
    State(state): State<Arc<ModuleState>>,
    Account(account_id): Account,
    Json(body): Json<PreferencesBody>,
) -> Result<Response, Problem> {
    for category in body.preferences.keys() {
        if !state.settings.declares(category) {
            return Err(Problem::new(&UNKNOWN_CATEGORY)
                .with_detail(format!("unknown category {category:?}"))
                .instance(&scope.request_id));
        }
    }
    let Some(db) = state.ctx.ports.db.clone() else {
        return Err(internal(&scope));
    };
    let at = now(&state);

    // Whether each category is an INSERT or an UPDATE is decided from a
    // read, and the write that follows is not in the same unit of work as
    // that read: two `PUT`s that arrive together — a double-tap, a client
    // retry — both see no row and both INSERT, and the second one loses on
    // the primary key. So the loser rebuilds against what is there now and
    // writes once more. One retry is enough: the second attempt can only
    // find a row (nothing here deletes one), and a row is an UPDATE, which
    // no concurrent writer can turn into a conflict.
    let mut stored = read_preferences_for(&db, &account_id, &scope).await?;
    for attempt in 0..2 {
        let statements = preference_writes(&state, &account_id, &body, &stored, &at);
        if statements.is_empty() {
            break;
        }
        match db.batch(&statements).await {
            Ok(()) => break,
            Err(err) if attempt == 0 => {
                tracing::info!(error = %err, "a concurrent preference write won; retrying once");
                stored = read_preferences_for(&db, &account_id, &scope).await?;
            }
            Err(err) => {
                tracing::error!(error = %err, "writing preferences failed");
                return Err(internal(&scope));
            }
        }
    }

    let stored = read_preferences_for(&db, &account_id, &scope).await?;
    Ok(Json(effective(&state.settings, &stored)).into_response())
}

async fn read_preferences_for(
    db: &Arc<dyn cratefield_core::Database>,
    account_id: &str,
    scope: &Scope,
) -> Result<Vec<(String, Channels)>, Problem> {
    store::preferences_for_account(&**db, account_id)
        .await
        .map_err(|err| {
            tracing::error!(error = %err, "reading preferences failed");
            internal(scope)
        })
}

/// The patch applied over what is stored: an `UPDATE` for a category the
/// account already has a row for, an `INSERT` for one it does not.
fn preference_writes(
    state: &ModuleState,
    account_id: &str,
    body: &PreferencesBody,
    stored: &[(String, Channels)],
    at: &str,
) -> Vec<cratefield_core::Statement> {
    let mut statements = Vec::with_capacity(body.preferences.len());
    for (category, patch) in &body.preferences {
        let existing = stored.iter().find(|(name, _)| name == category);
        let current = existing.map_or_else(
            || {
                Channels::all(
                    state
                        .settings
                        .category(category)
                        .is_some_and(|declared| declared.defaults.push),
                )
            },
            |(_, channels)| *channels,
        );
        let next = Channels {
            push: patch.push.unwrap_or(current.push),
            in_app: patch.in_app.unwrap_or(current.in_app),
            email: patch.email.unwrap_or(current.email),
        };
        statements.push(store::write_preference_statement(
            account_id,
            category,
            next,
            existing.is_some(),
            at,
        ));
    }
    statements
}

/// Every declared category with the values that actually apply: the
/// account's row where it has one, the category's default where it does
/// not.
fn effective(settings: &Settings, stored: &[(String, Channels)]) -> serde_json::Value {
    let mut out = serde_json::Map::new();
    for category in settings.categories.iter() {
        let channels = stored
            .iter()
            .find(|(name, _)| *name == category.name)
            .map_or_else(|| category.defaults, |(_, channels)| *channels);
        out.insert(
            category.name.clone(),
            json!({
                "push": channels.push,
                "in_app": channels.in_app,
                "email": channels.email,
            }),
        );
    }
    json!({ "preferences": serde_json::Value::Object(out) })
}

/// A recipient reduced to a prefix that identifies a device to its own
/// owner and reaches nothing.
///
/// For the token transports that is the first eight characters of the
/// token. For Web Push it is the endpoint's scheme and host: the path is
/// the bearer capability, and the host is what tells Chrome from Firefox.
pub(crate) fn preview(recipient: &Recipient) -> String {
    match recipient {
        Recipient::Apns { device_token } => token_prefix(device_token),
        Recipient::Fcm { registration_token } => token_prefix(registration_token),
        Recipient::WebPush { endpoint, .. } => endpoint_origin(endpoint),
    }
}

fn token_prefix(token: &str) -> String {
    let cut = token
        .char_indices()
        .nth(8)
        .map_or(token.len(), |(index, _)| index);
    format!("{}\u{2026}", &token[..cut])
}

fn endpoint_origin(endpoint: &str) -> String {
    match endpoint.split_once("://") {
        Some((scheme, rest)) => {
            let host = rest.split('/').next().unwrap_or_default();
            format!("{scheme}://{host}/\u{2026}")
        }
        None => "\u{2026}".to_owned(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_preview_reaches_nothing() {
        let apns = preview(&Recipient::apns("abcdefghIJKLMNOP-secret-tail"));
        assert_eq!(apns, "abcdefgh\u{2026}");
        assert!(!apns.contains("secret-tail"));

        let web = preview(&Recipient::web_push(
            "https://fcm.googleapis.com/wp/cAPABILITYtokenPATH",
            "BP256dhKey",
            "AuthSecret",
        ));
        assert_eq!(web, "https://fcm.googleapis.com/\u{2026}");
        assert!(!web.contains("cAPABILITYtokenPATH"));
        assert!(!web.contains("AuthSecret"));
    }

    #[test]
    fn a_short_or_multibyte_token_does_not_panic() {
        assert_eq!(preview(&Recipient::fcm("abc")), "abc\u{2026}");
        assert_eq!(preview(&Recipient::fcm("")), "\u{2026}");
        // Slicing at byte 8 of this would land inside a character.
        let emoji = preview(&Recipient::apns("\u{1f680}\u{1f680}\u{1f680}x"));
        assert!(emoji.ends_with('\u{2026}'), "{emoji}");
    }

    #[test]
    fn the_wire_recipient_is_the_ports_own_json_form() {
        for recipient in [
            Recipient::apns("device"),
            Recipient::fcm("registration"),
            Recipient::web_push("https://push.example.test/x", "p", "a"),
        ] {
            let json = serde_json::to_string(&recipient).expect("serialises");
            let body: RecipientBody = serde_json::from_str(&json)
                .unwrap_or_else(|err| panic!("the mirror drifted from the port: {json}: {err}"));
            assert_eq!(Recipient::from(body), recipient);
        }
    }
}

// ---------------------------------------------------------------------------
// The in-app inbox (#187)

/// The most rows one page may carry. A client asking for more gets this
/// many rather than an error: the cap is the server's business, and a
/// caller that wants everything should page.
const INBOX_PAGE_MAX: u64 = 100;
/// The page size a client that names none gets.
const INBOX_PAGE_DEFAULT: u64 = 20;
/// What joins the two halves of a cursor. A character no RFC 3339
/// timestamp and no ULID contains, so the split is unambiguous.
const CURSOR_SEPARATOR: char = '~';

#[derive(Debug, Default, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
struct InboxQuery {
    /// The id of the oldest row already seen. Ids are ULIDs, so this is
    /// both the cursor and the ordering key.
    #[serde(default)]
    cursor: Option<String>,
    #[serde(default)]
    limit: Option<u64>,
    #[serde(default)]
    unread: Option<bool>,
}

/// `GET /v1/notifications` — one page of this account's inbox, newest
/// first. Archived rows are excluded.
async fn list_inbox(
    scope: Scope,
    State(state): State<Arc<ModuleState>>,
    Account(account_id): Account,
    Query(query): Query<InboxQuery>,
) -> Result<Response, Problem> {
    let Some(db) = state.ctx.ports.db.clone() else {
        return Err(internal(&scope));
    };
    let limit = query
        .limit
        .unwrap_or(INBOX_PAGE_DEFAULT)
        .min(INBOX_PAGE_MAX);
    // Opaque to the client, and deliberately so: it is the ordering pair,
    // and which columns order the list is not part of the contract. A
    // malformed one pages from the start rather than erroring — a cursor
    // is a position, and losing it is not a failed request.
    let cursor = query
        .cursor
        .as_deref()
        .and_then(|raw| raw.split_once(CURSOR_SEPARATOR));
    let items = store::inbox_page(
        &*db,
        &account_id,
        cursor,
        query.unread.unwrap_or(false),
        limit,
    )
    .await
    .map_err(|err| {
        tracing::error!(error = %err, "reading the inbox failed");
        internal(&scope)
    })?;
    // The cursor for the next page is the last id of this one, and absent
    // when the page was not full — so a client stops without a second
    // round trip that returns nothing.
    let next = (items.len() as u64 == limit)
        .then(|| {
            items
                .last()
                .map(|item| format!("{}{CURSOR_SEPARATOR}{}", item.created_at, item.id))
        })
        .flatten();
    Ok(Json(json!({ "notifications": items, "cursor": next })).into_response())
}

/// `GET /v1/notifications/unread-count` — a number the client asked for
/// and renders itself. Not an OS badge: nothing here is pushed.
async fn unread_count(
    scope: Scope,
    State(state): State<Arc<ModuleState>>,
    Account(account_id): Account,
) -> Result<Response, Problem> {
    let Some(db) = state.ctx.ports.db.clone() else {
        return Err(internal(&scope));
    };
    let unread = store::unread_count(&*db, &account_id)
        .await
        .map_err(|err| {
            tracing::error!(error = %err, "counting unread failed");
            internal(&scope)
        })?;
    Ok(Json(json!({ "unread": unread })).into_response())
}

/// `POST /v1/notifications/{id}/read`. Idempotent: reading twice keeps the
/// first timestamp. Another account's id is a 404, never a 403.
async fn mark_read(
    scope: Scope,
    State(state): State<Arc<ModuleState>>,
    Account(account_id): Account,
    Path(id): Path<String>,
) -> Result<Response, Problem> {
    let Some(db) = state.ctx.ports.db.clone() else {
        return Err(internal(&scope));
    };
    let owned = store::mark_read(&*db, &id, &account_id, &now(&state))
        .await
        .map_err(|err| {
            tracing::error!(error = %err, "marking read failed");
            internal(&scope)
        })?;
    if owned {
        Ok(StatusCode::NO_CONTENT.into_response())
    } else {
        Err(Problem::not_found().instance(&scope.request_id))
    }
}

/// `POST /v1/notifications/read-all`. Answers how many moved, so a second
/// call answering `0` is the visible proof it is idempotent.
async fn mark_all_read(
    scope: Scope,
    State(state): State<Arc<ModuleState>>,
    Account(account_id): Account,
) -> Result<Response, Problem> {
    let Some(db) = state.ctx.ports.db.clone() else {
        return Err(internal(&scope));
    };
    let marked = store::mark_all_read(&*db, &account_id, &now(&state))
        .await
        .map_err(|err| {
            tracing::error!(error = %err, "marking all read failed");
            internal(&scope)
        })?;
    Ok(Json(json!({ "marked": marked })).into_response())
}

/// `DELETE /v1/notifications/{id}` — archive, a soft delete. The row stays
/// for `fz data export` and for retention to collect.
async fn archive(
    scope: Scope,
    State(state): State<Arc<ModuleState>>,
    Account(account_id): Account,
    Path(id): Path<String>,
) -> Result<Response, Problem> {
    let Some(db) = state.ctx.ports.db.clone() else {
        return Err(internal(&scope));
    };
    let archived = store::archive(&*db, &id, &account_id, &now(&state))
        .await
        .map_err(|err| {
            tracing::error!(error = %err, "archiving failed");
            internal(&scope)
        })?;
    if archived {
        Ok(StatusCode::NO_CONTENT.into_response())
    } else {
        Err(Problem::not_found().instance(&scope.request_id))
    }
}

// ---------------------------------------------------------------------------
// Email as a channel (#189)

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
struct EmailBody {
    email: String,
}

/// `PUT /v1/notifications/email` — the address this account is mailed at.
///
/// This route exists because `notify()` has no claims to read: it runs
/// inside another module's batch or off a bus event. Here there is a
/// token, so `email_verified` in the claims is the only thing that can
/// mark an address verified without the module inventing its own
/// confirmation flow.
async fn set_email(
    scope: Scope,
    State(state): State<Arc<ModuleState>>,
    AccountClaims(claims): AccountClaims,
    Json(body): Json<EmailBody>,
) -> Result<Response, Problem> {
    let account_id = claims.sub.clone();
    let Some(db) = state.ctx.ports.db.clone() else {
        return Err(internal(&scope));
    };
    // The workspace already has one address validator, and a module with
    // its own would disagree with the waitlist's about some real address
    // sooner or later.
    let email = cratefield_core::normalize_email(&body.email);
    if let Some(reason) = cratefield_core::validation_error(&email) {
        return Err(cratefield_core::invalid_email_problem(reason).instance(&scope.request_id));
    }

    // Verified only when the issuer says this token's own address is this
    // address and is verified. Anything else is stored unverified, and an
    // unverified address is never mailed.
    let verified = claims
        .email
        .as_deref()
        .is_some_and(|claimed| claimed.eq_ignore_ascii_case(&email))
        && claims.email_verified.unwrap_or(false);

    store::set_email_target(&*db, &account_id, &email, verified, &now(&state))
        .await
        .map_err(|err| {
            tracing::error!(error = %err, "storing an email target failed");
            internal(&scope)
        })?;
    Ok(Json(json!({ "email": email, "verified": verified })).into_response())
}

/// The `(account, category)` a valid unsubscribe token names.
fn unsubscribed_subject(state: &ModuleState, token: &str) -> Option<(String, String)> {
    let signer = state.ctx.ports.signer.as_ref()?;
    let payload = signer.verify(token, crate::notify::PURPOSE_UNSUBSCRIBE)?;
    let (account, category) = payload.subject.split_once(':')?;
    Some((account.to_owned(), category.to_owned()))
}

/// Applies one unsubscribe. `all` stops the channel for the address;
/// anything else switches that one category's `email` off.
async fn apply_unsubscribe(
    state: &ModuleState,
    account_id: &str,
    category: &str,
) -> Result<(), Problem> {
    let Some(db) = state.ctx.ports.db.clone() else {
        return Ok(());
    };
    let at = now(state);
    if category == "all" {
        store::unsubscribe_all(&*db, account_id, "one-click", &at)
            .await
            .map_err(|err| {
                tracing::error!(error = %err, "unsubscribing failed");
                Problem::internal()
            })?;
        return Ok(());
    }
    let existing = store::preference(&*db, account_id, category)
        .await
        .map_err(|_| Problem::internal())?;
    let channels = Channels {
        email: false,
        ..existing.unwrap_or(Channels {
            push: true,
            in_app: true,
            email: true,
        })
    };
    db.execute(&store::write_preference_statement(
        account_id,
        category,
        channels,
        existing.is_some(),
        &at,
    ))
    .await
    .map_err(|err| {
        tracing::error!(error = %err, "unsubscribing failed");
        Problem::internal()
    })?;
    Ok(())
}

/// `POST /v1/notifications/email/unsubscribe?token=` — RFC 8058 one-click.
///
/// No login: the token *is* the authority, which is the point — a mailbox
/// provider posts this on the recipient's behalf and has no session. It is
/// signed and purpose-bound, so a link for one account cannot switch
/// another's preference off.
async fn unsubscribe_one_click(
    scope: Scope,
    State(state): State<Arc<ModuleState>>,
    Query(query): Query<TokenQuery>,
) -> Result<Response, Problem> {
    let Some((account_id, category)) = unsubscribed_subject(&state, &query.token) else {
        return Err(Problem::new(&cratefield_core::SLUGS.invalid_token).instance(&scope.request_id));
    };
    apply_unsubscribe(&state, &account_id, &category)
        .await
        .map_err(|problem| problem.instance(&scope.request_id))?;
    Ok(StatusCode::OK.into_response())
}

/// `GET` of the same link, for a person who clicked it.
async fn unsubscribe_page(
    scope: Scope,
    State(state): State<Arc<ModuleState>>,
    Query(query): Query<TokenQuery>,
) -> Result<Response, Problem> {
    let Some((account_id, category)) = unsubscribed_subject(&state, &query.token) else {
        return Err(Problem::new(&cratefield_core::SLUGS.invalid_token).instance(&scope.request_id));
    };
    apply_unsubscribe(&state, &account_id, &category)
        .await
        .map_err(|problem| problem.instance(&scope.request_id))?;
    Ok((
        StatusCode::OK,
        [(header::CONTENT_TYPE, "text/html; charset=utf-8")],
        "<!doctype html><meta charset=utf-8><title>Unsubscribed</title>\
         <p>You will not get these emails again.</p>",
    )
        .into_response())
}

#[derive(Debug, Deserialize, JsonSchema)]
struct TokenQuery {
    token: String,
}

// ---------------------------------------------------------------------------
// Bounce and complaint suppression (#233)

/// The header names Svix — and so Resend — signs a delivery with.
const SVIX_ID: &str = "svix-id";
const SVIX_TIMESTAMP: &str = "svix-timestamp";
const SVIX_SIGNATURE: &str = "svix-signature";

/// The provider event that says the mailbox is gone for good.
const EVENT_BOUNCED: &str = "email.bounced";
/// The provider event that says the recipient reported the mail as spam.
const EVENT_COMPLAINED: &str = "email.complained";

/// The bounce classification that means "never deliverable". Anything
/// else — `Transient`, `Undetermined` — is a bad day, not a bad address.
const PERMANENT: &str = "Permanent";

/// What `unsubscribed_reason` records for each.
const REASON_BOUNCE: &str = "bounce";
const REASON_COMPLAINT: &str = "complaint";

/// One refusal for every way a delivery fails to prove itself.
///
/// Deliberately one answer for "the signature is wrong" and "this
/// deployment has no webhook secret configured": a caller learns whether
/// it signed correctly, and nothing about how the endpoint is set up.
pub const WEBHOOK_UNVERIFIED: ProblemDef = ProblemDef {
    slug: "webhook-unverified",
    status: StatusCode::UNAUTHORIZED,
    title: "Unverified webhook delivery",
    description: "The delivery did not carry a signature this deployment could verify.",
};

/// The provider's webhook envelope, narrowed to what suppression needs.
#[derive(Debug, Deserialize)]
struct ProviderEvent {
    #[serde(rename = "type")]
    kind: String,
    #[serde(default)]
    data: EventData,
}

#[derive(Debug, Default, Deserialize)]
struct EventData {
    /// The recipients the provider tried. An array, because one send can
    /// have several.
    #[serde(default)]
    to: Vec<String>,
    #[serde(default)]
    bounce: Option<Bounce>,
}

#[derive(Debug, Deserialize)]
struct Bounce {
    #[serde(rename = "type", default)]
    kind: String,
}

/// `POST /v1/notifications/email/webhook` — the provider's delivery
/// events (#233).
///
/// Unauthenticated by necessity: the provider has no account here, so the
/// Svix signature over the raw body is the whole authority. It is
/// verified **before** the body is parsed, and the body is read as bytes
/// rather than as `Json` for the same reason — the signature covers the
/// exact bytes sent, and re-serialising parsed JSON would sign a
/// different string.
///
/// A hard bounce or a complaint suppresses the address for every account
/// that holds it. A soft bounce suppresses nobody: a full mailbox is not
/// a reason to stop mailing somebody forever.
///
/// Answers `200` to everything it accepted, including events it does not
/// act on — a provider retries until it gets a 2xx, and a delivery this
/// module has no rule for is handled, not failed.
async fn provider_webhook(
    scope: Scope,
    State(state): State<Arc<ModuleState>>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Result<Response, Problem> {
    let unverified = || Problem::new(&WEBHOOK_UNVERIFIED).instance(&scope.request_id);

    let Some(secret) =
        ModuleConfig::new(crate::MODULE_NAME, &*state.ctx.config).get_opt("RESEND_WEBHOOK_SECRET")
    else {
        // Names the variable, never its value.
        tracing::error!(
            "notifications: no webhook secret — set NOTIFICATIONS_RESEND_WEBHOOK_SECRET; the \
             bounce webhook refuses every delivery until then"
        );
        return Err(unverified());
    };

    let header = |name: &str| headers.get(name).and_then(|value| value.to_str().ok());
    let (Some(id), Some(timestamp), Some(signatures)) = (
        header(SVIX_ID),
        header(SVIX_TIMESTAMP),
        header(SVIX_SIGNATURE),
    ) else {
        return Err(unverified());
    };

    let delivery = crate::webhook::Delivery {
        id,
        timestamp,
        signatures,
    };
    if !crate::webhook::is_signed(
        &secret,
        &delivery,
        &body,
        clock::now_unix(state.ctx.ports.clock.as_ref()),
    ) {
        return Err(unverified());
    }

    let Ok(event) = serde_json::from_slice::<ProviderEvent>(&body) else {
        // Accepted, because it was genuinely signed by the provider, and
        // refusing would only make it redeliver the same unparsable body
        // until the endpoint is disabled. Logged without the body: a
        // serde error quotes its input, and the input is a recipient.
        tracing::warn!("a verified provider delivery did not parse as a webhook event");
        return Ok(StatusCode::OK.into_response());
    };

    let Some(reason) = suppression_reason(&event) else {
        return Ok(StatusCode::OK.into_response());
    };

    let Some(db) = state.ctx.ports.db.clone() else {
        return Err(internal(&scope));
    };
    let at = now(&state);
    let mut suppressed = 0;
    for address in &event.data.to {
        // Normalised the same way the authenticated route stores it, or
        // a bounce for `Alice@Example.com` would never find the row that
        // holds `alice@example.com`.
        let email = cratefield_core::normalize_email(address);
        if cratefield_core::validation_error(&email).is_some() {
            continue;
        }
        suppressed += store::suppress_address(&*db, &email, reason, &at)
            .await
            .map_err(|err| {
                tracing::error!(error = %err, "suppressing a bounced address failed");
                internal(&scope)
            })?;
    }
    // Counts and the event kind. Never the address.
    tracing::info!(
        event = %event.kind,
        reason,
        suppressed,
        "suppressed accounts after a provider delivery event"
    );
    Ok(StatusCode::OK.into_response())
}

/// Why this event suppresses an address, or `None` when it does not.
///
/// A complaint always does: somebody pressed "this is spam", and the next
/// mail is how a sending domain gets blocked. A bounce only does when the
/// provider called it permanent — a soft bounce is a full mailbox or a
/// greylist, and unsubscribing somebody over one would be silent and
/// unrecoverable from their side.
fn suppression_reason(event: &ProviderEvent) -> Option<&'static str> {
    match event.kind.as_str() {
        EVENT_COMPLAINED => Some(REASON_COMPLAINT),
        EVENT_BOUNCED => event
            .data
            .bounce
            .as_ref()
            .filter(|bounce| bounce.kind.eq_ignore_ascii_case(PERMANENT))
            .map(|_| REASON_BOUNCE),
        _ => None,
    }
}
