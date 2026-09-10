//! The routes under `/v1/notifications` (issue #182).
//!
//! Every route here is `public_writes = false`: the account comes from the
//! [`Authenticated`] extractor and never from a body field, and a
//! subscription that belongs to another account answers **404**, not 403 —
//! a 403 would confirm that the id exists.

use std::collections::BTreeMap;
use std::sync::Arc;

use axum::extract::{FromRequestParts, Path, State};
use axum::http::request::Parts;
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, get, put};
use cratefield_core::{
    Clock, IdGen, Json, ModuleConfig, ModuleContext, Problem, ProblemDef, Recipient, Scope,
    SystemClock, UlidIdGen,
};
use factory0_auth_client::{AuthClient, AuthState, Authenticated, UNAUTHENTICATED};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::Settings;
use crate::store::{self, Channels, Transport};

/// A category the venture does not declare. Distinct from
/// `validation-failed` because the fix is different: the caller is not
/// malformed, it named something this deployment does not have.
pub const UNKNOWN_CATEGORY: ProblemDef = ProblemDef {
    slug: "unknown-category",
    status: StatusCode::BAD_REQUEST,
    title: "Unknown notification category",
    description: "The named category is not declared by this venture.",
};

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
    use time::format_description::well_known::Rfc3339;
    let at = match state.ctx.ports.clock.as_ref() {
        Some(clock) => clock.now(),
        None => SystemClock.now(),
    };
    at.replace_nanosecond(0)
        .unwrap_or(at)
        .format(&Rfc3339)
        .unwrap_or_default()
}

fn new_id(state: &ModuleState) -> String {
    match state.ctx.ports.id_gen.as_ref() {
        Some(id_gen) => id_gen.ulid(),
        None => UlidIdGen.ulid(),
    }
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
    let id = store::upsert_subscription(
        &*db,
        &store::NewSubscription {
            id: &new_id(&state),
            account_id: &account_id,
            recipient: &recipient,
            app_id: body.app_id.as_deref(),
            app_version: body.app_version.as_deref(),
            user_agent,
            now: &now(&state),
        },
    )
    .await
    .map_err(|err| {
        tracing::error!(error = %err, "registering a subscription failed");
        internal(&scope)
    })?;
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
    let stored = store::preferences_for_account(&*db, &account_id)
        .await
        .map_err(|err| {
            tracing::error!(error = %err, "reading preferences failed");
            internal(&scope)
        })?;
    let at = now(&state);

    let mut statements = Vec::with_capacity(body.preferences.len());
    for (category, patch) in &body.preferences {
        let existing = stored.iter().find(|(name, _)| name == category);
        let current = existing.map_or_else(
            || {
                Channels::all(
                    state
                        .settings
                        .category(category)
                        .is_some_and(|declared| declared.default_enabled),
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
            &account_id,
            category,
            next,
            existing.is_some(),
            &at,
        ));
    }
    if !statements.is_empty() {
        db.batch(&statements).await.map_err(|err| {
            tracing::error!(error = %err, "writing preferences failed");
            internal(&scope)
        })?;
    }

    let stored = store::preferences_for_account(&*db, &account_id)
        .await
        .map_err(|err| {
            tracing::error!(error = %err, "reading preferences back failed");
            internal(&scope)
        })?;
    Ok(Json(effective(&state.settings, &stored)).into_response())
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
            .map_or_else(
                || Channels::all(category.default_enabled),
                |(_, channels)| *channels,
            );
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
