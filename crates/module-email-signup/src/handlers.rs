//! HTTP handlers for `/v1/email-signup` (architecture section 6, issue
//! #10). Every public handler runs the rate-limit check; the POST also
//! runs captcha when the port is present, and both write paths preserve
//! the no-enumeration rule: the same `202 {"ok":true}` bytes whether the
//! address is new, pending, confirmed or unsubscribed.

use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, get, post};
use cratefield_core::{
    Action, Audience, Captcha, Clock, Column, Decision, IdGen, Json, Kid, ModuleConfig,
    ModuleContext, Outcome, Payload, Problem, RateLimiter, SLUGS, Scope, SendOutcome, Signer,
    Surface, SystemClock, UlidIdGen, View, client_ip, csv_row, invalid_email_problem,
    normalize_email, rate_limit_keys, rate_limited, require_admin, validation_error,
};
use schemars::JsonSchema;
use serde::Deserialize;
use serde_json::json;
use std::sync::Arc;
use time::format_description::well_known::Rfc3339;

use crate::mail::{self, ConfirmMailData, OutgoingMail, TEMPLATE_CONFIRM, TEMPLATE_WELCOME};
use crate::store::{self, ALL_STATUSES, STATUS_CONFIRMED, STATUS_PENDING, SubscriberRow};

pub(crate) const PURPOSE_CONFIRM: &str = "email-signup.confirm";
pub(crate) const PURPOSE_UNSUBSCRIBE: &str = "email-signup.unsubscribe";

pub(crate) const EVENT_CONFIRMED: &str = "email-signup.confirmed";
pub(crate) const EVENT_UNSUBSCRIBED: &str = "email-signup.unsubscribed";
pub(crate) const WAITLIST_CONFIRMED: &str = "waitlist.confirmed";

/// One confirmation mail per address per hour (issue #10).
pub(crate) const REMAIL_AFTER_SECS: i64 = 3600;

/// The builder's compile-time settings, cloned into the router state
/// alongside the module context.
#[derive(Debug, Clone)]
pub(crate) struct Settings {
    pub double_opt_in: bool,
    pub confirm_ttl_days: u32,
    pub retention_days_pending: u32,
    pub confirmed_redirect: Option<String>,
    pub unsubscribed_redirect: Option<String>,
    pub expired_redirect: Option<String>,
    pub welcome_on_confirm: bool,
    pub subscribe_on_waitlist_confirm: bool,
}

pub(crate) struct ModuleState {
    pub ctx: Arc<ModuleContext>,
    pub settings: Settings,
}

pub(crate) fn router(ctx: Arc<ModuleContext>, settings: Settings) -> axum::Router {
    let state = Arc::new(ModuleState { ctx, settings });
    axum::Router::new()
        .route("/", post(signup))
        .route("/confirm", get(confirm))
        .route("/unsubscribe", get(unsubscribe_get).post(unsubscribe_post))
        .route("/admin/export.csv", get(admin_export))
        .route("/admin/subscribers/{id}", delete(admin_delete))
        .with_state(state)
}

pub(crate) fn now_iso() -> String {
    SystemClock
        .now()
        .replace_nanosecond(0)
        .expect("truncation stays in range")
        .format(&Rfc3339)
        .unwrap_or_default()
}

pub(crate) fn iso_ago(secs: i64) -> String {
    SystemClock
        .now()
        .replace_nanosecond(0)
        .expect("truncation stays in range")
        .saturating_sub(time::Duration::seconds(secs))
        .format(&Rfc3339)
        .unwrap_or_default()
}

fn unix_now() -> u64 {
    u64::try_from(SystemClock.now().unix_timestamp().max(0)).unwrap_or(0)
}

fn accepted() -> Response {
    (StatusCode::ACCEPTED, Json(json!({ "ok": true }))).into_response()
}

fn see_other(location: String) -> Response {
    (StatusCode::SEE_OTHER, [(header::LOCATION, location)]).into_response()
}

fn internal(scope: &Scope) -> Problem {
    Problem::internal().instance(&scope.request_id)
}

fn api_base(cfg: &ModuleConfig, ctx: &ModuleContext) -> String {
    cfg.get_opt("API_BASE")
        .unwrap_or_else(|| format!("https://api.{}", ctx.venture.domain))
}

fn configured_or_default(
    cfg: &ModuleConfig,
    key: &str,
    builder: Option<&String>,
    default: String,
) -> String {
    cfg.get_opt(key)
        .or_else(|| builder.cloned())
        .unwrap_or(default)
}

/// The 429 response when a key is over budget. Fails open (with a
/// warning) when the limiter itself is unreachable — an in-edge
/// Cloudflare binding outage must not take signups down.
async fn rate_limit(
    state: &ModuleState,
    headers: &HeaderMap,
    email: Option<&str>,
) -> Option<Response> {
    let limiter: Arc<dyn RateLimiter> = state.ctx.ports.rate_limiter.clone()?;
    let ip = client_ip(headers);
    for key in rate_limit_keys(ip.as_deref(), email) {
        match limiter.limit(&key).await {
            Ok(Decision { ok: true, .. }) => {}
            Ok(Decision {
                ok: false,
                retry_after,
            }) => return Some(rate_limited(retry_after)),
            Err(err) => {
                tracing::warn!(error = %err, key = %key, "rate limiter unavailable; allowing");
            }
        }
    }
    None
}

/// Fail-closed: with the `Captcha` port configured, a missing or rejected
/// token is a `400 captcha-failed` (architecture section 6).
async fn check_captcha(
    state: &ModuleState,
    headers: &HeaderMap,
    token: Option<&str>,
    scope: &Scope,
) -> Result<(), Problem> {
    let Some(captcha): Option<Arc<dyn Captcha>> = state.ctx.ports.captcha.clone() else {
        return Ok(());
    };
    let Some(token) = token else {
        return Err(Problem::new(&SLUGS.captcha_failed).instance(&scope.request_id));
    };
    let ip = client_ip(headers);
    match captcha.verify(token, ip.as_deref()).await {
        Ok(verdict) if verdict.ok => Ok(()),
        _ => Err(Problem::new(&SLUGS.captcha_failed).instance(&scope.request_id)),
    }
}

fn sanitize_source(raw: Option<String>) -> Option<String> {
    raw.map(|value| {
        value
            .chars()
            .map(|c| if c.is_control() { ' ' } else { c })
            .take(128)
            .collect::<String>()
            .trim()
            .to_owned()
    })
    .filter(|value| !value.is_empty())
}

fn sanitize_locale(raw: Option<String>) -> String {
    fn is_tag(tag: &str) -> bool {
        let mut parts = tag.split('-');
        let language_ok = parts.next().is_some_and(|part| {
            (2..=3).contains(&part.len()) && part.chars().all(|c| c.is_ascii_alphabetic())
        });
        let region_ok = parts.next().is_none_or(|part| {
            (2..=4).contains(&part.len()) && part.chars().all(|c| c.is_ascii_alphabetic())
        });
        language_ok && region_ok && parts.next().is_none()
    }
    match raw {
        Some(tag) if is_tag(&tag) => tag,
        _ => "en".to_owned(),
    }
}

#[derive(Deserialize, JsonSchema)]
struct SignupBody {
    #[schemars(extend(
        "x-cf-label" = "Email",
        "x-cf-widget" = "email",
        "x-cf-placeholder" = "you@example.com"
    ))]
    email: String,
    // Where the signup came from (a page or campaign slug); set by the
    // embedding page, not typed by the visitor.
    #[schemars(extend("x-cf-hidden" = true))]
    source: Option<String>,
    #[schemars(extend("x-cf-hidden" = true))]
    locale: Option<String>,
    #[schemars(extend("x-cf-hidden" = true))]
    #[serde(rename = "captchaToken")]
    captcha_token: Option<String>,
}

#[derive(Deserialize, JsonSchema)]
struct TokenQuery {
    #[schemars(extend("x-cf-hidden" = true))]
    token: String,
}

/// The module's UI surface (ADR 0010, issue #71): the signup form, the two
/// signed links, and the admin export as a table. Body types are the ones
/// the handlers deserialize, so the schema cannot drift from the route.
pub(crate) fn surface(settings: &Settings) -> Surface {
    let message = if settings.double_opt_in {
        "Check your inbox to confirm your subscription."
    } else {
        "You're subscribed."
    };
    Surface::new()
        .action(
            Action::post("subscribe", "/")
                .input::<SignupBody>()
                .captcha()
                .accepted(message),
        )
        .action(Action::get("confirm", "/confirm").input::<TokenQuery>())
        .action(Action::get("unsubscribe", "/unsubscribe").input::<TokenQuery>())
        .action(
            Action::get("export", "/admin/export.csv")
                .audience(Audience::Admin)
                .outcome(Outcome::Json),
        )
        .action(Action::delete("delete", "/admin/subscribers/{id}"))
        .view(View::form("subscribe"))
        .view(View::table(
            "export",
            [
                ("id", "Id"),
                ("email", "Email"),
                ("status", "Status"),
                ("source", "Source"),
                ("locale", "Locale"),
                ("created_at", "Created"),
                ("confirmed_at", "Confirmed"),
                ("unsubscribed_at", "Unsubscribed"),
            ]
            .into_iter()
            .map(|(key, label)| Column::new(key, label))
            .collect(),
        ))
}

async fn signup(
    scope: Scope,
    State(state): State<Arc<ModuleState>>,
    headers: HeaderMap,
    Json(body): Json<SignupBody>,
) -> Result<Response, Problem> {
    if let Some(denied) = rate_limit(&state, &headers, Some(&body.email)).await {
        return Ok(denied);
    }
    check_captcha(&state, &headers, body.captcha_token.as_deref(), &scope).await?;

    let normalized = normalize_email(&body.email);
    if let Some(reason) = validation_error(&normalized) {
        return Err(invalid_email_problem(reason).instance(&scope.request_id));
    }

    let cfg = ModuleConfig::new("email-signup", &*state.ctx.config);
    let Some(db) = state.ctx.ports.db.clone() else {
        return Err(internal(&scope));
    };

    let existing = store::find_by_normalized_email(&*db, &normalized).await?;

    // Confirmed rows are never re-mailed and never rewritten.
    if existing
        .as_ref()
        .is_some_and(|row| row.status == STATUS_CONFIRMED)
    {
        return Ok(accepted());
    }
    // At most one confirmation mail per address per hour.
    if existing
        .as_ref()
        .is_some_and(|row| row.updated_at > iso_ago(REMAIL_AFTER_SECS))
    {
        return Ok(accepted());
    }

    let source = sanitize_source(body.source);
    let locale = sanitize_locale(body.locale);
    let now = now_iso();

    if !state.settings.double_opt_in {
        return signup_without_opt_in(&state, &scope, existing, &normalized, source, &locale, &now)
            .await;
    }

    let Some(signer): Option<Arc<dyn Signer>> = state.ctx.ports.signer.clone() else {
        return Err(internal(&scope));
    };
    let ttl_days = cfg.get_u32("CONFIRM_TTL_DAYS", state.settings.confirm_ttl_days);
    let id = existing
        .as_ref()
        .map_or_else(|| UlidIdGen.ulid(), |row| row.id.clone());
    send_confirmation(
        &state,
        &scope,
        &signer,
        &cfg,
        Confirmation {
            id: id.clone(),
            normalized: normalized.clone(),
            locale: locale.clone(),
            ttl_days,
            now: now.clone(),
        },
    )
    .await?;

    match existing {
        Some(row) => {
            store::refresh_to_pending(&*db, &row.id, source.as_deref(), Some(&locale), &now)
                .await?;
        }
        None => {
            store::insert_row(
                &*db,
                &SubscriberRow {
                    id,
                    email: body.email.trim().to_owned(),
                    email_normalized: normalized,
                    status: STATUS_PENDING.to_owned(),
                    source,
                    locale: Some(locale),
                    confirmed_at: None,
                    unsubscribed_at: None,
                    created_at: now.clone(),
                    updated_at: now,
                },
            )
            .await?;
        }
    }
    Ok(accepted())
}

/// Everything [`send_confirmation`] needs for one address.
struct Confirmation {
    id: String,
    normalized: String,
    locale: String,
    ttl_days: u32,
    now: String,
}

/// Builds both tokens, renders and sends the confirmation mail. Mail
/// before write: a `NotConfigured` or failed send leaves no row, so
/// nothing traps the next attempt behind the hourly throttle.
async fn send_confirmation(
    state: &ModuleState,
    scope: &Scope,
    signer: &Arc<dyn Signer>,
    cfg: &ModuleConfig<'_>,
    confirmation: Confirmation,
) -> Result<(), Problem> {
    let Confirmation {
        id,
        normalized,
        locale,
        ttl_days,
        now,
    } = confirmation;
    let confirm_token = signer.sign(&Payload {
        purpose: PURPOSE_CONFIRM.to_owned(),
        subject: id.clone(),
        exp: Some(unix_now().saturating_add(u64::from(ttl_days) * 86_400)),
        kid: Kid::Cur,
    });
    let unsubscribe_token = signer.sign(&Payload {
        purpose: PURPOSE_UNSUBSCRIBE.to_owned(),
        subject: id.clone(),
        exp: None,
        kid: Kid::Cur,
    });
    let base = api_base(cfg, &state.ctx);
    let data = json!(ConfirmMailData {
        venture: state.ctx.venture.name.clone(),
        email: normalized.clone(),
        confirm_url: format!("{base}/v1/email-signup/confirm?token={confirm_token}"),
        unsubscribe_url: format!("{base}/v1/email-signup/unsubscribe?token={unsubscribe_token}"),
        brand: state.ctx.venture.brand.clone(),
    });
    match mail::send(
        &state.ctx,
        &OutgoingMail {
            to: normalized.clone(),
            template_id: TEMPLATE_CONFIRM,
            data,
            locale: locale.clone(),
            idempotency_key: format!("signup:{id}:{now}"),
        },
    )
    .await
    {
        Ok(SendOutcome::Sent { .. }) => Ok(()),
        Ok(SendOutcome::NotConfigured) => {
            Err(Problem::new(&SLUGS.mail_not_configured).instance(&scope.request_id))
        }
        Err(err) => {
            tracing::error!(error = %err, "confirmation mail failed");
            Err(internal(scope))
        }
    }
}

async fn signup_without_opt_in(
    state: &ModuleState,
    scope: &Scope,
    existing: Option<SubscriberRow>,
    normalized: &str,
    source: Option<String>,
    locale: &str,
    now: &str,
) -> Result<Response, Problem> {
    let Some(db) = state.ctx.ports.db.clone() else {
        return Err(internal(scope));
    };
    match existing {
        Some(row) if row.status == STATUS_PENDING => {
            store::confirm(&*db, &row.id, now).await?;
        }
        None => {
            store::insert_row(
                &*db,
                &SubscriberRow {
                    id: UlidIdGen.ulid(),
                    email: normalized.to_owned(),
                    email_normalized: normalized.to_owned(),
                    status: STATUS_CONFIRMED.to_owned(),
                    source,
                    locale: Some(locale.to_owned()),
                    confirmed_at: Some(now.to_owned()),
                    unsubscribed_at: None,
                    created_at: now.to_owned(),
                    updated_at: now.to_owned(),
                },
            )
            .await?;
        }
        _ => {}
    }
    Ok(accepted())
}

async fn confirm(
    scope: Scope,
    State(state): State<Arc<ModuleState>>,
    headers: HeaderMap,
    Query(query): Query<TokenQuery>,
) -> Response {
    if let Some(denied) = rate_limit(&state, &headers, None).await {
        return denied;
    }
    let Some(signer): Option<Arc<dyn Signer>> = state.ctx.ports.signer.clone() else {
        return internal(&scope).into_response();
    };
    let Some(db) = state.ctx.ports.db.clone() else {
        return internal(&scope).into_response();
    };

    let cfg = ModuleConfig::new("email-signup", &*state.ctx.config);
    // With the UI mounted (ADR 0010) the landings default to its pages;
    // otherwise to pages the venture site provides. Config and builder
    // settings still win.
    let (confirmed_default, expired_default) = if state.ctx.ui_mounted {
        let base = api_base(&cfg, &state.ctx);
        (
            format!("{base}/ui/email-signup/confirm/done"),
            format!("{base}/ui/email-signup/confirm/expired"),
        )
    } else {
        (
            format!("{}/confirmed", state.ctx.venture.public_url),
            format!("{}/confirm-expired", state.ctx.venture.public_url),
        )
    };
    let confirmed_target = configured_or_default(
        &cfg,
        "CONFIRMED_REDIRECT",
        state.settings.confirmed_redirect.as_ref(),
        confirmed_default,
    );
    let expired_target = configured_or_default(
        &cfg,
        "EXPIRED_REDIRECT",
        state.settings.expired_redirect.as_ref(),
        expired_default,
    );

    // A human clicked this link: every failure path stays a redirect,
    // never a JSON problem (issue #10).
    let Some(payload) = signer.verify(&query.token, PURPOSE_CONFIRM) else {
        return see_other(expired_target);
    };
    let subject = payload.subject;
    let now = now_iso();

    let flipped = match store::confirm(&*db, &subject, &now).await {
        Ok(affected) => affected > 0,
        Err(err) => {
            tracing::error!(error = %err, "confirm update failed");
            return internal(&scope).into_response();
        }
    };

    if !flipped {
        // Replay (already confirmed) or the row is gone; both are no-ops,
        // but a missing row means the link is dead — say so.
        return match store::find_by_id(&*db, &subject).await {
            Ok(Some(_)) => see_other(confirmed_target),
            _ => see_other(expired_target),
        };
    }

    if let Ok(Some(row)) = store::find_by_id(&*db, &subject).await {
        state.ctx.events.emit_in(
            &scope,
            EVENT_CONFIRMED,
            json!({
                "subscriber_id": row.id,
                "email": row.email,
                "source": row.source,
            }),
        );
        let welcome = cfg.get_bool("WELCOME_ON_CONFIRM", state.settings.welcome_on_confirm);
        if welcome {
            let unsubscribe_token = signer.sign(&Payload {
                purpose: PURPOSE_UNSUBSCRIBE.to_owned(),
                subject: row.id.clone(),
                exp: None,
                kid: Kid::Cur,
            });
            let base = api_base(&cfg, &state.ctx);
            let mail = OutgoingMail {
                to: row.email_normalized.clone(),
                template_id: TEMPLATE_WELCOME,
                data: json!(mail::WelcomeMailData {
                    venture: state.ctx.venture.name.clone(),
                    email: row.email.clone(),
                    unsubscribe_url: format!(
                        "{base}/v1/email-signup/unsubscribe?token={unsubscribe_token}"
                    ),
                    brand: state.ctx.venture.brand.clone(),
                }),
                locale: row.locale.clone().unwrap_or_else(|| "en".to_owned()),
                idempotency_key: format!(
                    "welcome:{}:{}",
                    row.id,
                    row.confirmed_at.as_deref().unwrap_or(&now)
                ),
            };
            scope
                .defer
                .wait_until(mail::spawn_deferred(Arc::clone(&state.ctx), mail));
        }
    }
    see_other(confirmed_target)
}

async fn unsubscribe_get(
    scope: Scope,
    State(state): State<Arc<ModuleState>>,
    headers: HeaderMap,
    Query(query): Query<TokenQuery>,
) -> Result<Response, Problem> {
    let target = unsubscribe(&state, &scope, &headers, &query.token).await?;
    Ok(see_other(target))
}

async fn unsubscribe_post(
    scope: Scope,
    State(state): State<Arc<ModuleState>>,
    headers: HeaderMap,
    Json(body): Json<TokenQuery>,
) -> Result<Response, Problem> {
    unsubscribe(&state, &scope, &headers, &body.token).await?;
    Ok(Json(json!({ "ok": true })).into_response())
}

async fn unsubscribe(
    state: &ModuleState,
    scope: &Scope,
    headers: &HeaderMap,
    token: &str,
) -> Result<String, Problem> {
    if rate_limit(state, headers, None).await.is_some() {
        return Err(Problem::new(&SLUGS.rate_limited).instance(&scope.request_id));
    }
    let Some(signer): Option<Arc<dyn Signer>> = state.ctx.ports.signer.clone() else {
        return Err(internal(scope));
    };
    let Some(db) = state.ctx.ports.db.clone() else {
        return Err(internal(scope));
    };
    let cfg = ModuleConfig::new("email-signup", &*state.ctx.config);
    let unsubscribed_default = if state.ctx.ui_mounted {
        format!(
            "{}/ui/email-signup/unsubscribe/done",
            api_base(&cfg, &state.ctx)
        )
    } else {
        format!("{}/unsubscribed", state.ctx.venture.public_url)
    };
    let target = configured_or_default(
        &cfg,
        "UNSUBSCRIBED_REDIRECT",
        state.settings.unsubscribed_redirect.as_ref(),
        unsubscribed_default,
    );

    let Some(payload) = signer.verify(token, PURPOSE_UNSUBSCRIBE) else {
        return Err(Problem::new(&SLUGS.invalid_token).instance(&scope.request_id));
    };
    let now = now_iso();
    let row = store::find_by_id(&*db, &payload.subject).await?;
    let affected = store::unsubscribe(&*db, &payload.subject, &now).await?;
    if affected > 0
        && let Some(row) = row
    {
        state.ctx.events.emit_in(
            scope,
            EVENT_UNSUBSCRIBED,
            json!({
                "subscriber_id": row.id,
                "email": row.email,
            }),
        );
    }
    // Idempotent: a deleted row is as unsubscribed as an unsubscribed one.
    Ok(target)
}

#[derive(Deserialize, Default)]
struct ExportQuery {
    status: Option<String>,
}

async fn admin_export(
    scope: Scope,
    State(state): State<Arc<ModuleState>>,
    headers: HeaderMap,
    Query(query): Query<ExportQuery>,
) -> Result<Response, Problem> {
    require_admin(&*state.ctx.config, &headers)
        .map_err(|problem| problem.instance(&scope.request_id))?;
    let status = match query.status.as_deref() {
        None => None,
        Some(status) if ALL_STATUSES.contains(&status) => Some(status),
        Some(_) => {
            return Err(Problem::validation_failed(format!(
                "status must be one of {}",
                ALL_STATUSES.join("|")
            ))
            .instance(&scope.request_id));
        }
    };
    let Some(db) = state.ctx.ports.db.clone() else {
        return Err(internal(&scope));
    };
    let rows = store::list_for_export(&*db, status).await?;
    let mut body =
        String::from("id,email,status,source,locale,created_at,confirmed_at,unsubscribed_at\n");
    for row in &rows {
        let cells = [
            row.id.as_str(),
            row.email.as_str(),
            row.status.as_str(),
            row.source.as_deref().unwrap_or(""),
            row.locale.as_deref().unwrap_or(""),
            row.created_at.as_str(),
            row.confirmed_at.as_deref().unwrap_or(""),
            row.unsubscribed_at.as_deref().unwrap_or(""),
        ];
        body.push_str(&csv_row(&cells));
    }
    Ok((
        StatusCode::OK,
        [(header::CONTENT_TYPE, "text/csv; charset=utf-8")],
        body,
    )
        .into_response())
}

/// Hard-deletes one subscriber by its opaque row id. The path never
/// carries the email (issue #135): request paths outlive the request in
/// access logs, proxies and browser history, so the id — already a column
/// of the admin export table the UI renders — is the delete key.
async fn admin_delete(
    scope: Scope,
    State(state): State<Arc<ModuleState>>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<Response, Problem> {
    require_admin(&*state.ctx.config, &headers)
        .map_err(|problem| problem.instance(&scope.request_id))?;
    let Some(db) = state.ctx.ports.db.clone() else {
        return Err(internal(&scope));
    };
    let deleted = store::delete_by_id(&*db, &id).await?;
    Ok(Json(json!({ "deleted": deleted })).into_response())
}
