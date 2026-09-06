//! HTTP handlers for `/v1/waitlist` (architecture section 6, issue
//! #11). Positions are assigned atomically inside `Database::batch`
//! (see [`crate::store::confirm_entry`]); the POST answers the same
//! `202 {"ok":true}` bytes whatever the row state.

use axum::extract::{Query, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use factory0_core::{
    Captcha, Clock, Decision, IdGen, Json, Kid, ModuleConfig, ModuleContext, Payload, Problem,
    RateLimiter, SLUGS, Scope, SendOutcome, Signer, SystemClock, UlidIdGen, client_ip, csv_row,
    invalid_email_problem, normalize_email, rate_limit_keys, rate_limited, require_admin,
    validation_error,
};
use serde::Deserialize;
use serde_json::{Value, json};
use std::sync::Arc;
use time::format_description::well_known::Rfc3339;

use crate::mail::{self, ConfirmMailData, OutgoingMail, TEMPLATE_CONFIRM, TEMPLATE_CONFIRMED};
use crate::store::{self, STATUS_CONFIRMED, WaitlistRow};

pub(crate) const PURPOSE_CONFIRM: &str = "waitlist.confirm";
pub(crate) const PURPOSE_STATUS: &str = "waitlist.status";

pub(crate) const EVENT_JOINED: &str = "waitlist.joined";
pub(crate) const EVENT_CONFIRMED: &str = "waitlist.confirmed";

/// One confirmation mail per address+product per hour, mirroring
/// `module-email-signup`'s throttle.
pub(crate) const REMAIL_AFTER_SECS: i64 = 3600;

/// How the allowed product set is configured.
#[derive(Debug, Clone)]
pub(crate) enum Products {
    /// `.any_product()`: every product slug is accepted.
    Any,
    /// `.products([..])`: exactly these slugs (config `WAITLIST_PRODUCTS`
    /// overrides at runtime; `*` means any).
    List(Vec<String>),
}

/// The builder's compile-time settings, cloned into the router state.
#[derive(Clone)]
pub(crate) struct Settings {
    pub products: Products,
    pub confirm_ttl_days: u32,
    pub status_redirect: Option<String>,
    pub referrals: bool,
    pub answers_schema: crate::AnswersSchema,
}

pub(crate) struct ModuleState {
    pub ctx: Arc<ModuleContext>,
    pub settings: Settings,
}

pub(crate) fn router(ctx: Arc<ModuleContext>, settings: Settings) -> axum::Router {
    let state = Arc::new(ModuleState { ctx, settings });
    axum::Router::new()
        .route("/", post(join))
        .route("/confirm", get(confirm))
        .route("/status", get(status))
        .route("/admin/export.csv", get(admin_export))
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

fn api_base(cfg: &ModuleConfig<'_>, ctx: &ModuleContext) -> String {
    cfg.get_opt("API_BASE")
        .unwrap_or_else(|| format!("https://api.{}", ctx.venture.domain))
}

fn configured_or_default(
    cfg: &ModuleConfig<'_>,
    key: &str,
    builder: Option<&String>,
    default: String,
) -> String {
    cfg.get_opt(key)
        .or_else(|| builder.cloned())
        .unwrap_or(default)
}

fn effective_products(cfg: &ModuleConfig<'_>, settings: &Settings) -> Products {
    match cfg.get_opt("PRODUCTS").as_deref() {
        Some("*") => Products::Any,
        Some(list) => Products::List(
            list.split(',')
                .map(str::trim)
                .filter(|slug| !slug.is_empty())
                .map(str::to_owned)
                .collect(),
        ),
        None => settings.products.clone(),
    }
}

fn product_allowed(products: &Products, product: &str) -> bool {
    match products {
        Products::Any => true,
        Products::List(list) => list.iter().any(|allowed| allowed == product),
    }
}

/// See `module-email-signup::handlers::rate_limit`: fails open with a
/// warning when the limiter is unreachable.
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

/// 8-char Crockford base32 from `IdGen`. A ULID's **last** 8 chars are
/// its random part; the first 8 are timestamp-dominated and consecutive
/// confirms inside one ~256 ms window would collide on the UNIQUE
/// constraint. Collisions on the random tail are backstopped by a
/// bounded retry in [`confirm_with_code`].
pub(crate) fn referral_code() -> String {
    let ulid = UlidIdGen.ulid();
    ulid.chars()
        .rev()
        .take(8)
        .collect::<String>()
        .to_lowercase()
}

fn unique_code_violation(err: &factory0_core::DbError) -> bool {
    let detail = match err {
        factory0_core::DbError::Batch(detail) | factory0_core::DbError::Execute(detail) => detail,
        factory0_core::DbError::Query(_) => return false,
    };
    detail.contains("UNIQUE constraint failed") && detail.contains("referral_code")
}

/// Runs the confirm batch with up to three fresh referral codes; the
/// whole batch (position included) rolls back on a code collision, so a
/// retry assigns cleanly.
async fn confirm_with_code(
    db: &dyn factory0_core::Database,
    row: &store::WaitlistRow,
    now: &str,
) -> Result<bool, factory0_core::DbError> {
    let mut last_err = None;
    for _ in 0..3 {
        let code = referral_code();
        match store::confirm_entry(db, row, now, &code).await {
            Ok(flipped) => return Ok(flipped),
            Err(err) if unique_code_violation(&err) => {
                tracing::warn!("referral code collision; retrying with a fresh code");
                last_err = Some(err);
            }
            Err(err) => return Err(err),
        }
    }
    Err(last_err.expect("at least one attempt"))
}

#[derive(Deserialize)]
struct JoinBody {
    email: String,
    product: String,
    #[serde(rename = "ref")]
    referral: Option<String>,
    answers: Option<Value>,
    locale: Option<String>,
    #[serde(rename = "captchaToken")]
    captcha_token: Option<String>,
}

async fn join(
    scope: Scope,
    State(state): State<Arc<ModuleState>>,
    headers: HeaderMap,
    Json(body): Json<JoinBody>,
) -> Result<Response, Problem> {
    if let Some(denied) = rate_limit(&state, &headers, Some(&body.email)).await {
        return Ok(denied);
    }
    check_captcha(&state, &headers, body.captcha_token.as_deref(), &scope).await?;

    let cfg = ModuleConfig::new("waitlist", &*state.ctx.config);
    let normalized = validate_join(&state, &scope, &cfg, &body)?;

    let Some(db) = state.ctx.ports.db.clone() else {
        return Err(internal(&scope));
    };
    let Some(signer): Option<Arc<dyn Signer>> = state.ctx.ports.signer.clone() else {
        return Err(internal(&scope));
    };

    let existing = store::find_by_email_and_product(&*db, &normalized, &body.product).await?;
    if existing
        .as_ref()
        .is_some_and(|row| row.status == STATUS_CONFIRMED)
    {
        return Ok(accepted());
    }
    if existing
        .as_ref()
        .is_some_and(|row| row.created_at > iso_ago(REMAIL_AFTER_SECS))
    {
        return Ok(accepted());
    }

    let locale = sanitize_locale(body.locale);
    let answers_text = body.answers.as_ref().map(ToString::to_string);
    let referred_by = match body.referral.as_deref() {
        Some(code) if state.settings.referrals => {
            store::find_confirmed_by_referral_code(&*db, &body.product, code)
                .await?
                .map(|referrer| referrer.id)
        }
        _ => None,
    };

    let ttl_days = cfg.get_u32("CONFIRM_TTL_DAYS", state.settings.confirm_ttl_days);
    let id = existing
        .as_ref()
        .map_or_else(|| UlidIdGen.ulid(), |row| row.id.clone());
    let now = now_iso();
    send_join_confirmation(
        &state,
        &scope,
        &signer,
        &cfg,
        JoinMail {
            id: id.clone(),
            normalized: normalized.clone(),
            product: body.product.clone(),
            locale: locale.clone(),
            ttl_days,
            now: now.clone(),
        },
    )
    .await?;

    if let Some(row) = &existing {
        store::refresh_pending(
            &*db,
            &row.id,
            answers_text.as_deref(),
            referred_by.as_deref(),
            &now,
        )
        .await?;
    } else {
        store::insert_row(
            &*db,
            &WaitlistRow {
                id: id.clone(),
                email: body.email.trim().to_owned(),
                email_normalized: normalized.clone(),
                product: body.product.clone(),
                status: store::STATUS_PENDING.to_owned(),
                position: None,
                referral_code: None,
                referred_by,
                referrals: 0,
                answers: answers_text,
                created_at: now.clone(),
                confirmed_at: None,
            },
        )
        .await?;
        state.ctx.events.emit_in(
            &scope,
            EVENT_JOINED,
            json!({
                "entry_id": id,
                "email": normalized,
                "product": body.product,
            }),
        );
    }
    Ok(accepted())
}

/// Normalises the address and enforces the product allowlist and the
/// venture's answers schema; `Err` carries the matching problem.
fn validate_join(
    state: &ModuleState,
    scope: &Scope,
    cfg: &ModuleConfig<'_>,
    body: &JoinBody,
) -> Result<String, Problem> {
    let normalized = normalize_email(&body.email);
    if let Some(reason) = validation_error(&normalized) {
        return Err(invalid_email_problem(reason).instance(&scope.request_id));
    }
    let products = effective_products(cfg, &state.settings);
    if !product_allowed(&products, &body.product) {
        return Err(Problem::new(&SLUGS.unknown_product).instance(&scope.request_id));
    }
    if let Some(answers) = &body.answers
        && let Err(detail) = (state.settings.answers_schema)(answers)
    {
        return Err(
            Problem::validation_failed(format!("answers: {detail}")).instance(&scope.request_id)
        );
    }
    Ok(normalized)
}

/// Everything [`send_join_confirmation`] needs for one address.
struct JoinMail {
    id: String,
    normalized: String,
    product: String,
    locale: String,
    ttl_days: u32,
    now: String,
}

/// Signs the confirm token, renders and sends the join mail. Mail before
/// write (as in module-email-signup): a failed send leaves no row behind
/// the hourly throttle.
async fn send_join_confirmation(
    state: &ModuleState,
    scope: &Scope,
    signer: &Arc<dyn Signer>,
    cfg: &ModuleConfig<'_>,
    mail: JoinMail,
) -> Result<(), Problem> {
    let confirm_token = signer.sign(&Payload {
        purpose: PURPOSE_CONFIRM.to_owned(),
        subject: mail.id.clone(),
        exp: Some(unix_now().saturating_add(u64::from(mail.ttl_days) * 86_400)),
        kid: Kid::Cur,
    });
    let base = api_base(cfg, &state.ctx);
    let data = json!(ConfirmMailData {
        venture: state.ctx.venture.name.clone(),
        product: mail.product,
        email: mail.normalized.clone(),
        confirm_url: format!("{base}/v1/waitlist/confirm?token={confirm_token}"),
        brand: state.ctx.venture.brand.clone(),
    });
    match mail::send(
        &state.ctx,
        &OutgoingMail {
            to: mail.normalized.clone(),
            template_id: TEMPLATE_CONFIRM,
            data,
            locale: mail.locale,
            idempotency_key: format!("waitlist:{}:{}", mail.id, mail.now),
        },
    )
    .await
    {
        Ok(SendOutcome::Sent { .. }) => Ok(()),
        Ok(SendOutcome::NotConfigured) => {
            Err(Problem::new(&SLUGS.mail_not_configured).instance(&scope.request_id))
        }
        Err(err) => {
            tracing::error!(error = %err, "waitlist confirmation mail failed");
            Err(internal(scope))
        }
    }
}

#[derive(Deserialize)]
struct TokenQuery {
    token: String,
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

    let cfg = ModuleConfig::new("waitlist", &*state.ctx.config);
    let status_base = configured_or_default(
        &cfg,
        "STATUS_REDIRECT",
        state.settings.status_redirect.as_ref(),
        format!("{}/waitlist/status", state.ctx.venture.public_url),
    );
    let expired_target = configured_or_default(
        &cfg,
        "EXPIRED_REDIRECT",
        None,
        format!("{}/confirm-expired", state.ctx.venture.public_url),
    );

    let Some(payload) = signer.verify(&query.token, PURPOSE_CONFIRM) else {
        return see_other(expired_target);
    };
    let Ok(Some(row)) = store::find_by_id(&*db, &payload.subject).await else {
        return see_other(expired_target);
    };

    if row.status != STATUS_CONFIRMED {
        let now = now_iso();
        let flipped = match confirm_with_code(&*db, &row, &now).await {
            Ok(flipped) => flipped,
            Err(err) => {
                tracing::error!(error = %err, "waitlist confirm batch failed");
                return internal(&scope).into_response();
            }
        };
        if flipped {
            let fresh = store::find_by_id(&*db, &row.id)
                .await
                .ok()
                .flatten()
                .unwrap_or(row);
            let status_token = signer.sign(&Payload {
                purpose: PURPOSE_STATUS.to_owned(),
                subject: fresh.id.clone(),
                exp: None,
                kid: Kid::Cur,
            });
            state.ctx.events.emit_in(
                &scope,
                EVENT_CONFIRMED,
                json!({
                    "entry_id": fresh.id,
                    "email": fresh.email,
                    "product": fresh.product,
                    "position": fresh.position,
                    "referral_code": fresh.referral_code,
                }),
            );
            let base = api_base(&cfg, &state.ctx);
            let mail = OutgoingMail {
                to: fresh.email_normalized.clone(),
                template_id: TEMPLATE_CONFIRMED,
                data: json!(mail::ConfirmedMailData {
                    venture: state.ctx.venture.name.clone(),
                    product: fresh.product.clone(),
                    email: fresh.email.clone(),
                    position: fresh.position.unwrap_or(0),
                    status_url: format!("{base}/v1/waitlist/status?token={status_token}"),
                    brand: state.ctx.venture.brand.clone(),
                }),
                locale: "en".to_owned(),
                idempotency_key: format!(
                    "waitlist-confirmed:{}:{}",
                    fresh.id,
                    fresh.confirmed_at.as_deref().unwrap_or(&now)
                ),
            };
            scope
                .defer
                .wait_until(mail::spawn_deferred(Arc::clone(&state.ctx), mail));
            return see_other(format!("{status_base}?token={status_token}"));
        }
    }

    // Replay (or a lost race): the entry already holds a position.
    let status_token = signer.sign(&Payload {
        purpose: PURPOSE_STATUS.to_owned(),
        subject: row.id.clone(),
        exp: None,
        kid: Kid::Cur,
    });
    see_other(format!("{status_base}?token={status_token}"))
}

async fn status(
    scope: Scope,
    State(state): State<Arc<ModuleState>>,
    headers: HeaderMap,
    Query(query): Query<TokenQuery>,
) -> Result<Response, Problem> {
    if let Some(denied) = rate_limit(&state, &headers, None).await {
        let _ = denied;
        return Err(Problem::new(&SLUGS.rate_limited).instance(&scope.request_id));
    }
    let Some(signer): Option<Arc<dyn Signer>> = state.ctx.ports.signer.clone() else {
        return Err(internal(&scope));
    };
    let Some(db) = state.ctx.ports.db.clone() else {
        return Err(internal(&scope));
    };
    let Some(payload) = signer.verify(&query.token, PURPOSE_STATUS) else {
        return Err(Problem::new(&SLUGS.invalid_token).instance(&scope.request_id));
    };
    let Some(row) = store::find_by_id(&*db, &payload.subject).await? else {
        return Err(Problem::not_found().instance(&scope.request_id));
    };
    let code = row.referral_code.clone().unwrap_or_default();
    Ok(Json(json!({
        "product": row.product,
        "position": row.position,
        "referrals": row.referrals,
        "referralCode": code,
        "shareUrl": format!(
            "{}/waitlist/{}?ref={}",
            state.ctx.venture.public_url, row.product, code
        ),
    }))
    .into_response())
}

#[derive(Deserialize, Default)]
struct ExportQuery {
    product: Option<String>,
}

async fn admin_export(
    scope: Scope,
    State(state): State<Arc<ModuleState>>,
    headers: HeaderMap,
    Query(query): Query<ExportQuery>,
) -> Result<Response, Problem> {
    require_admin(&*state.ctx.config, &headers)
        .map_err(|problem| problem.instance(&scope.request_id))?;
    let Some(db) = state.ctx.ports.db.clone() else {
        return Err(internal(&scope));
    };
    let rows = store::list_for_export(&*db, query.product.as_deref()).await?;
    let mut body = String::from(
        "id,email,product,status,position,referral_code,referred_by,referrals,created_at,confirmed_at\n",
    );
    for row in &rows {
        let cells = [
            row.id.as_str(),
            row.email.as_str(),
            row.product.as_str(),
            row.status.as_str(),
            &row.position.map_or_else(String::new, |p| p.to_string()),
            row.referral_code.as_deref().unwrap_or(""),
            row.referred_by.as_deref().unwrap_or(""),
            &row.referrals.to_string(),
            row.created_at.as_str(),
            row.confirmed_at.as_deref().unwrap_or(""),
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
