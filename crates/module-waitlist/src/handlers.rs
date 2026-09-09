//! HTTP handlers for `/v1/waitlist` (architecture section 6, issue
//! #11). Positions are assigned atomically inside `Database::batch`
//! (see [`crate::store::confirm_entry`]); the POST answers the same
//! `202 {"ok":true}` bytes whatever the row state.

use axum::extract::{Query, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use cratefield_core::{
    Action, Audience, Clock, Column, Database, IdGen, Json, Kid, ModuleConfig, ModuleContext,
    Outcome, Payload, Problem, RateLimit, RateLimitFailure, SLUGS, Scope, SendCooldown,
    SendOutcome, Signer, Surface, SystemClock, UlidIdGen, View, check_rate_limit, client_ip,
    csv_row, hint_field, invalid_email_problem, normalize_email, rate_limit_keys, rate_limited,
    require_admin, validation_error, verify_human_form,
};
use schemars::JsonSchema;
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

/// The durable send-claim table (issue #133). Must match
/// `0003_mail_cooldown.sql` and `Waitlist::tables()`.
pub(crate) const SEND_COOLDOWN_TABLE: &str = "waitlist_send_cooldown";

/// Builds a confirm-token subject: the immutable entry id plus the
/// generation it may confirm (issue #127), mirroring
/// `module-email-signup`.
fn confirm_subject(id: &str, generation: i64) -> String {
    format!("{id}.{generation}")
}

/// Parses a confirm-token subject into `(id, generation)`. Pre-#127
/// tokens carry the bare id and read as generation 1, which is what
/// every existing row holds; a generation bump (should the state machine
/// ever grow one) invalidates them atomically.
fn parse_confirm_subject(subject: &str) -> Option<(&str, i64)> {
    match subject.split_once('.') {
        Some((id, generation)) if !id.is_empty() => generation
            .parse::<i64>()
            .ok()
            .filter(|generation| *generation >= 1)
            .map(|generation| (id, generation)),
        None if !subject.is_empty() => Some((subject, 1)),
        _ => None,
    }
}

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
    pub retention_days_pending: u32,
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

/// Where confirm lands by default: with the UI mounted (ADR 0010) on its
/// pages, otherwise on pages the venture site provides. Config and
/// builder settings still win over either.
fn landing_defaults(cfg: &ModuleConfig<'_>, ctx: &ModuleContext) -> (String, String) {
    if ctx.ui_mounted {
        let base = api_base(cfg, ctx);
        (
            format!("{base}/ui/waitlist/status"),
            format!("{base}/ui/waitlist/confirm/expired"),
        )
    } else {
        (
            format!("{}/waitlist/status", ctx.venture.public_url),
            format!("{}/confirm-expired", ctx.venture.public_url),
        )
    }
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

/// Shared limiter loop (issue #133). `FailOpen` is deliberate: the captcha
/// gate and the DB-enforced send cooldown in [`join`] bound abuse even
/// when the limiter transport is down; failing closed would take the
/// whole invite queue down on a transient limiter outage.
async fn rate_limit(
    state: &ModuleState,
    headers: &HeaderMap,
    email: Option<&str>,
) -> Option<Response> {
    let keys = rate_limit_keys(client_ip(headers).as_deref(), email);
    match check_rate_limit(
        state.ctx.ports.rate_limiter.as_ref(),
        &keys,
        RateLimitFailure::FailOpen,
    )
    .await
    {
        RateLimit::Denied { retry_after } => Some(rate_limited(retry_after)),
        RateLimit::Allowed => None,
    }
}

/// The shared human-form gate (issue #133): any non-`ok` verdict or a
/// missing token is refused; in production a missing port is refused
/// too, so no composition can reach this handler unverified.
async fn check_captcha(
    state: &ModuleState,
    headers: &HeaderMap,
    token: Option<&str>,
    scope: &Scope,
) -> Result<(), Problem> {
    verify_human_form(
        state.ctx.ports.captcha.as_ref(),
        state.ctx.venture.env,
        token,
        client_ip(headers).as_deref(),
        &scope.request_id,
    )
    .await
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

/// The driver message of a write failure, for the dialect-aware error
/// predicates below. A `Query` error never reports a constraint or
/// lock conflict on this path.
fn write_failure_detail(err: &cratefield_core::DbError) -> Option<&str> {
    match err {
        cratefield_core::DbError::Batch(detail) | cratefield_core::DbError::Execute(detail) => {
            Some(detail)
        }
        cratefield_core::DbError::Query(_) => None,
    }
}

/// Whether `err` is a UNIQUE violation on `referral_code` — SQLite/D1
/// wording (`UNIQUE constraint failed: waitlist_entries.referral_code`)
/// **or** Postgres wording (`duplicate key value violates unique
/// constraint "waitlist_entries_referral_code_key"`), which quotes the
/// column in the constraint name (issue #173: matching only the SQLite
/// wording made the retry below dead code on Postgres). SQLSTATE 23505
/// is not in sqlx's `Display`, which is what the adapter captures, so
/// the messages are matched per dialect.
fn unique_code_violation(err: &cratefield_core::DbError) -> bool {
    write_failure_detail(err).is_some_and(|detail| {
        (detail.contains("UNIQUE constraint failed")
            || detail.contains("duplicate key value violates unique constraint"))
            && detail.contains("referral_code")
    })
}

/// Defence-in-depth (issue #173): whether `err` is a transaction the
/// engine asks the client to redo — Postgres deadlock (this backend
/// killed as the victim) or serialization failure, or SQLite/D1 losing
/// the write lock. The confirm batch is all-or-nothing, so replaying it
/// from scratch is safe. This is a backstop only: the root cause, the
/// nondeterministic multi-row bulk lock, is removed in
/// [`store::confirm_entry`] by the single-row position mutex.
fn retriable_transaction_failure(err: &cratefield_core::DbError) -> bool {
    write_failure_detail(err).is_some_and(|detail| {
        detail.contains("deadlock detected")
            || detail.contains("could not serialize access")
            || detail.contains("database is locked")
            || detail.contains("database table is locked")
    })
}

/// Runs the confirm batch with up to three fresh referral codes,
/// retrying a code collision ([`unique_code_violation`]) and an
/// engine-retriable transaction failure ([`retriable_transaction_failure`],
/// issue #173 backstop); the whole batch (position included) rolls back
/// on either, so a retry assigns cleanly.
async fn confirm_with_code(
    db: &dyn cratefield_core::Database,
    row: &store::WaitlistRow,
    generation: i64,
    now: &str,
) -> Result<bool, cratefield_core::DbError> {
    let mut last_err = None;
    for _ in 0..3 {
        let code = referral_code();
        match store::confirm_entry(db, row, generation, now, &code).await {
            Ok(flipped) => return Ok(flipped),
            Err(err) if unique_code_violation(&err) => {
                tracing::warn!("referral code collision; retrying with a fresh code");
                last_err = Some(err);
            }
            Err(err) if retriable_transaction_failure(&err) => {
                tracing::warn!("confirm batch hit a retriable transaction failure; retrying");
                last_err = Some(err);
            }
            Err(err) => return Err(err),
        }
    }
    Err(last_err.expect("at least one attempt"))
}

#[derive(Deserialize, JsonSchema)]
struct JoinBody {
    #[schemars(extend(
        "x-cf-label" = "Email",
        "x-cf-widget" = "email",
        "x-cf-placeholder" = "you@example.com"
    ))]
    email: String,
    // Configured slugs become a `select` in [`surface`]; with
    // `.any_product()` it stays a text input.
    #[schemars(extend("x-cf-label" = "Product"))]
    product: String,
    // Referral code from the share link; the page supplies it.
    #[schemars(extend("x-cf-hidden" = true))]
    #[serde(rename = "ref")]
    referral: Option<String>,
    // Free-form answers; nested, so not form-renderable until a later
    // issue adds question rendering.
    #[schemars(extend("x-cf-hidden" = true))]
    answers: Option<Value>,
    #[schemars(extend("x-cf-hidden" = true))]
    locale: Option<String>,
    #[schemars(extend("x-cf-hidden" = true))]
    #[serde(rename = "captchaToken")]
    captcha_token: Option<String>,
}

/// The module's UI surface (ADR 0010, issue #71): the join form (product
/// as a `select` over the configured list), the confirm link, the status
/// page, and the admin export as a table.
pub(crate) fn surface(settings: &Settings) -> Surface {
    let mut join = cratefield_core::schema_for::<JoinBody>();
    if let Products::List(products) = &settings.products {
        hint_field(&mut join, "product", "enum", json!(products));
        hint_field(&mut join, "product", "x-cf-widget", json!("select"));
    }
    Surface::new()
        .action(
            Action::post("join", "/")
                .input_schema(join)
                .captcha()
                .accepted("Check your inbox to confirm your spot."),
        )
        .action(Action::get("confirm", "/confirm").input::<TokenQuery>())
        .action(
            Action::get("status", "/status")
                .input::<TokenQuery>()
                .outcome(Outcome::Json),
        )
        .action(
            Action::get("export", "/admin/export.csv")
                .audience(Audience::Admin)
                .input::<ExportQuery>()
                .outcome(Outcome::Json),
        )
        .view(View::form("join"))
        .view(View::status("status"))
        .view(View::table(
            "export",
            [
                ("id", "Id"),
                ("email", "Email"),
                ("product", "Product"),
                ("status", "Status"),
                ("position", "Position"),
                ("referral_code", "Referral code"),
                ("referred_by", "Referred by"),
                ("referrals", "Referrals"),
                ("created_at", "Created"),
                ("confirmed_at", "Confirmed"),
            ]
            .into_iter()
            .map(|(key, label)| Column::new(key, label))
            .collect(),
        ))
}

/// Issue #133: the one-send-per-window claim is a row in the database,
/// not a `created_at` read — a limiter fail-open or two concurrent
/// first-time joins can no longer leak a second mail.
async fn acquire_send_claim(db: &dyn Database, subject: &str, now: &str) -> Result<bool, Problem> {
    Ok(SendCooldown::new(SEND_COOLDOWN_TABLE)
        .try_acquire(db, subject, now, &iso_ago(REMAIL_AFTER_SECS))
        .await?)
}

/// Referral credit lookup (issue #11): only a confirmed referrer for the
/// same product counts, and a code is ignored when referrals are off.
async fn referral_target(
    db: &dyn Database,
    referrals: bool,
    product: &str,
    code: Option<&str>,
) -> Result<Option<String>, Problem> {
    match code {
        Some(code) if referrals => Ok(store::find_confirmed_by_referral_code(db, product, code)
            .await?
            .map(|referrer| referrer.id)),
        _ => Ok(None),
    }
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
    let now = now_iso();
    let cooldown = SendCooldown::new(SEND_COOLDOWN_TABLE);
    let cooldown_subject = format!("{normalized}:{}", body.product);
    if !acquire_send_claim(&*db, &cooldown_subject, &now).await? {
        return Ok(accepted());
    }

    let locale = sanitize_locale(body.locale);
    let answers_text = body.answers.as_ref().map(ToString::to_string);
    let referred_by = referral_target(
        &*db,
        state.settings.referrals,
        &body.product,
        body.referral.as_deref(),
    )
    .await?;

    let ttl_days = cfg.get_u32("CONFIRM_TTL_DAYS", state.settings.confirm_ttl_days);
    // Only pending rows reach here (confirmed early-returns above), and
    // `refresh_pending` keeps a pending row's generation: the token is
    // signed for the generation the row holds now (issue #127).
    let id = existing
        .as_ref()
        .map_or_else(|| UlidIdGen.ulid(), |row| row.id.clone());
    let generation = existing.as_ref().map_or(1, |row| row.generation);
    let mail = JoinMail {
        id: id.clone(),
        generation,
        normalized: normalized.clone(),
        product: body.product.clone(),
        locale: locale.clone(),
        ttl_days,
        now: now.clone(),
    };
    if let Err(problem) = send_join_confirmation(&state, &scope, &signer, &cfg, mail).await {
        // The claim was taken but no mail went out (mailer unconfigured
        // or failing): hand the window back so a genuine retry is not
        // locked out for the rest of the hour (issue #133).
        let _ = cooldown.release(&*db, &cooldown_subject).await;
        return Err(problem);
    }

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
                generation,
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
    generation: i64,
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
        subject: confirm_subject(&mail.id, mail.generation),
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

#[derive(Deserialize, JsonSchema)]
struct TokenQuery {
    #[schemars(extend("x-cf-hidden" = true))]
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
    let (status_default, expired_default) = landing_defaults(&cfg, &state.ctx);
    let status_base = configured_or_default(
        &cfg,
        "STATUS_REDIRECT",
        state.settings.status_redirect.as_ref(),
        status_default,
    );
    let expired_target = configured_or_default(&cfg, "EXPIRED_REDIRECT", None, expired_default);

    let Some(payload) = signer.verify(&query.token, PURPOSE_CONFIRM) else {
        return see_other(expired_target);
    };
    let Some((id, generation)) = parse_confirm_subject(&payload.subject) else {
        return see_other(expired_target);
    };
    let Ok(Some(row)) = store::find_by_id(&*db, id).await else {
        return see_other(expired_target);
    };

    if row.status != STATUS_CONFIRMED {
        let now = now_iso();
        let flipped = match confirm_with_code(&*db, &row, generation, &now).await {
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

#[derive(Deserialize, Default, JsonSchema)]
struct ExportQuery {
    #[schemars(extend("x-cf-label" = "Product"))]
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

#[cfg(test)]
mod tests {
    use super::{retriable_transaction_failure, unique_code_violation};
    use cratefield_core::DbError;

    fn batch(message: &str) -> DbError {
        DbError::Batch(message.to_owned())
    }

    #[test]
    fn unique_code_violation_recognizes_sqlite_and_postgres_wordings() {
        // Given the two dialects' real messages for a referral_code clash…
        let sqlite = batch("UNIQUE constraint failed: waitlist_entries.referral_code");
        let postgres = batch(
            "duplicate key value violates unique constraint \
             \"waitlist_entries_referral_code_key\" DETAIL:  \
             Key (referral_code)=(abc12345) already exists.",
        );
        // When each is classified, Then both retry — the Postgres leg of
        // this is issue #173's second defect (it used to be dead code).
        assert!(unique_code_violation(&sqlite), "sqlite wording");
        assert!(unique_code_violation(&postgres), "postgres wording");
    }

    #[test]
    fn unique_violations_on_other_columns_are_not_code_collisions() {
        let other = batch(
            "duplicate key value violates unique constraint \
             \"waitlist_entries_email_normalized_product_key\" \
             DETAIL:  Key (email_normalized, product)=(nick@example.com, kontinuum) already exists.",
        );
        assert!(!unique_code_violation(&other), "only referral_code retries");
        assert!(
            !retriable_transaction_failure(&other),
            "and it is not retriable"
        );
    }

    #[test]
    fn retriable_transaction_failure_recognizes_deadlock_and_busy() {
        // Real messages: the PG deadlock that killed confirms on #173,
        // its serialization sibling, and SQLite's busy errors.
        for message in [
            "error returned from database: deadlock detected",
            "could not serialize access due to concurrent update",
            "database is locked",
            "database table is locked",
        ] {
            let err = batch(message);
            assert!(
                retriable_transaction_failure(&err),
                "{message} is retriable"
            );
            assert!(!unique_code_violation(&err), "{message} is not a collision");
        }
    }

    #[test]
    fn non_transaction_errors_are_never_retried() {
        let syntax = batch("error returned from database: syntax error at or near \"UPDAT\"");
        let query = DbError::Query("no such table: waitlist_entries".to_owned());
        assert!(!retriable_transaction_failure(&syntax));
        assert!(!unique_code_violation(&syntax));
        assert!(
            !retriable_transaction_failure(&query),
            "query errors never retry"
        );
        assert!(!unique_code_violation(&query));
    }
}
