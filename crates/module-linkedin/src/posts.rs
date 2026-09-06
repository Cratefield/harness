//! Posts: create, schedule, publish, confirm, reconcile, edit, delete
//! (issues #12, #13).
//!
//! # Why publishing is not inline
//!
//! LinkedIn has no idempotency key on create. If a publish dies between
//! LinkedIn's `201` and our write of the returned URN, a naive retry posts the
//! same thing publicly a second time, and there is no way to take it back
//! quietly. So:
//!
//! - a create writes a row and answers `202`; `Defer` is a fast path to the
//!   same routine, never the source of truth, because `wait_until` is not
//!   durable either;
//! - a publish claims the row with a conditional update whose affected-row
//!   count decides the winner, so two cron passes cannot both post;
//! - a row reclaimed from a stale lease, or retried after an error, is
//!   reconciled against LinkedIn's author finder **before** it is created
//!   again: a match means adopt the URN, not post again;
//! - a `201` is not a published post. `lifecycleState` may be
//!   `PUBLISH_REQUESTED` and then `PUBLISH_FAILED`, so the row waits in
//!   `publish_requested` until LinkedIn says which.

use axum::extract::{Path, Query, State};
use axum::http::HeaderMap;
use axum::response::Response;
use factory0_core::{Clock, Database, ModuleContext, Problem, Scope};
use serde::Deserialize;
use serde_json::{Value, json};
use std::sync::Arc;

use crate::client::{ApiError, Client};
use crate::handlers::{
    self, EVENT_POST_FAILED, EVENT_POST_PUBLISHED, ListQuery, ModuleState, Settings,
};
use crate::images::{self, AssetTrouble};
use crate::store::{self, PostRow};
use crate::tokens::{self, TokenTrouble};

/// LinkedIn's call-to-action labels. `BUY_NOW` and `SHOP_NOW` only exist from
/// version 202504, so they are checked against the pinned version rather than
/// forwarded and refused upstream.
const CTA_LABELS: [&str; 11] = [
    "APPLY",
    "DOWNLOAD",
    "VIEW_QUOTE",
    "LEARN_MORE",
    "SIGN_UP",
    "SUBSCRIBE",
    "REGISTER",
    "JOIN",
    "ATTEND",
    "REQUEST_DEMO",
    "SEE_MORE",
];
const CTA_LABELS_202504: [&str; 2] = ["BUY_NOW", "SHOP_NOW"];

/// The four organic fields LinkedIn lets a published post change. (`adContext`
/// is a fifth, for direct sponsored content, which this module does not do.)
const EDITABLE: [&str; 3] = [
    "commentary",
    "content_call_to_action_label",
    "content_landing_page",
];

/// How many posts one publisher pass will handle. Keeps a backlog from
/// spending the whole daily request budget in one cron tick.
const PUBLISH_BATCH: u64 = 5;
const CONFIRM_BATCH: u64 = 10;

/// Retry backoff, in minutes, by attempt. Flat rather than exponential: the
/// publisher runs every five minutes and LinkedIn's rate limits are daily, so
/// there is nothing to be gained by backing off for hours.
fn backoff_secs(attempts: i64) -> i64 {
    match attempts {
        0 => 300,
        1 => 600,
        2 => 1800,
        _ => 3600,
    }
}

#[derive(Debug, Deserialize)]
pub(crate) struct CreateBody {
    /// Plain text by default: the module escapes all fifteen characters
    /// `little` reserves. Set `commentary_format` to `little` to pass
    /// pre-formatted text (mentions, hashtag templates) straight through.
    commentary: String,
    commentary_format: Option<String>,
    visibility: Option<String>,
    asset_id: Option<String>,
    article: Option<ArticleBody>,
    /// ISO-8601. Absent means "as soon as the publisher runs".
    scheduled_at: Option<String>,
    idempotency_key: String,
}

#[derive(Debug, Deserialize)]
struct ArticleBody {
    source: String,
    title: Option<String>,
    description: Option<String>,
}

/// What a create needs after validation. Doing this in one place keeps the
/// handler readable and makes the rules testable without a router.
struct Prepared {
    commentary: String,
    visibility: String,
}

/// Validates a create and settles the commentary. Plain text is escaped here,
/// once, so the publisher never has to decide: `little` reserves fifteen
/// characters and the docs are explicit that all of them must be escaped even
/// when they are not being used as markup.
fn prepare(body: &CreateBody, settings: &Settings) -> Result<Prepared, Problem> {
    if body.commentary.trim().is_empty() {
        return Err(Problem::validation_failed("commentary must not be empty"));
    }
    if body.idempotency_key.trim().is_empty() {
        return Err(Problem::validation_failed(
            "idempotency_key must not be empty",
        ));
    }

    let visibility = body
        .visibility
        .clone()
        .unwrap_or_else(|| settings.default_visibility.clone());
    if !crate::VISIBILITIES.contains(&visibility.as_str()) {
        return Err(Problem::validation_failed(format!(
            "visibility must be one of {}, got {visibility:?}",
            crate::VISIBILITIES.join(", ")
        )));
    }

    if let Some(scheduled_at) = body.scheduled_at.as_deref()
        && store::parse_iso(scheduled_at).is_none()
    {
        return Err(Problem::validation_failed(
            "scheduled_at must be an ISO-8601 timestamp such as 2026-09-08T09:00:00Z",
        ));
    }

    let commentary = match body.commentary_format.as_deref() {
        None | Some("plain") => crate::little::escape(&body.commentary),
        Some("little") => body.commentary.clone(),
        Some(other) => {
            return Err(Problem::validation_failed(format!(
                "commentary_format must be plain or little, got {other:?}"
            )));
        }
    };

    Ok(Prepared {
        commentary,
        visibility,
    })
}

pub(crate) async fn create(
    State(state): State<Arc<ModuleState>>,
    scope: Scope,
    headers: HeaderMap,
    Path(org): Path<String>,
    factory0_core::Json(body): factory0_core::Json<CreateBody>,
) -> Result<Response, Problem> {
    handlers::admin(&state, &headers)?;
    let ctx = state.ctx.as_ref();
    let settings = state.settings();
    let db = handlers::db(ctx)?;
    let clock = handlers::clock(ctx)?;
    let id_gen = handlers::id_gen(ctx)?;

    let page = crate::pages::require_postable(db, &org).await?;

    // Refuse now rather than accept a post the publisher cannot send: a dead
    // connection needs a human, and queueing work behind one hides that.
    tokens::require_connected(ctx)
        .await
        .map_err(|trouble| trouble.problem(&scope))?;

    let prepared = prepare(&body, &settings)?;

    if let Some(asset_id) = body.asset_id.as_deref() {
        let asset = store::find_asset(db, asset_id)
            .await
            .map_err(|error| {
                tracing::error!(error = %error, "could not read the asset");
                handlers::internal(&scope)
            })?
            .ok_or_else(|| Problem::validation_failed("asset_id does not exist"))?;
        if asset.org_id != page.org_id {
            return Err(Problem::validation_failed(
                "that asset belongs to a different page",
            ));
        }
        if asset.status == store::ASSET_FAILED {
            return Err(Problem::validation_failed(
                "that asset failed processing at LinkedIn; upload it again",
            ));
        }
    }

    // A repeat of an idempotency key returns the first result and makes no
    // call: the caller's retry must never become a second public post.
    if let Some(existing) = store::find_post_by_idempotency(db, &page.org_id, &body.idempotency_key)
        .await
        .map_err(|error| {
            tracing::error!(error = %error, "could not check idempotency");
            handlers::internal(&scope)
        })?
    {
        return Ok(handlers::accepted(json!({
            "post": handlers::post_json(&existing),
            "duplicate": true,
        })));
    }

    let now = store::now_iso(clock);
    let row = PostRow {
        id: id_gen.ulid(),
        account_id: String::new(),
        org_id: page.org_id.clone(),
        idempotency_key: body.idempotency_key.clone(),
        commentary: prepared.commentary,
        visibility: prepared.visibility,
        asset_id: body.asset_id.clone(),
        article_source: body.article.as_ref().map(|article| article.source.clone()),
        article_title: body
            .article
            .as_ref()
            .and_then(|article| article.title.clone()),
        article_description: body
            .article
            .as_ref()
            .and_then(|article| article.description.clone()),
        state: store::POST_SCHEDULED.to_owned(),
        post_urn: None,
        scheduled_at: body.scheduled_at.clone(),
        not_before: None,
        publishing_since: None,
        attempts: 0,
        error_code: None,
        error_detail: None,
        edited_at: None,
        previous_commentary: None,
        created_at: now.clone(),
        published_at: None,
        deleted_at: None,
    };
    store::insert_post(db, &row, &now).await.map_err(|error| {
        tracing::error!(error = %error, "could not record the post");
        handlers::internal(&scope)
    })?;

    // Fast path only: if the isolate dies here the row is still `scheduled`
    // and the next cron pass picks it up.
    if row.scheduled_at.is_none() {
        let ctx_for_defer = state.ctx.clone();
        let settings_for_defer = settings.clone();
        let id = row.id.clone();
        let scope_for_defer = scope.clone();
        scope.defer.wait_until(Box::pin(async move {
            publish_one(
                ctx_for_defer.as_ref(),
                &settings_for_defer,
                &scope_for_defer,
                &id,
            )
            .await;
        }));
    }

    Ok(handlers::accepted(json!({
        "post": handlers::post_json(&row),
        "duplicate": false,
    })))
}

pub(crate) async fn list(
    State(state): State<Arc<ModuleState>>,
    scope: Scope,
    headers: HeaderMap,
    Query(query): Query<ListQuery>,
) -> Result<Response, Problem> {
    handlers::admin(&state, &headers)?;
    let db = handlers::db(state.ctx.as_ref())?;
    let org_id = match query.page.as_deref() {
        None => None,
        Some(page) => Some(
            crate::urn::page_id(page)
                .ok_or_else(|| Problem::validation_failed("page must name an organization"))?,
        ),
    };
    let limit = query.limit.unwrap_or(50).clamp(1, 200);
    let posts = store::list_posts(db, org_id.as_deref(), query.state.as_deref(), limit)
        .await
        .map_err(|error| {
            tracing::error!(error = %error, "could not list posts");
            handlers::internal(&scope)
        })?;
    Ok(handlers::ok(json!({
        "posts": posts.iter().map(handlers::post_json).collect::<Vec<_>>(),
    })))
}

/// The four organic fields LinkedIn lets a published post change, validated
/// and translated into its `$set` shape.
///
/// Anything else is refused here with a message that says what LinkedIn
/// allows, rather than forwarded to come back as a 422.
fn build_patch(
    body: &Value,
    settings: &Settings,
) -> Result<(serde_json::Map<String, Value>, Option<String>), Problem> {
    let object = body
        .as_object()
        .ok_or_else(|| Problem::validation_failed("the body must be a JSON object"))?;
    if object.is_empty() {
        return Err(Problem::validation_failed(
            "nothing to change; the editable fields are commentary, \
             content_call_to_action_label and content_landing_page",
        ));
    }

    for key in object.keys() {
        if EDITABLE.contains(&key.as_str()) {
            continue;
        }
        return Err(Problem::validation_failed(match key.as_str() {
            "asset_id" | "media" | "image" | "article" => {
                "LinkedIn does not allow the media of a published post to change. \
                 Delete the post and create a new one."
                    .to_owned()
            }
            "visibility" => {
                "LinkedIn does not allow the visibility of a published post to change.".to_owned()
            }
            other => format!(
                "{other:?} cannot be changed; LinkedIn allows commentary, \
                 content_call_to_action_label and content_landing_page"
            ),
        }));
    }

    let mut set = serde_json::Map::new();
    let mut new_commentary = None;

    if let Some(commentary) = object.get("commentary") {
        let text = commentary
            .as_str()
            .ok_or_else(|| Problem::validation_failed("commentary must be a string"))?;
        if text.trim().is_empty() {
            return Err(Problem::validation_failed("commentary must not be empty"));
        }
        let escaped = crate::little::escape(text);
        set.insert("commentary".to_owned(), Value::String(escaped.clone()));
        new_commentary = Some(escaped);
    }

    if let Some(label) = object.get("content_call_to_action_label") {
        let label = label.as_str().ok_or_else(|| {
            Problem::validation_failed("content_call_to_action_label must be a string")
        })?;
        if !cta_allowed(label, &settings.api_version) {
            return Err(Problem::validation_failed(format!(
                "content_call_to_action_label must be one of {} (BUY_NOW and SHOP_NOW need \
                 version 202504 or later); got {label:?}",
                CTA_LABELS.join(", ")
            )));
        }
        set.insert(
            "contentCallToActionLabel".to_owned(),
            Value::String(label.to_owned()),
        );
    }

    if let Some(landing) = object.get("content_landing_page") {
        let url = landing
            .as_str()
            .ok_or_else(|| Problem::validation_failed("content_landing_page must be a string"))?;
        if !url.starts_with("https://") {
            return Err(Problem::validation_failed(
                "content_landing_page must be an https URL",
            ));
        }
        set.insert(
            "contentLandingPage".to_owned(),
            Value::String(url.to_owned()),
        );
    }

    Ok((set, new_commentary))
}

pub(crate) async fn edit(
    State(state): State<Arc<ModuleState>>,
    scope: Scope,
    headers: HeaderMap,
    Path(id): Path<String>,
    factory0_core::Json(body): factory0_core::Json<Value>,
) -> Result<Response, Problem> {
    handlers::admin(&state, &headers)?;
    let ctx = state.ctx.as_ref();
    let settings = state.settings();
    let db = handlers::db(ctx)?;
    let clock = handlers::clock(ctx)?;
    let http = handlers::http(ctx)?;

    let (set, new_commentary) = build_patch(&body, &settings)?;

    let row = store::find_post(db, &id)
        .await
        .map_err(|error| {
            tracing::error!(error = %error, "could not read the post");
            handlers::internal(&scope)
        })?
        .ok_or_else(Problem::not_found)?;
    if row.state == store::POST_DELETED {
        return Err(Problem::not_found());
    }

    let now = store::now_iso(clock);

    // A post that never reached LinkedIn is edited locally, with no call.
    let Some(post_urn) = row.post_urn.as_deref() else {
        if let Some(commentary) = new_commentary.as_deref() {
            store::update_commentary(db, &row.id, commentary, &row.commentary, &now)
                .await
                .map_err(|error| {
                    tracing::error!(error = %error, "could not update the post");
                    handlers::internal(&scope)
                })?;
        }
        let updated = store::find_post(db, &id)
            .await
            .ok()
            .flatten()
            .unwrap_or(row);
        return Ok(handlers::ok(json!({
            "post": handlers::post_json(&updated),
            "sent_to_linkedin": false,
        })));
    };

    let session = tokens::session(ctx, &settings, &scope)
        .await
        .map_err(|trouble| trouble.problem(&scope))?;
    let client = Client::new(http, &settings.api_version, &session.access_token);
    let result = client
        .partial_update_post(post_urn, Value::Object(set))
        .await;
    handlers::flush_budget(ctx, client.spent()).await;
    result.map_err(|error| {
        tracing::warn!(error = %error, "linkedin refused a post update");
        handlers::upstream_problem(&error)
    })?;

    if let Some(commentary) = new_commentary.as_deref() {
        store::update_commentary(db, &row.id, commentary, &row.commentary, &now)
            .await
            .map_err(|error| {
                tracing::error!(error = %error, "could not record the edit");
                handlers::internal(&scope)
            })?;
    }
    let updated = store::find_post(db, &id)
        .await
        .ok()
        .flatten()
        .unwrap_or(row);
    Ok(handlers::ok(json!({
        "post": handlers::post_json(&updated),
        "sent_to_linkedin": true,
    })))
}

fn cta_allowed(label: &str, api_version: &str) -> bool {
    if CTA_LABELS.contains(&label) {
        return true;
    }
    CTA_LABELS_202504.contains(&label) && api_version >= "202504"
}

pub(crate) async fn remove(
    State(state): State<Arc<ModuleState>>,
    scope: Scope,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<Response, Problem> {
    handlers::admin(&state, &headers)?;
    let ctx = state.ctx.as_ref();
    let settings = state.settings();
    let db = handlers::db(ctx)?;
    let clock = handlers::clock(ctx)?;
    let http = handlers::http(ctx)?;

    let row = store::find_post(db, &id)
        .await
        .map_err(|error| {
            tracing::error!(error = %error, "could not read the post");
            handlers::internal(&scope)
        })?
        .ok_or_else(Problem::not_found)?;

    // Already deleted: LinkedIn's delete is idempotent, but spending a
    // request to prove it is not.
    if row.state == store::POST_DELETED {
        return Ok(handlers::ok(json!({
            "ok": true,
            "id": row.id,
            "was_on_linkedin": row.post_urn.is_some(),
            "already_deleted": true,
        })));
    }

    let now = store::now_iso(clock);
    if let Some(post_urn) = row.post_urn.as_deref() {
        let session = tokens::session(ctx, &settings, &scope)
            .await
            .map_err(|trouble| trouble.problem(&scope))?;
        let client = Client::new(http, &settings.api_version, &session.access_token);
        // Deletion is idempotent on LinkedIn's side: an already-deleted post
        // answers 204 too, so a lost response costs nothing.
        let result = client.delete_post(post_urn).await;
        handlers::flush_budget(ctx, client.spent()).await;
        result.map_err(|error| {
            tracing::warn!(error = %error, "linkedin refused a post deletion");
            handlers::upstream_problem(&error)
        })?;
    }

    store::mark_deleted(db, &row.id, &now)
        .await
        .map_err(|error| {
            tracing::error!(error = %error, "could not mark the post deleted");
            handlers::internal(&scope)
        })?;
    Ok(handlers::ok(json!({
        "ok": true,
        "id": row.id,
        "was_on_linkedin": row.post_urn.is_some(),
        "already_deleted": false,
    })))
}

// ---------------------------------------------------------------------------
// The publisher

/// One pass of the publisher. Returns how many rows it touched.
pub(crate) async fn publish_due(ctx: &ModuleContext, settings: &Settings, scope: &Scope) -> u32 {
    let (Ok(db), Ok(clock)) = (handlers::db(ctx), handlers::clock(ctx)) else {
        return 0;
    };
    let now = store::now_iso(clock);
    let lease_cutoff = store::iso_in(clock, -settings.publish_lease_secs);
    let ids = store::due_post_ids(db, &now, &lease_cutoff, PUBLISH_BATCH)
        .await
        .unwrap_or_default();
    let mut handled = 0;
    for id in ids {
        publish_one(ctx, settings, scope, &id).await;
        handled += 1;
    }
    handled
}

/// Publishes one row, if it can claim it.
pub(crate) async fn publish_one(
    ctx: &ModuleContext,
    settings: &Settings,
    scope: &Scope,
    post_id: &str,
) {
    let (Ok(db), Ok(clock), Ok(http)) =
        (handlers::db(ctx), handlers::clock(ctx), handlers::http(ctx))
    else {
        return;
    };

    let Ok(Some(before)) = store::find_post(db, post_id).await else {
        return;
    };
    if !matches!(
        before.state.as_str(),
        store::POST_SCHEDULED | store::POST_PUBLISHING
    ) {
        return;
    }
    // A row found mid-publish is one whose previous attempt did not finish;
    // so is one that has already failed at least once. Either way LinkedIn
    // may already hold the post, and that is what triggers reconciliation
    // before creating anything. It has to be read *before* the claim, which
    // sets `publishing_since` on every row it touches.
    let reclaimed = before.state == store::POST_PUBLISHING || before.attempts > 0;

    let now = store::now_iso(clock);
    let lease_cutoff = store::iso_in(clock, -settings.publish_lease_secs);
    match store::claim_post(db, post_id, &now, &lease_cutoff).await {
        Ok(true) => {}
        Ok(false) => return,
        Err(error) => {
            tracing::error!(error = %error, "could not claim a post for publishing");
            return;
        }
    }

    let Ok(Some(row)) = store::find_post(db, post_id).await else {
        return;
    };

    let session = match tokens::session(ctx, settings, scope).await {
        Ok(session) => session,
        Err(TokenTrouble::NotConnected | TokenTrouble::NeedsReconnect) => {
            // Not this post's fault: wait for a human rather than burning the
            // row. An hour is long enough not to spin, short enough to
            // resume soon after a reconnect.
            defer(db, &row, clock, 3600, "reconnect_required").await;
            return;
        }
        Err(trouble) => {
            tracing::warn!(trouble = ?trouble, "could not get a token to publish with");
            defer(db, &row, clock, backoff_secs(row.attempts), "token").await;
            return;
        }
    };

    let client = Client::new(http, &settings.api_version, &session.access_token);
    publish_with(ctx, settings, scope, db, clock, &client, &row, reclaimed).await;
    handlers::flush_budget(ctx, client.spent()).await;
}

#[allow(clippy::too_many_arguments)]
async fn publish_with(
    ctx: &ModuleContext,
    settings: &Settings,
    scope: &Scope,
    db: &dyn Database,
    clock: &dyn Clock,
    client: &Client<'_>,
    row: &PostRow,
    reclaimed: bool,
) {
    // Already created: all that is left is to learn how it ended.
    if let Some(urn) = row.post_urn.as_deref() {
        confirm(ctx, scope, db, clock, client, row, urn).await;
        return;
    }

    let page = match store::find_page(db, &row.org_id).await {
        Ok(Some(page)) if page.can_post_organic && page.state == store::PAGE_ACTIVE => page,
        Ok(_) => {
            fail(
                ctx,
                scope,
                db,
                clock,
                row,
                "page_role_missing",
                "the connected account cannot publish organic posts to that page",
            )
            .await;
            return;
        }
        Err(error) => {
            tracing::error!(error = %error, "could not read the page for a post");
            return;
        }
    };

    // Media has to be ready. A post referencing an asset that is still
    // processing renders blank, so it waits instead.
    let (media_urn, alt_text) = match resolve_media(db, row).await {
        Media::None => (None, None),
        Media::Ready { urn, alt_text } => (Some(urn), alt_text),
        Media::Wait => {
            defer(db, row, clock, settings.asset_poll_secs, "asset_processing").await;
            return;
        }
        Media::Gone { code, detail } => {
            fail(ctx, scope, db, clock, row, code, detail).await;
            return;
        }
        Media::Unreadable => return,
    };

    // Reconciliation. A reclaimed lease or a previous attempt means LinkedIn
    // may already hold this post; ask before creating a second one. A first
    // attempt skips this read, because it cannot have created anything yet
    // and the daily request budget is small.
    if reclaimed && let Some(existing) = find_existing(client, &page.urn, row).await {
        tracing::warn!(
            post = %row.id,
            urn = %existing,
            "adopted an existing linkedin post instead of creating a second one"
        );
        let now = store::now_iso(clock);
        if store::set_post_urn(db, &row.id, &existing, &now)
            .await
            .is_ok()
        {
            confirm(ctx, scope, db, clock, client, row, &existing).await;
        }
        return;
    }

    let body = build_body(row, &page.urn, media_urn.as_deref(), alt_text.as_deref());
    match create_with_one_retry(ctx, settings, scope, client, body).await {
        Ok(urn) => {
            let now = store::now_iso(clock);
            if let Err(error) = store::set_post_urn(db, &row.id, &urn, &now).await {
                // The post exists on LinkedIn but we could not record it.
                // Nothing is lost: the next pass reconciles by author.
                tracing::error!(error = %error, urn = %urn, "created a post but could not store its urn");
                return;
            }
            confirm(ctx, scope, db, clock, client, row, &urn).await;
        }
        // A rejected token has already been through one refresh and a replay
        // by now (`create_with_one_retry`). Waiting for a human to reconnect
        // is right; marking the post failed would throw away work that is
        // still perfectly publishable.
        Err(ApiError::TokenRejected) => {
            tracing::warn!(post = %row.id, "publishing is waiting for a reconnect");
            defer(db, row, clock, 3600, "reconnect_required").await;
        }
        Err(error) if error.is_retryable() => {
            let wait = match &error {
                ApiError::RateLimited {
                    retry_after_secs: Some(seconds),
                } => *seconds,
                _ => backoff_secs(row.attempts),
            };
            tracing::warn!(error = %error, "deferring a post after a retryable failure");
            defer(db, row, clock, wait, &error.code()).await;
        }
        Err(error) => {
            let code = error.code();
            fail(ctx, scope, db, clock, row, &code, &error.to_string()).await;
        }
    }
}

/// What the post's attached image is doing. Publishing against anything but
/// `Ready` would put a blank card in the feed.
enum Media {
    None,
    Ready {
        urn: String,
        alt_text: Option<String>,
    },
    /// Still processing at LinkedIn: wait, do not publish.
    Wait,
    Gone {
        code: &'static str,
        detail: &'static str,
    },
    /// Our own database is unhappy; leave the row alone and try later.
    Unreadable,
}

async fn resolve_media(db: &dyn Database, row: &PostRow) -> Media {
    let Some(asset_id) = row.asset_id.as_deref() else {
        return Media::None;
    };
    match images::ready_for_post(db, asset_id).await {
        Ok(Some(asset)) => Media::Ready {
            urn: asset.image_urn,
            alt_text: asset.alt_text,
        },
        Ok(None) => Media::Wait,
        Err(AssetTrouble::Failed) => Media::Gone {
            code: "asset_failed",
            detail: "the image failed processing at LinkedIn",
        },
        Err(AssetTrouble::Missing) => Media::Gone {
            code: "asset_missing",
            detail: "the image is gone",
        },
        Err(AssetTrouble::Db(error)) => {
            tracing::error!(error = %error, "could not read the asset for a post");
            Media::Unreadable
        }
    }
}

/// Creates the post, and if LinkedIn rejects the token, refreshes once and
/// replays (issue #9). A token can be revoked between `session` refreshing it
/// and this call: that is LinkedIn's documented right, and it must not cost a
/// scheduled post its slot when a refresh would fix it.
///
/// The replay is safe precisely because it happens on a `401`: LinkedIn
/// rejected the request before it could create anything.
async fn create_with_one_retry(
    ctx: &ModuleContext,
    settings: &Settings,
    scope: &Scope,
    client: &Client<'_>,
    body: Value,
) -> Result<String, ApiError> {
    match client.create_post(body.clone()).await {
        Err(ApiError::TokenRejected) => {}
        other => return other,
    }

    tracing::warn!("linkedin rejected the access token mid-publish; refreshing once");
    let Ok(http) = handlers::http(ctx) else {
        return Err(ApiError::TokenRejected);
    };
    let Ok(fresh) = tokens::refresh_now(ctx, settings, scope).await else {
        // The refresh failed, which already flipped the account to
        // needs_reconnect and emitted the event. Nothing more to try.
        return Err(ApiError::TokenRejected);
    };
    let retry = Client::new(http, &settings.api_version, &fresh.access_token);
    let result = retry.create_post(body).await;
    handlers::flush_budget(ctx, retry.spent()).await;
    result
}

/// Confirms what happened to a created post. A `201` only means LinkedIn
/// accepted it for publishing.
async fn confirm(
    ctx: &ModuleContext,
    scope: &Scope,
    db: &dyn Database,
    clock: &dyn Clock,
    client: &Client<'_>,
    row: &PostRow,
    urn: &str,
) {
    let now = store::now_iso(clock);
    match client.get_post(urn).await {
        Ok(view) => match view.lifecycle_state.as_str() {
            "PUBLISHED" => {
                if store::mark_published(db, &row.id, &now).await.is_ok() {
                    ctx.events.emit_in(
                        scope,
                        EVENT_POST_PUBLISHED,
                        json!({
                            "post_id": row.id,
                            "org_id": row.org_id,
                            "urn": urn,
                            "permalink": format!("https://www.linkedin.com/feed/update/{urn}/"),
                        }),
                    );
                }
            }
            // LinkedIn's own note: an edit is required before publishing can
            // be re-attempted, so this is terminal rather than a retry.
            "PUBLISH_FAILED" => {
                fail(
                    ctx,
                    scope,
                    db,
                    clock,
                    row,
                    "publish_failed",
                    "LinkedIn could not process the post; it needs an edit before republishing",
                )
                .await;
            }
            // PUBLISH_REQUESTED, PROCESSING, DRAFT: still in flight. The row
            // stays in publish_requested and the next pass asks again.
            other => {
                tracing::info!(post = %row.id, state = %other, "linkedin post is still publishing");
            }
        },
        Err(ApiError::NotFound) => {
            fail(
                ctx,
                scope,
                db,
                clock,
                row,
                "not_found",
                "LinkedIn does not have that post any more",
            )
            .await;
        }
        Err(error) => {
            tracing::warn!(error = %error, "could not confirm a post; will ask again");
        }
    }
}

/// The reconciliation read: has LinkedIn already got this post? Matched on
/// the commentary and a creation window, because there is no idempotency key
/// to match on.
async fn find_existing(client: &Client<'_>, author_urn: &str, row: &PostRow) -> Option<String> {
    let recent = client.posts_by_author(author_urn, 20).await.ok()?;
    let created_at = store::parse_iso(&row.created_at)?;
    let window_start = (created_at - time::Duration::minutes(10)).unix_timestamp() * 1000;
    recent
        .into_iter()
        .find(|view| {
            view.created_at_ms >= window_start
                && commentary_matches(&view.commentary, &row.commentary)
        })
        .map(|view| view.urn)
}

/// Compares commentary ignoring backslash escapes: what LinkedIn stores and
/// what it returns need not agree byte for byte about escaping, and a false
/// negative here would post twice.
fn commentary_matches(a: &str, b: &str) -> bool {
    fn strip(value: &str) -> String {
        value.chars().filter(|ch| *ch != '\\').collect()
    }
    strip(a) == strip(b)
}

fn build_body(
    row: &PostRow,
    author_urn: &str,
    media_urn: Option<&str>,
    alt_text: Option<&str>,
) -> Value {
    let mut body = json!({
        "author": author_urn,
        "commentary": row.commentary,
        "visibility": row.visibility,
        "distribution": {
            "feedDistribution": "MAIN_FEED",
            "targetEntities": [],
            "thirdPartyDistributionChannels": [],
        },
        "lifecycleState": "PUBLISHED",
        "isReshareDisabledByAuthor": false,
    });

    if let Some(media) = media_urn {
        let mut media_object = json!({ "id": media });
        if let Some(alt) = alt_text {
            media_object["altText"] = json!(alt);
        }
        body["content"] = json!({ "media": media_object });
    } else if let Some(source) = row.article_source.as_deref() {
        // LinkedIn does not scrape the URL, so the title and description are
        // ours to supply or the card renders bare.
        let mut article = json!({ "source": source });
        if let Some(title) = row.article_title.as_deref() {
            article["title"] = json!(title);
        }
        if let Some(description) = row.article_description.as_deref() {
            article["description"] = json!(description);
        }
        body["content"] = json!({ "article": article });
    }
    body
}

async fn defer(db: &dyn Database, row: &PostRow, clock: &dyn Clock, secs: i64, reason: &str) {
    let now = store::now_iso(clock);
    let not_before = store::iso_in(clock, secs);
    if let Err(error) = store::defer_post(db, &row.id, &not_before, reason, &now).await {
        tracing::error!(error = %error, "could not defer a post");
    }
}

async fn fail(
    ctx: &ModuleContext,
    scope: &Scope,
    db: &dyn Database,
    clock: &dyn Clock,
    row: &PostRow,
    code: &str,
    detail: &str,
) {
    let now = store::now_iso(clock);
    if store::mark_failed(db, &row.id, code, detail, &now)
        .await
        .is_ok()
    {
        ctx.events.emit_in(
            scope,
            EVENT_POST_FAILED,
            json!({
                "post_id": row.id,
                "org_id": row.org_id,
                "code": code,
                "detail": detail,
            }),
        );
    }
}

/// The cron pass over posts LinkedIn accepted but has not finished
/// publishing.
pub(crate) async fn confirm_pending(
    ctx: &ModuleContext,
    settings: &Settings,
    scope: &Scope,
) -> u32 {
    let (Ok(db), Ok(clock), Ok(http)) =
        (handlers::db(ctx), handlers::clock(ctx), handlers::http(ctx))
    else {
        return 0;
    };
    let pending = store::awaiting_confirmation(db, CONFIRM_BATCH)
        .await
        .unwrap_or_default();
    if pending.is_empty() {
        return 0;
    }
    let Ok(session) = tokens::session(ctx, settings, scope).await else {
        return 0;
    };
    let client = Client::new(http, &settings.api_version, &session.access_token);
    let mut checked = 0;
    for row in pending {
        if let Some(urn) = row.post_urn.clone() {
            confirm(ctx, scope, db, clock, &client, &row, &urn).await;
            checked += 1;
        }
    }
    handlers::flush_budget(ctx, client.spent()).await;
    checked
}

#[cfg(test)]
mod tests {
    use super::*;

    fn row() -> PostRow {
        PostRow {
            id: "post_1".to_owned(),
            account_id: "acc_1".to_owned(),
            org_id: "2414183".to_owned(),
            idempotency_key: "key".to_owned(),
            commentary: "Hello".to_owned(),
            visibility: "PUBLIC".to_owned(),
            asset_id: None,
            article_source: None,
            article_title: None,
            article_description: None,
            state: store::POST_SCHEDULED.to_owned(),
            post_urn: None,
            scheduled_at: None,
            not_before: None,
            publishing_since: None,
            attempts: 0,
            error_code: None,
            error_detail: None,
            edited_at: None,
            previous_commentary: None,
            created_at: "2026-09-07T10:00:00Z".to_owned(),
            published_at: None,
            deleted_at: None,
        }
    }

    #[test]
    fn a_text_post_carries_what_linkedin_requires() {
        let body = build_body(&row(), "urn:li:organization:2414183", None, None);
        assert_eq!(body["author"], "urn:li:organization:2414183");
        assert_eq!(body["lifecycleState"], "PUBLISHED");
        assert_eq!(body["distribution"]["feedDistribution"], "MAIN_FEED");
        assert_eq!(body["visibility"], "PUBLIC");
        assert!(body.get("content").is_none(), "a text post has no content");
    }

    #[test]
    fn media_and_article_are_mutually_exclusive_and_media_wins() {
        let mut with_article = row();
        with_article.article_source = Some("https://example.com".to_owned());
        let body = build_body(
            &with_article,
            "urn:li:organization:1",
            Some("urn:li:image:A"),
            Some("a chart"),
        );
        assert_eq!(body["content"]["media"]["id"], "urn:li:image:A");
        assert_eq!(body["content"]["media"]["altText"], "a chart");
        assert!(body["content"].get("article").is_none());
    }

    #[test]
    fn an_article_post_supplies_its_own_title() {
        let mut article = row();
        article.article_source = Some("https://example.com/x".to_owned());
        article.article_title = Some("Title".to_owned());
        article.article_description = Some("Description".to_owned());
        let body = build_body(&article, "urn:li:organization:1", None, None);
        assert_eq!(
            body["content"]["article"]["source"],
            "https://example.com/x"
        );
        assert_eq!(body["content"]["article"]["title"], "Title");
        assert_eq!(body["content"]["article"]["description"], "Description");
    }

    #[test]
    fn commentary_matching_survives_escape_round_trips() {
        assert!(commentary_matches("a\\_b", "a_b"));
        assert!(commentary_matches("Hello", "Hello"));
        assert!(!commentary_matches("Hello", "Hello there"));
    }

    #[test]
    fn backoff_grows_then_settles() {
        assert_eq!(backoff_secs(0), 300);
        assert_eq!(backoff_secs(1), 600);
        assert_eq!(backoff_secs(2), 1800);
        assert_eq!(backoff_secs(9), 3600);
    }

    #[test]
    fn call_to_action_labels_are_version_gated() {
        assert!(cta_allowed("LEARN_MORE", "202601"));
        assert!(cta_allowed("BUY_NOW", "202601"));
        assert!(!cta_allowed("BUY_NOW", "202501"));
        assert!(!cta_allowed("DO_A_BARREL_ROLL", "202608"));
    }
}
