//! Media upload (issue #11).
//!
//! LinkedIn's image flow is three calls: register the upload, `PUT` the bytes
//! to the URL it hands back, then wait for the asset to become `AVAILABLE`.
//! The Images API has no synchronous mode, so the wait is not optional: a post
//! that references an asset still processing is the classic way to publish
//! something that never renders.

use axum::extract::{Path, State};
use axum::http::{HeaderMap, header};
use axum::response::Response;
use bytes::Bytes;
use cratefield_core::{Database, ModuleContext, Problem, Scope};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::sync::Arc;

use crate::client::Client;
use crate::handlers::{self, ModuleState, Settings};
use crate::imagehdr;
use crate::store::{self, AssetRow};
use crate::tokens;

/// LinkedIn's own status strings.
const LI_AVAILABLE: &str = "AVAILABLE";
const LI_PROCESSING_FAILED: &str = "PROCESSING_FAILED";
const LI_WAITING_UPLOAD: &str = "WAITING_UPLOAD";

fn hex(bytes: &[u8]) -> String {
    const HEX: [u8; 16] = *b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX[usize::from(byte >> 4)] as char);
        out.push(HEX[usize::from(byte & 0x0f)] as char);
    }
    out
}

fn map_status(linkedin: &str) -> &'static str {
    match linkedin {
        LI_AVAILABLE => store::ASSET_AVAILABLE,
        LI_PROCESSING_FAILED => store::ASSET_FAILED,
        LI_WAITING_UPLOAD => store::ASSET_WAITING,
        _ => store::ASSET_PROCESSING,
    }
}

/// What the local checks established about the body.
struct CheckedImage {
    format: imagehdr::Format,
    width: u32,
    height: u32,
    alt_text: Option<String>,
}

/// Everything that can be decided without spending a LinkedIn request:
/// size, declared type against the real bytes, pixel count, alt text length.
/// The Development Tier allows 500 requests a day, so a bad upload must never
/// cost one.
fn check_image(
    headers: &HeaderMap,
    body: &Bytes,
    max_bytes: usize,
) -> Result<CheckedImage, Problem> {
    if body.len() > max_bytes {
        return Err(Problem::request_too_large());
    }
    if body.is_empty() {
        return Err(Problem::validation_failed("the request body is empty"));
    }

    let content_type = headers
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default();
    let (format, width, height) = imagehdr::inspect(body)
        .ok_or_else(|| Problem::validation_failed("the body is not a JPEG, PNG or GIF image"))?;
    if !format.accepts(content_type) {
        return Err(Problem::validation_failed(format!(
            "the body is {} but the request announced {content_type:?}",
            format.content_type()
        )));
    }

    let pixels = u64::from(width) * u64::from(height);
    if pixels > imagehdr::MAX_PIXELS {
        return Err(Problem::validation_failed(format!(
            "{width}x{height} is {pixels} pixels; LinkedIn accepts fewer than {}",
            imagehdr::MAX_PIXELS
        )));
    }

    let alt_text = alt_text_of(headers);
    if let Some(alt) = alt_text.as_deref()
        && alt.chars().count() > 4086
    {
        return Err(Problem::validation_failed(
            "alt text is longer than LinkedIn's 4,086 character limit",
        ));
    }

    Ok(CheckedImage {
        format,
        width,
        height,
        alt_text,
    })
}

/// Takes the raw image body. Not multipart: parsing multipart in wasm buys
/// nothing when the request carries exactly one file.
///
/// This route runs under its own `DefaultBodyLimit` (see `handlers::router`),
/// because core caps every `/v1/*` body at 64 KiB and an image is not that.
pub(crate) async fn upload(
    State(state): State<Arc<ModuleState>>,
    scope: Scope,
    headers: HeaderMap,
    Path(org): Path<String>,
    body: Bytes,
) -> Result<Response, Problem> {
    handlers::admin(&state, &headers)?;
    let ctx = state.ctx.as_ref();
    let settings = state.settings();
    let db = handlers::db(ctx)?;
    let clock = handlers::clock(ctx)?;
    let http = handlers::http(ctx)?;
    let id_gen = handlers::id_gen(ctx)?;

    let page = crate::pages::require_known(db, &org).await?;
    let checked = check_image(&headers, &body, settings.max_image_bytes)?;

    let digest = hex(&Sha256::digest(&body));

    // Reuse an upload of the same bytes for the same page, but never one that
    // failed processing: dedupe must not make a bad upload permanent.
    if let Some(existing) = store::find_reusable_asset(db, &page.org_id, &digest)
        .await
        .map_err(|error| {
            tracing::error!(error = %error, "could not look for a reusable asset");
            handlers::internal(&scope)
        })?
    {
        return Ok(handlers::accepted(json!({
            "asset_id": existing.id,
            "image_urn": existing.image_urn,
            "status": existing.status,
            "reused": true,
        })));
    }

    let session = tokens::session(ctx, &settings, &scope)
        .await
        .map_err(|trouble| trouble.problem(&scope))?;
    let client = Client::new(http, clock, &settings.api_version, &session.access_token);

    let result = async {
        let initialized = client.initialize_image_upload(&page.urn).await?;
        client
            .upload_image(
                &initialized.upload_url,
                checked.format.content_type(),
                body.clone(),
            )
            .await?;
        // One status read here rather than making the caller poll for the
        // common case where processing is quick.
        let status = client
            .image_status(&initialized.image_urn)
            .await
            .unwrap_or_else(|_| LI_WAITING_UPLOAD.to_owned());
        Ok::<_, crate::client::ApiError>((initialized.image_urn, status))
    }
    .await;
    handlers::flush_budget(ctx, client.spent()).await;

    let (image_urn, linkedin_status) = result.map_err(|error| {
        tracing::warn!(error = %error, "linkedin image upload failed");
        handlers::upstream_problem(&error)
    })?;

    let asset = AssetRow {
        id: id_gen.ulid(),
        account_id: session.account_id.clone(),
        org_id: page.org_id.clone(),
        image_urn,
        status: map_status(&linkedin_status).to_owned(),
        sha256: digest,
        byte_len: i64::try_from(body.len()).unwrap_or(i64::MAX),
        alt_text: checked.alt_text.clone(),
        checked_at: Some(store::now_iso(clock)),
    };
    store::insert_asset(db, &asset, &store::now_iso(clock))
        .await
        .map_err(|error| {
            tracing::error!(error = %error, "could not record the linkedin asset");
            handlers::internal(&scope)
        })?;

    Ok(handlers::accepted(json!({
        "asset_id": asset.id,
        "image_urn": asset.image_urn,
        "status": asset.status,
        "width": checked.width,
        "height": checked.height,
        "reused": false,
    })))
}

/// `alt_text` travels as a header rather than a query parameter so the body
/// stays the file and nothing else.
fn alt_text_of(headers: &HeaderMap) -> Option<String> {
    headers
        .get("x-alt-text")
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
}

pub(crate) async fn status(
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

    let asset = store::find_asset(db, &id)
        .await
        .map_err(|error| {
            tracing::error!(error = %error, "could not read the linkedin asset");
            handlers::internal(&scope)
        })?
        .ok_or_else(Problem::not_found)?;

    // Refresh from LinkedIn at most once a minute per asset, and only while
    // it is still in flight.
    let is_stale = asset
        .checked_at
        .as_deref()
        .and_then(store::parse_iso)
        .is_none_or(|checked| (clock.now() - checked).whole_seconds() >= settings.asset_poll_secs);
    let in_flight = matches!(
        asset.status.as_str(),
        store::ASSET_WAITING | store::ASSET_PROCESSING
    );
    let asset = if is_stale && in_flight {
        refresh(ctx, &settings, &scope, &asset)
            .await
            .unwrap_or(asset)
    } else {
        asset
    };

    Ok(handlers::ok(json!({
        "asset_id": asset.id,
        "org_id": asset.org_id,
        "image_urn": asset.image_urn,
        "status": asset.status,
        "byte_len": asset.byte_len,
        "alt_text": asset.alt_text,
        "checked_at": asset.checked_at,
    })))
}

/// Reads one asset's status from LinkedIn and stores it. Used by the status
/// route and by the five-minute cron.
pub(crate) async fn refresh(
    ctx: &ModuleContext,
    settings: &Settings,
    scope: &Scope,
    asset: &AssetRow,
) -> Option<AssetRow> {
    let db = handlers::db(ctx).ok()?;
    let clock = handlers::clock(ctx).ok()?;
    let http = handlers::http(ctx).ok()?;
    let session = tokens::session(ctx, settings, scope).await.ok()?;
    let client = Client::new(http, clock, &settings.api_version, &session.access_token);
    let status = client.image_status(&asset.image_urn).await;
    handlers::flush_budget(ctx, client.spent()).await;

    let status = match status {
        Ok(status) => status,
        Err(error) => {
            tracing::warn!(error = %error, "could not read an asset status");
            return None;
        }
    };
    let mapped = map_status(&status);
    let now = store::now_iso(clock);
    if let Err(error) = store::set_asset_status(db, &asset.id, mapped, &now).await {
        tracing::error!(error = %error, "could not store an asset status");
        return None;
    }
    let mut updated = asset.clone();
    mapped.clone_into(&mut updated.status);
    updated.checked_at = Some(now);
    Some(updated)
}

/// The cron pass over assets that have not settled yet.
pub(crate) async fn poll_in_flight(ctx: &ModuleContext, settings: &Settings, scope: &Scope) -> u32 {
    let Ok(db) = handlers::db(ctx) else {
        return 0;
    };
    let assets = store::assets_in_flight(db).await.unwrap_or_default();
    let mut settled = 0;
    for asset in assets {
        if let Some(updated) = refresh(ctx, settings, scope, &asset).await
            && updated.status != store::ASSET_WAITING
            && updated.status != store::ASSET_PROCESSING
        {
            settled += 1;
        }
    }
    settled
}

/// The asset a post is about to reference, if it is ready. `Ok(None)` means
/// "not yet": the caller should wait rather than publish something that will
/// render blank.
pub(crate) async fn ready_for_post(
    db: &dyn Database,
    asset_id: &str,
) -> Result<Option<AssetRow>, AssetTrouble> {
    let asset = store::find_asset(db, asset_id)
        .await
        .map_err(AssetTrouble::Db)?
        .ok_or(AssetTrouble::Missing)?;
    match asset.status.as_str() {
        store::ASSET_AVAILABLE => Ok(Some(asset)),
        store::ASSET_FAILED => Err(AssetTrouble::Failed),
        _ => Ok(None),
    }
}

#[derive(Debug)]
pub(crate) enum AssetTrouble {
    Missing,
    Failed,
    Db(cratefield_core::DbError),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn linkedin_statuses_map_onto_ours() {
        assert_eq!(map_status("AVAILABLE"), store::ASSET_AVAILABLE);
        assert_eq!(map_status("PROCESSING_FAILED"), store::ASSET_FAILED);
        assert_eq!(map_status("WAITING_UPLOAD"), store::ASSET_WAITING);
        assert_eq!(map_status("PROCESSING"), store::ASSET_PROCESSING);
        // An unknown status is treated as still in flight rather than as
        // ready: publishing against it would be the expensive mistake.
        assert_eq!(map_status("SOMETHING_NEW"), store::ASSET_PROCESSING);
    }

    #[test]
    fn hex_is_lowercase_and_padded() {
        assert_eq!(hex(&[0x00, 0x0f, 0xff]), "000fff");
    }
}
