//! The client-registration admin API (issue #6): create, rotate, patch
//! and list registered consuming apps under `admin/clients`. Every
//! route answers only behind the harness `require_admin` layer and
//! writes one audit line carrying the action and the client id — never
//! a secret, never a secret's hash.
//!
//! The plaintext secret exists exactly once, in the 201/200 body of the
//! create and rotate responses; only its argon2id hash is stored
//! ([`crate::secrets`]). Public clients rely on PKCE: their row holds
//! the hash of a secret whose plaintext was discarded at creation, so
//! no presented secret can ever verify.

use axum::extract::{Path, Request, State};
use axum::http::StatusCode;
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use axum::routing::{patch, post};
use cratefield_core::{Clock, Database, Json, Problem, Scope, require_admin};
use serde::Deserialize;
use serde_json::{Value, json};
use std::sync::Arc;

use crate::ModuleState;
use crate::secrets;
use crate::store::{
    self, CLIENT_CONFIDENTIAL, CLIENT_PUBLIC, ClientRow, Redacted, STATUS_ACTIVE, STATUS_DISABLED,
};

const MAX_REDIRECT_URIS: usize = 32;
const MAX_REDIRECT_URI_BYTES: usize = 2048;

/// The harness `admin_auth` layer: `Authorization: Bearer <ADMIN_TOKEN>`
/// is checked before any body parsing, so an unauthenticated request
/// can never reach a handler — not even to be told its body was invalid.
async fn admin_guard(
    State(state): State<Arc<ModuleState>>,
    request: Request,
    next: Next,
) -> Response {
    let scope = request.extensions().get::<Scope>().cloned();
    if let Err(problem) = require_admin(&*state.ctx.config, request.headers()) {
        let problem = match scope.as_ref() {
            Some(scope) => problem.instance(&scope.request_id),
            None => problem,
        };
        return problem.into_response();
    }
    next.run(request).await
}

pub(crate) fn router(state: Arc<ModuleState>) -> axum::Router {
    axum::Router::new()
        .route("/admin/clients", post(create).get(list))
        .route("/admin/clients/{id}", patch(patch_client))
        .route("/admin/clients/{id}/rotate-secret", post(rotate_secret))
        .route_layer(axum::middleware::from_fn_with_state(
            Arc::clone(&state),
            admin_guard,
        ))
        .with_state(state)
}
fn now_iso(clock: &dyn Clock) -> String {
    clock
        .now()
        .replace_nanosecond(0)
        .expect("truncation stays in range")
        .format(&time::format_description::well_known::Rfc3339)
        .expect("rfc3339 formats")
}

fn internal(scope: &Scope) -> Problem {
    Problem::internal().instance(&scope.request_id)
}

fn bad_request(scope: &Scope, detail: impl Into<String>) -> Problem {
    Problem::validation_failed(detail).instance(&scope.request_id)
}

fn audit(action: &str, client_id: &str) {
    tracing::info!(audit = true, action, client_id, "auth-core admin");
}

fn sanitize_name(raw: &str) -> Result<String, Problem> {
    let name = raw.trim();
    if name.is_empty() || name.len() > 128 {
        return Err(Problem::validation_failed("name must be 1..=128 bytes"));
    }
    Ok(name.to_owned())
}

fn validate_kind(kind: &str) -> Result<(), Problem> {
    if matches!(kind, CLIENT_CONFIDENTIAL | CLIENT_PUBLIC) {
        Ok(())
    } else {
        Err(Problem::validation_failed(format!(
            "kind must be `{CLIENT_CONFIDENTIAL}` or `{CLIENT_PUBLIC}`"
        )))
    }
}

fn validate_redirect_uris(uris: &[String], kind: &str) -> Result<(), Problem> {
    if uris.is_empty() {
        return Err(Problem::validation_failed(
            "redirect_uris must not be empty",
        ));
    }
    if uris.len() > MAX_REDIRECT_URIS {
        return Err(Problem::validation_failed(format!(
            "at most {MAX_REDIRECT_URIS} redirect URIs per client"
        )));
    }
    for uri in uris {
        if uri.len() > MAX_REDIRECT_URI_BYTES {
            return Err(Problem::validation_failed(
                "a redirect URI exceeds 2048 bytes",
            ));
        }
        // The same rule /authorize will apply (issue #7): registration
        // rejects any URI the matcher would never accept.
        crate::redirect_uri::validate_registration(uri, kind)?;
    }
    Ok(())
}

/// The hash every new client row starts from, and the plaintext when
/// this client kind gets one at all. Confidential clients keep the
/// plaintext (returned once by the caller); public clients discard it
/// immediately — a public client has no secret to present.
fn hash_new_secret(kind: &str) -> Result<(String, Option<String>), Problem> {
    let secret = secrets::generate_secret().map_err(|err| {
        tracing::error!(error = %err, "secret generation failed");
        Problem::internal()
    })?;
    let hash = secrets::hash_secret(&secret).map_err(|err| {
        tracing::error!(error = %err, "secret hashing failed");
        Problem::internal()
    })?;
    let plaintext = (kind == CLIENT_CONFIDENTIAL).then_some(secret);
    Ok((hash, plaintext))
}

async fn redirect_uris_of(db: &dyn Database, client_id: &str) -> Result<Vec<String>, Problem> {
    Ok(store::redirect_uris_for_client(db, client_id)
        .await?
        .into_iter()
        .map(|row| row.uri)
        .collect())
}

/// The admin-visible shape of a client: everything except the hashes.
async fn client_view(db: &dyn Database, row: &ClientRow) -> Result<Value, Problem> {
    Ok(json!({
        "id": row.id,
        "name": row.name,
        "kind": row.kind,
        "status": row.status,
        "created_at": row.created_at,
        "redirect_uris": redirect_uris_of(db, &row.id).await?,
    }))
}

#[derive(Deserialize)]
struct CreateBody {
    name: String,
    kind: String,
    redirect_uris: Vec<String>,
}

async fn create(
    scope: Scope,
    State(state): State<Arc<ModuleState>>,
    Json(body): Json<CreateBody>,
) -> Result<Response, Problem> {
    let name = sanitize_name(&body.name).map_err(|p| p.instance(&scope.request_id))?;
    validate_kind(&body.kind).map_err(|p| p.instance(&scope.request_id))?;
    validate_redirect_uris(&body.redirect_uris, &body.kind)
        .map_err(|p| p.instance(&scope.request_id))?;

    let (Some(db), Some(clock), Some(id_gen)) = (
        state.ctx.ports.db.clone(),
        state.ctx.ports.clock.clone(),
        state.ctx.ports.id_gen.clone(),
    ) else {
        return Err(internal(&scope));
    };

    let id = id_gen.ulid();
    let (secret_hash, plaintext) = hash_new_secret(&body.kind)?;

    store::insert_client(
        &*db,
        &ClientRow {
            id: id.clone(),
            name: name.clone(),
            secret_hash: Redacted(secret_hash),
            previous_secret_hash: None,
            previous_hash_expires_at: None,
            kind: body.kind.clone(),
            status: STATUS_ACTIVE.to_owned(),
            created_at: now_iso(&*clock),
        },
    )
    .await?;
    store::replace_redirect_uris(&*db, &id, &body.redirect_uris).await?;

    audit("client.create", &id);
    let mut response = json!({
        "id": id,
        "name": name,
        "kind": body.kind,
        "status": STATUS_ACTIVE,
        "redirect_uris": body.redirect_uris,
    });
    if let Some(secret) = plaintext {
        response["client_secret"] = json!(secret);
    }
    Ok((StatusCode::CREATED, Json(response)).into_response())
}

async fn list(scope: Scope, State(state): State<Arc<ModuleState>>) -> Result<Response, Problem> {
    let Some(db) = state.ctx.ports.db.clone() else {
        return Err(internal(&scope));
    };
    let mut views = Vec::new();
    for row in store::list_clients(&*db).await? {
        views.push(client_view(&*db, &row).await?);
    }
    audit("client.list", "all");
    Ok(Json(Value::Array(views)).into_response())
}

#[derive(Deserialize)]
struct PatchBody {
    name: Option<String>,
    status: Option<String>,
    redirect_uris: Option<Vec<String>>,
}

async fn patch_client(
    scope: Scope,
    State(state): State<Arc<ModuleState>>,
    Path(id): Path<String>,
    Json(body): Json<PatchBody>,
) -> Result<Response, Problem> {
    if body.name.is_none() && body.status.is_none() && body.redirect_uris.is_none() {
        return Err(bad_request(
            &scope,
            "nothing to change: name, status or redirect_uris",
        ));
    }
    if let Some(status) = &body.status
        && !matches!(status.as_str(), STATUS_ACTIVE | STATUS_DISABLED)
    {
        return Err(bad_request(
            &scope,
            format!("status must be `{STATUS_ACTIVE}` or `{STATUS_DISABLED}`"),
        ));
    }
    let Some(db) = state.ctx.ports.db.clone() else {
        return Err(internal(&scope));
    };
    let row = store::client_by_id(&*db, &id)
        .await?
        .ok_or_else(|| Problem::not_found().instance(&scope.request_id))?;
    if let Some(uris) = &body.redirect_uris {
        // URIs are validated against the kind the client already has;
        // kind itself is immutable (a public client becoming
        // confidential is a new client).
        validate_redirect_uris(uris, &row.kind).map_err(|p| p.instance(&scope.request_id))?;
    }

    if let Some(name) = &body.name {
        let name = sanitize_name(name).map_err(|p| p.instance(&scope.request_id))?;
        store::update_client_name(&*db, &id, &name).await?;
    }
    if let Some(status) = &body.status {
        store::update_client_status(&*db, &id, status).await?;
    }
    if let Some(uris) = &body.redirect_uris {
        store::replace_redirect_uris(&*db, &id, uris).await?;
    }

    audit("client.patch", &id);
    let fresh = store::client_by_id(&*db, &id)
        .await?
        .ok_or_else(|| internal(&scope))?;
    Ok(Json(client_view(&*db, &fresh).await?).into_response())
}

async fn rotate_secret(
    scope: Scope,
    State(state): State<Arc<ModuleState>>,
    Path(id): Path<String>,
) -> Result<Response, Problem> {
    let (Some(db), Some(clock)) = (state.ctx.ports.db.clone(), state.ctx.ports.clock.clone())
    else {
        return Err(internal(&scope));
    };
    let Some(row) = store::client_by_id(&*db, &id).await? else {
        return Err(Problem::not_found().instance(&scope.request_id));
    };
    if !secrets::kind_allows_secret(&row.kind) {
        return Err(bad_request(
            &scope,
            "public clients have no secret to rotate",
        ));
    }

    let (hash, plaintext) = hash_new_secret(CLIENT_CONFIDENTIAL)?;
    let plaintext = plaintext.ok_or_else(|| internal(&scope))?;
    let overlap_secs: i64 = state.secret_overlap_secs.try_into().unwrap_or(i64::MAX);
    let overlap_ends = clock
        .now()
        .replace_nanosecond(0)
        .expect("truncation stays in range")
        .saturating_add(time::Duration::seconds(overlap_secs))
        .format(&time::format_description::well_known::Rfc3339)
        .expect("rfc3339 formats");
    store::rotate_client_secret(&*db, &id, &hash, &overlap_ends).await?;

    audit("client.rotate-secret", &id);
    Ok(Json(json!({
        "client_secret": plaintext,
        "previous_hash_expires_at": overlap_ends,
    }))
    .into_response())
}
