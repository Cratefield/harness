//! The account on/off switch (issue #854): the two admin routes that
//! disable an account and undo it, under the same
//! `Authorization: Bearer <ADMIN_TOKEN>` guard as the client API
//! ([`crate::clients`]) and the import API ([`crate::import`]).
//!
//! Disable is the whole kill switch in one call: the `users.status` flag
//! moves first — in the same commit as its `user_admin_audit` row — and
//! then every live session is revoked and every live refresh token
//! retired. Refusing *new* sign-ins needs no work here: every login
//! method funnels through [`crate::sessions::issue`], which reads the
//! flag, and the token endpoint re-reads it when a refresh grant is
//! presented (`token_endpoint`'s `live_session_and_user`). A successor
//! minted moments earlier, inside the refresh-reuse grace, dies on
//! arrival — the disable revokes the session it is bound to. What the
//! flag alone cannot do is pull live credentials out from under the
//! account — that is what the revocations are for.
//!
//! Idempotent on purpose: disabling an already-disabled account (or
//! enabling an active one) answers `200` with the same shape, still
//! writes its audit row — the call is the action being recorded — and
//! re-runs the revocations, which find nothing left and report `0`.
//!
//! The response is counts, not state: `sub`, the status now on the row,
//! and how many sessions and refresh tokens this call took away. An
//! account a second call finds already disabled reports zeros, so an
//! operator can tell a first disable from a repeat.

use axum::extract::{Path, State};
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use cratefield_core::{Json, Problem, Scope, subject_hash};
use serde_json::json;
use std::sync::Arc;

use crate::ModuleState;
use crate::store::{self, STATUS_ACTIVE, STATUS_DISABLED, TOKEN_REFRESH, UserAdminAuditRow};

pub(crate) fn router(state: Arc<ModuleState>) -> axum::Router {
    axum::Router::new()
        .route("/admin/users/{sub}/disable", post(disable))
        .route("/admin/users/{sub}/enable", post(enable))
        .route_layer(axum::middleware::from_fn_with_state(
            Arc::clone(&state),
            crate::clients::admin_guard,
        ))
        .with_state(state)
}

fn internal(scope: &Scope) -> Problem {
    Problem::internal().instance(&scope.request_id)
}

fn audit(action: &str, sub: &str) {
    tracing::info!(
        audit = true,
        action,
        subject_hash = %subject_hash(sub),
        "auth-core admin"
    );
}

/// `POST /admin/users/{sub}/disable` — the kill switch: no new sign-in,
/// no live session, no usable refresh token.
async fn disable(
    scope: Scope,
    State(state): State<Arc<ModuleState>>,
    Path(sub): Path<String>,
) -> Result<Response, Problem> {
    switch(&scope, &state, &sub, STATUS_DISABLED, "user.disable").await
}

/// `POST /admin/users/{sub}/enable` — the undo: sign-ins are accepted
/// again. What disable took away stays taken: no session is restored,
/// and the person signs in again as normal.
async fn enable(
    scope: Scope,
    State(state): State<Arc<ModuleState>>,
    Path(sub): Path<String>,
) -> Result<Response, Problem> {
    switch(&scope, &state, &sub, STATUS_ACTIVE, "user.enable").await
}

/// The shared body of both routes: flip `users.status` beside its audit
/// row, then — for a disable — pull the live access paths out. The flag
/// moves first because it is what refuses the racing sign-in; the
/// revocations after it can only find what was live before the flip.
async fn switch(
    scope: &Scope,
    state: &Arc<ModuleState>,
    sub: &str,
    status: &str,
    action: &str,
) -> Result<Response, Problem> {
    let (Some(db), Some(clock), Some(id_gen)) = (
        state.ctx.ports.db.clone(),
        state.ctx.ports.clock.clone(),
        state.ctx.ports.id_gen.clone(),
    ) else {
        return Err(internal(scope));
    };
    // An unknown sub is a 404, not a silent 200: the caller holds an
    // admin token and named an account, so "nobody by that id" is an
    // answer they need.
    store::user_by_id(&*db, sub)
        .await?
        .ok_or_else(|| Problem::not_found().instance(&scope.request_id))?;

    let now = crate::clients::now_iso(&*clock);
    store::set_user_status(
        &*db,
        sub,
        status,
        &UserAdminAuditRow {
            id: id_gen.ulid(),
            user_id: sub.to_owned(),
            action: action.to_owned(),
            at: now.clone(),
        },
        &now,
    )
    .await?;

    // The batch reports no per-statement counts, and the account can be
    // erased between the check above and the batch — the audit insert
    // draws its `user_id` from the users row itself, so that race leaves
    // nothing dangling, and this re-read gives the erasure the same 404
    // the first check would have. On the common path this is one more
    // read that finds the account exactly where it was left.
    if store::user_by_id(&*db, sub).await?.is_none() {
        return Err(Problem::not_found().instance(&scope.request_id));
    }
    audit(action, sub);

    // Disable only: what the account still holds. Sessions first — a
    // cookie presented mid-revocation is already refused by the flag.
    let (sessions_revoked, refresh_tokens_revoked) = if status == STATUS_DISABLED {
        (
            crate::sessions::revoke_all(&*db, &*clock, sub).await?,
            store::retire_unconsumed_tokens(&*db, TOKEN_REFRESH, sub, &now).await?,
        )
    } else {
        (0, 0)
    };

    Ok(Json(json!({
        "sub": sub,
        "status": status,
        "sessions_revoked": sessions_revoked,
        "refresh_tokens_revoked": refresh_tokens_revoked,
    }))
    .into_response())
}
