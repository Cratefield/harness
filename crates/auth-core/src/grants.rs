//! The clients a person has authorized on this deployment, and the way to
//! change that (venture linking). Used by the account console of a Factory
//! Zero style account page, never by a venture.
//!
//! A grant is written when an authorization code is issued to a client for a
//! signed-in person (see `authorize.rs`), so the list is "every client this
//! person has signed in to here", not a guess.
//!
//! Who may call it: the one client named by `AUTH_CORE_GRANTS_CLIENT_ID`,
//! with an access token it was issued (`aud` is that client, `sid` a live
//! session, `sub` the session's user). Any other client's token is refused,
//! so a venture cannot read the list of ventures its person also uses. With
//! the variable unset the routes do not exist (404).
//!
//! Revoking spends the person's refresh tokens for that client, and stops the
//! client receiving codes for this person: `/authorize` refuses with
//! `access_denied` until the person grants the client again here (the POST
//! route, the "Link" action). It does not recall access tokens already issued:
//! those are short-lived ES256 JWTs and carry no server-side state to remove.

use std::sync::Arc;

use axum::Json;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, get};
use cratefield_core::{Clock, Database, ModuleConfig, Problem};
use serde_json::{Value, json};

use crate::ModuleState;
use crate::sessions::iso;
use crate::store;
use crate::token_endpoint::live_session_and_user;
use crate::tokens::verify_access_token;

const GRANTS_CLIENT_KEY: &str = "GRANTS_CLIENT_ID";

pub(crate) fn router() -> axum::Router<Arc<ModuleState>> {
    axum::Router::new()
        .route("/grants", get(list_grants))
        .route(
            "/grants/{client_id}",
            delete(revoke_grant).post(grant_client),
        )
}

/// The database and clock a grants request needs.
type Ports = (Arc<dyn Database>, Arc<dyn Clock>);

fn ports(state: &ModuleState) -> Result<Ports, Problem> {
    match (state.ctx.ports.db.clone(), state.ctx.ports.clock.clone()) {
        (Some(db), Some(clock)) => Ok((db, clock)),
        _ => Err(Problem::internal()),
    }
}

/// The one client allowed to read and change grants, or `None` when the
/// feature is off for this deployment.
fn grants_client(state: &ModuleState) -> Option<String> {
    ModuleConfig::new("auth-core", &*state.ctx.config)
        .get_opt(GRANTS_CLIENT_KEY)
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty())
}

/// The same refusal userinfo gives, so a bad token is one answer everywhere.
fn refused() -> Response {
    (
        StatusCode::UNAUTHORIZED,
        [(header::WWW_AUTHENTICATE, "Bearer error=\"invalid_token\"")],
        Json(json!({ "error": "invalid_token" })),
    )
        .into_response()
}

/// The person a request acts for, or `None` when the token does not prove it.
///
/// `Err` is a feature that is off (404), or a failure we cannot act on.
async fn account_of(state: &ModuleState, headers: &HeaderMap) -> Result<Option<String>, Problem> {
    let Some(expected_client) = grants_client(state) else {
        return Err(Problem::not_found());
    };
    let (db, clock) = ports(state)?;
    let Some(keys) = state
        .tokens
        .read()
        .expect("signing cell uncontended")
        .clone()
    else {
        return Ok(None);
    };
    let Some(token) = headers
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
    else {
        return Ok(None);
    };
    let now = clock.now().unix_timestamp();
    let Some(claims) = verify_access_token(&keys, token, now) else {
        return Ok(None);
    };
    if claims.get("aud").and_then(Value::as_str) != Some(expected_client.as_str()) {
        return Ok(None);
    }
    let Some(sid) = claims.get("sid").and_then(Value::as_str) else {
        return Ok(None);
    };
    let Some((_session, user)) = live_session_and_user(&*db, &*clock, sid).await? else {
        return Ok(None);
    };
    if claims.get("sub").and_then(Value::as_str) != Some(user.id.as_str()) {
        return Ok(None);
    }
    Ok(Some(user.id))
}

async fn list_grants(
    State(state): State<Arc<ModuleState>>,
    headers: HeaderMap,
) -> Result<Response, Problem> {
    let Some(user_id) = account_of(&state, &headers).await? else {
        return Ok(refused());
    };
    let (db, _clock) = ports(&state)?;
    let rows = store::active_grants_by_user(&*db, &user_id).await?;
    let mut grants: Vec<Value> = Vec::with_capacity(rows.len());
    for row in rows {
        // A grant whose client has been removed is not offered: there is
        // nothing to open and nothing to revoke against.
        let Some(client) = store::client_by_id(&*db, &row.client_id).await? else {
            continue;
        };
        grants.push(json!({
            "client_id": row.client_id,
            "name": client.name,
            "granted_at": row.granted_at,
        }));
    }
    Ok(Json(json!({ "grants": grants })).into_response())
}

/// The person's explicit grant to one client: the "Link" action. It is the
/// only thing that lifts a revocation. The client must exist and be active;
/// a grant to nothing is not offered.
async fn grant_client(
    State(state): State<Arc<ModuleState>>,
    headers: HeaderMap,
    Path(client_id): Path<String>,
) -> Result<Response, Problem> {
    let Some(user_id) = account_of(&state, &headers).await? else {
        return Ok(refused());
    };
    let (db, clock) = ports(&state)?;
    let Some(client) = store::client_by_id(&*db, &client_id).await? else {
        return Err(Problem::not_found());
    };
    if client.status != store::STATUS_ACTIVE {
        return Err(Problem::not_found());
    }
    store::record_grant(&*db, &user_id, &client_id, &iso(clock.now())).await?;
    tracing::info!(audit = true, action = "grant.grant", client_id = %client_id, "auth-core grant");
    Ok(Json(json!({ "ok": true })).into_response())
}

async fn revoke_grant(
    State(state): State<Arc<ModuleState>>,
    headers: HeaderMap,
    Path(client_id): Path<String>,
) -> Result<Response, Problem> {
    let Some(user_id) = account_of(&state, &headers).await? else {
        return Ok(refused());
    };
    let (db, clock) = ports(&state)?;
    let now = iso(clock.now());
    // Only the person's own live grants are addressable.
    let owns = store::active_grants_by_user(&*db, &user_id)
        .await?
        .iter()
        .any(|row| row.client_id == client_id);
    if !owns {
        return Err(Problem::not_found());
    }
    let revoked = store::revoke_grant(&*db, &user_id, &client_id, &now).await?;
    let retired = store::retire_refresh_tokens(&*db, &user_id, &client_id, &now).await?;
    tracing::info!(
        audit = true,
        action = "grant.revoke",
        client_id = %client_id,
        refresh_tokens_retired = retired,
        "auth-core grant"
    );
    Ok(Json(json!({
        "ok": true,
        "revoked": revoked,
        // Stated, not implied: a revoke stops future refreshes, not an
        // access token the client already holds.
        "access_tokens": "expire at their own lifetime",
    }))
    .into_response())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::{ClientRow, Redacted, SingleUseTokenRow, TOKEN_REFRESH, UserRow};
    use cratefield_core::{Database, Statement};
    use cratefield_testing::TestHarness;

    const NOW: &str = "2026-10-01T10:00:00Z";
    const LATER: &str = "2026-10-02T10:00:00Z";

    fn harness() -> TestHarness {
        TestHarness::new(vec![Box::new(crate::AuthCore::new())])
    }

    async fn seed(db: &dyn Database) {
        for id in ["u1", "u2"] {
            store::insert_user(
                db,
                &UserRow {
                    id: id.to_owned(),
                    display_name: None,
                    primary_email: Some(format!("{id}@example.com")),
                    primary_email_verified: true,
                    locale: None,
                    status: "active".to_owned(),
                    created_at: NOW.to_owned(),
                    updated_at: NOW.to_owned(),
                },
            )
            .await
            .expect("user");
        }
        for (id, name) in [("ledgers", "Ledgers"), ("other", "Other venture")] {
            store::insert_client(
                db,
                &ClientRow {
                    id: id.to_owned(),
                    name: name.to_owned(),
                    secret_hash: Redacted("unused".to_owned()),
                    previous_secret_hash: None,
                    previous_hash_expires_at: None,
                    kind: "confidential".to_owned(),
                    status: "active".to_owned(),
                    created_at: NOW.to_owned(),
                },
            )
            .await
            .expect("client");
        }
    }

    async fn refresh_token(db: &dyn Database, id: &str, user: &str, client: &str) {
        store::insert_single_use_token(
            db,
            &SingleUseTokenRow {
                id: id.to_owned(),
                kind: TOKEN_REFRESH.to_owned(),
                token_hash: Redacted(id.as_bytes().to_vec()),
                user_id: Some(user.to_owned()),
                client_id: Some(client.to_owned()),
                payload: None,
                expires_at: "2099-01-01T00:00:00Z".to_owned(),
                consumed_at: None,
            },
        )
        .await
        .expect("token");
    }

    async fn live_token_ids(db: &dyn Database) -> Vec<String> {
        let rows = db
            .query(&Statement::new(
                "SELECT id FROM single_use_tokens WHERE consumed_at IS NULL ORDER BY id",
            ))
            .await
            .expect("query");
        rows.rows
            .iter()
            .map(|row| row.get::<String>("id").unwrap_or_default())
            .collect()
    }

    fn client_ids(rows: &[store::GrantRow]) -> Vec<String> {
        rows.iter().map(|row| row.client_id.clone()).collect()
    }

    #[test]
    fn a_revoked_grant_leaves_the_list_and_a_new_authorization_restores_it() {
        pollster::block_on(async {
            let kit = harness();
            seed(&*kit.db).await;
            let db = &*kit.db;
            store::record_grant(db, "u1", "ledgers", NOW).await.unwrap();
            store::record_grant(db, "u1", "other", NOW).await.unwrap();
            assert_eq!(
                client_ids(&store::active_grants_by_user(db, "u1").await.unwrap()),
                ["ledgers", "other"]
            );

            assert_eq!(
                store::revoke_grant(db, "u1", "ledgers", LATER)
                    .await
                    .unwrap(),
                1
            );
            assert_eq!(
                client_ids(&store::active_grants_by_user(db, "u1").await.unwrap()),
                ["other"]
            );
            // A second revoke finds nothing live to revoke.
            assert_eq!(
                store::revoke_grant(db, "u1", "ledgers", LATER)
                    .await
                    .unwrap(),
                0
            );

            // Signing in to the client again is a fresh authorization: it is
            // live again, and its grant time is the new one, so it now sorts
            // after the grant that was never revoked.
            store::record_grant(db, "u1", "ledgers", LATER)
                .await
                .unwrap();
            assert_eq!(
                client_ids(&store::active_grants_by_user(db, "u1").await.unwrap()),
                ["other", "ledgers"]
            );
        });
    }

    #[test]
    fn a_revoke_touches_only_that_persons_grant() {
        pollster::block_on(async {
            let kit = harness();
            seed(&*kit.db).await;
            let db = &*kit.db;
            store::record_grant(db, "u1", "ledgers", NOW).await.unwrap();
            store::record_grant(db, "u2", "ledgers", NOW).await.unwrap();
            store::revoke_grant(db, "u1", "ledgers", LATER)
                .await
                .unwrap();
            assert!(
                store::active_grants_by_user(db, "u1")
                    .await
                    .unwrap()
                    .is_empty()
            );
            assert_eq!(
                client_ids(&store::active_grants_by_user(db, "u2").await.unwrap()),
                ["ledgers"],
                "another person's grant to the same client survives"
            );
        });
    }

    #[test]
    fn revoking_retires_only_that_pairs_refresh_tokens() {
        pollster::block_on(async {
            let kit = harness();
            seed(&*kit.db).await;
            let db = &*kit.db;
            refresh_token(db, "t-u1-ledgers", "u1", "ledgers").await;
            refresh_token(db, "t-u1-other", "u1", "other").await;
            refresh_token(db, "t-u2-ledgers", "u2", "ledgers").await;

            let retired = store::retire_refresh_tokens(db, "u1", "ledgers", LATER)
                .await
                .unwrap();
            assert_eq!(retired, 1);
            assert_eq!(
                live_token_ids(db).await,
                ["t-u1-other", "t-u2-ledgers"],
                "only u1's token for the revoked client is spent"
            );
        });
    }
}
