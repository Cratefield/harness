//! `POST /token` (issue #10): the two grants of the authorization
//! code flow — `authorization_code` with mandatory S256 PKCE, and
//! `refresh_token` per issue #9.
//!
//! **No implicit flow, no password grant, no `plain` PKCE**: any other
//! `grant_type` is refused. Client authentication is confidential-only
//! (secret verified through the argon2 path, constant-time at the
//! digest compare); public clients rely on PKCE alone.
//!
//! The one refusal rule: **unknown client id, wrong secret, and every
//! invalid grant answer with the same stable problem** —
//! `auth/token-request-refused` — so a probe cannot distinguish a
//! nonexistent client from a mistyped secret. `auth/client-disabled`
//! is answered only after a confidential client has authenticated
//! (its owner may learn their own app is disabled; a stranger cannot).
//!
//! Single-use semantics come from the guarded consume in
//! [`store::consume_single_use_token`]; reuse of a consumed
//! authorization code or refresh token **revokes the session** it was
//! bound to before the request is refused.

use axum::extract::{Form, State};
use axum::extract::rejection::FormRejection;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use base64ct::{Base64UrlUnpadded, Encoding};
use factory0_core::{Clock, Database, Json, Problem, Scope, constant_time_eq, subject_hash};
use serde::Deserialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::sync::Arc;
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

use crate::ModuleState;
use crate::secrets;
use crate::store::{self, TOKEN_AUTHORIZATION_CODE, UserRow};
use crate::tokens::{self, SigningKeys, TOKENS_UNCONFIGURED, mint_access_token, mint_refresh_token};

/// The one answer every refused token request sees. The description
/// says what it does not distinguish, on purpose.
pub const TOKEN_REFUSED: factory0_core::ProblemDef = factory0_core::ProblemDef {
    slug: "auth/token-request-refused",
    status: StatusCode::BAD_REQUEST,
    title: "Token request refused",
    description: "Unknown client, wrong secret, or an invalid grant — deliberately not distinguished",
};

/// What both grants share: the request scope, the ports, the resolved
/// signing keys and the authenticated client.
struct GrantContext<'a> {
    scope: &'a Scope,
    db: &'a dyn Database,
    clock: &'a dyn Clock,
    id_gen: &'a dyn factory0_core::IdGen,
    keys: &'a SigningKeys,
    client_id: &'a str,
}

#[derive(Deserialize)]
struct TokenForm {
    grant_type: String,
    client_id: String,
    client_secret: Option<String>,
    code: Option<String>,
    redirect_uri: Option<String>,
    code_verifier: Option<String>,
    refresh_token: Option<String>,
}

fn iso(t: OffsetDateTime) -> String {
    t.replace_nanosecond(0)
        .expect("truncation stays in range")
        .format(&Rfc3339)
        .expect("rfc3339 formats")
}

fn refused(scope: &Scope) -> Problem {
    Problem::new(&TOKEN_REFUSED).instance(&scope.request_id)
}

fn sha256(bytes: &[u8]) -> Vec<u8> {
    Sha256::digest(bytes).to_vec()
}

/// PKCE S256 (RFC 7636 section 4.2): the verifier is 43..=128
/// unreserved characters; the challenge is the base64url of its
/// SHA-256. The comparison is constant-time via the harness helper.
fn pkce_s256_matches(verifier: &str, challenge: &str) -> bool {
    let verifier_ok = (43..=128).contains(&verifier.len())
        && verifier
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~'));
    if !verifier_ok {
        return false;
    }
    let computed = Base64UrlUnpadded::encode_string(&Sha256::digest(verifier.as_bytes()));
    constant_time_eq(computed.as_bytes(), challenge.as_bytes())
}

/// The session a grant is bound to, still live, with its user.
async fn live_session_and_user(
    db: &dyn Database,
    clock: &dyn Clock,
    session_id: &str,
) -> Result<Option<(store::SessionRow, UserRow)>, Problem> {
    let now = iso(clock.now().replace_nanosecond(0).expect("in range"));
    let Some(session) = store::session_by_id(db, session_id).await? else {
        return Ok(None);
    };
    if session.revoked_at.is_some() || session.expires_at <= now {
        return Ok(None);
    };
    let Some(user) = store::user_by_id(db, &session.user_id).await? else {
        return Ok(None);
    };
    if user.status != store::STATUS_ACTIVE {
        return Ok(None);
    }
    Ok(Some((session, user)))
}

fn amr_of(session: &store::SessionRow) -> Vec<String> {
    session
        .amr
        .as_deref()
        .and_then(|raw| serde_json::from_str::<Vec<String>>(raw).ok())
        .unwrap_or_default()
}

async fn mint_pair(
    db: &dyn Database,
    clock: &dyn Clock,
    id_gen: &dyn factory0_core::IdGen,
    keys: &SigningKeys,
    session: &store::SessionRow,
    user: &UserRow,
    client_id: &str,
) -> Result<Response, Problem> {
    let email = user
        .primary_email
        .as_deref()
        .map(|email| (email, user.primary_email_verified));
    let amr = amr_of(session);
    let access = mint_access_token(
        keys,
        clock,
        &session.id,
        &user.id,
        email,
        client_id,
        &amr,
    )
    .map_err(|err| {
        tracing::error!(error = %err, "access-token mint failed");
        Problem::internal()
    })?;
    let refresh = mint_refresh_token(db, clock, id_gen, &session.id, &user.id, client_id).await?;
    Ok(Json(json!({
        "access_token": access,
        "token_type": "Bearer",
        "expires_in": tokens::ACCESS_TOKEN_SECS,
        "refresh_token": refresh,
    }))
    .into_response())
}

async fn token(
    scope: Scope,
    State(state): State<Arc<ModuleState>>,
    form: Result<Form<TokenForm>, FormRejection>,
) -> Result<Response, Problem> {
    let (Some(db), Some(clock), Some(id_gen)) = (
        state.ctx.ports.db.clone(),
        state.ctx.ports.clock.clone(),
        state.ctx.ports.id_gen.clone(),
    ) else {
        return Err(Problem::internal());
    };
    // A malformed body is just another refused request.
    let Form(form) = form.map_err(|_| refused(&scope))?;

    // Signing keys are a service precondition, not a per-request
    // outcome: refused with the stable unconfigured problem before
    // anything is consumed.
    let Some(keys) = state.tokens.clone() else {
        return Err(Problem::new(&TOKENS_UNCONFIGURED).instance(&scope.request_id));
    };

    // Client authentication. Unknown client and wrong secret are the
    // same refusal; a disabled client is only ever told so after
    // authenticating.
    let Some(client) = store::client_by_id(&*db, &form.client_id).await? else {
        return Err(refused(&scope));
    };
    if secrets::kind_allows_secret(&client.kind) {
        let presented = form.client_secret.as_deref().unwrap_or_default();
        let now = iso(clock.now().replace_nanosecond(0).expect("in range"));
        if !secrets::verify_client_secret(&client, presented, &now) {
            return Err(refused(&scope));
        }
    }
    secrets::ensure_client_usable(&client).map_err(|problem| problem.instance(&scope.request_id))?;

    let grant = GrantContext {
        scope: &scope,
        db: &*db,
        clock: &*clock,
        id_gen: &*id_gen,
        keys: &keys,
        client_id: &client.id,
    };
    match form.grant_type.as_str() {
        "authorization_code" => code_grant(&grant, &form).await,
        "refresh_token" => refresh_grant(&grant, &form).await,
        // No implicit flow, no password grant — one answer for every
        // other grant type.
        _ => Err(refused(&scope)),
    }
}

async fn code_grant(grant: &GrantContext<'_>, form: &TokenForm) -> Result<Response, Problem> {
    let scope = grant.scope;
    let db = grant.db;
    let clock = grant.clock;
    let client_id = grant.client_id;
    let Some(code) = form.code.as_deref() else {
        return Err(refused(scope));
    };
    let Some(redirect_uri) = form.redirect_uri.as_deref() else {
        return Err(refused(scope));
    };
    let Some(verifier) = form.code_verifier.as_deref() else {
        return Err(refused(scope));
    };

    let Some(row) = store::single_use_token_by_hash(db, &sha256(code.as_bytes())).await? else {
        return Err(refused(scope));
    };
    if row.kind != TOKEN_AUTHORIZATION_CODE || row.client_id.as_deref() != Some(client_id) {
        return Err(refused(scope));
    }
    let Some(payload) = row.payload.as_deref().and_then(|raw| {
        serde_json::from_str::<Value>(raw).ok()
    }) else {
        return Err(refused(scope));
    };
    let (Some(bound_redirect), Some(challenge), Some(session_id)) = (
        payload.get("redirect_uri").and_then(Value::as_str),
        payload.get("code_challenge").and_then(Value::as_str),
        payload.get("sid").and_then(Value::as_str),
    ) else {
        return Err(refused(scope));
    };

    let now = iso(clock.now().replace_nanosecond(0).expect("in range"));
    if row.consumed_at.is_some() {
        // Code reuse: revoke the session the code was minted for,
        // then refuse — the same alarm as refresh-token reuse.
        store::revoke_session(db, session_id, &now).await?;
        tracing::warn!(
            audit = true,
            action = "token.code-reuse",
            client_id,
            "authorization-code reuse detected; session revoked"
        );
        return Err(refused(scope));
    }

    if redirect_uri != bound_redirect || !pkce_s256_matches(verifier, challenge) {
        return Err(refused(scope));
    }
    let Some((session, user)) = live_session_and_user(db, clock, session_id).await? else {
        return Err(refused(scope));
    };
    // The guarded consume decides the winner of any race; losing it
    // is just another refusal.
    store::consume_single_use_token(db, &row.id, &now)
        .await?
        .ok_or_else(|| refused(scope))?;

    tracing::info!(
        audit = true,
        action = "token.code",
        client_id,
        subject_hash = %subject_hash(&user.id),
        "authorization code exchanged"
    );
    mint_pair(
        db,
        clock,
        grant.id_gen,
        grant.keys,
        &session,
        &user,
        client_id,
    )
    .await
}

async fn refresh_grant(grant: &GrantContext<'_>, form: &TokenForm) -> Result<Response, Problem> {
    let scope = grant.scope;
    let db = grant.db;
    let clock = grant.clock;
    let client_id = grant.client_id;
    let Some(presented) = form.refresh_token.as_deref() else {
        return Err(refused(scope));
    };
    let (tokens::RefreshOutcome::Granted, Some(granted)) =
        tokens::exchange_refresh_token(db, clock, presented, client_id).await?
    else {
        return Err(refused(scope));
    };
    let Some((session, user)) = live_session_and_user(db, clock, &granted.session_id).await?
    else {
        return Err(refused(scope));
    };

    tracing::info!(
        audit = true,
        action = "token.refresh",
        client_id,
        subject_hash = %subject_hash(&user.id),
        "refresh token exchanged"
    );
    mint_pair(
        db,
        clock,
        grant.id_gen,
        grant.keys,
        &session,
        &user,
        client_id,
    )
    .await
}

pub(crate) fn router() -> axum::Router<Arc<ModuleState>> {
    axum::Router::new().route("/token", post(token))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn s256_is_the_only_pkce_path_and_it_is_constant_shape() {
        let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        let challenge = Base64UrlUnpadded::encode_string(&Sha256::digest(verifier.as_bytes()));
        assert!(pkce_s256_matches(verifier, &challenge));
        assert!(!pkce_s256_matches("a-different-verifier-for-sure-1234567890abc", &challenge));

        // Verifier bounds: 43 minimum, 128 maximum, unreserved only.
        assert!(!pkce_s256_matches(&"x".repeat(42), &challenge));
        assert!(pkce_s256_matches(&"x".repeat(43), &Base64UrlUnpadded::encode_string(&Sha256::digest("x".repeat(43).as_bytes()))));
        assert!(pkce_s256_matches(&"y".repeat(128), &Base64UrlUnpadded::encode_string(&Sha256::digest("y".repeat(128).as_bytes()))));
        assert!(!pkce_s256_matches(&"y".repeat(129), &challenge));
        assert!(!pkce_s256_matches("contains space and & symbols pad-to-43-chars!!", &challenge));
        assert!(!pkce_s256_matches("plus+slash/equals=not-unreserved-padding-43", &challenge));
    }
}
