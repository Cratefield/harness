//! Login: options and verify (issue #14).
//!
//! Two paths through one pair of endpoints. With an email, the browser is
//! handed the account's credential ids. Without one, the list is empty and
//! the authenticator offers whatever discoverable credential it holds, which
//! is what makes passwordless autofill work.
//!
//! Every refusal answers identically. An attacker who can tell "no such
//! credential" from "bad signature" learns which half of the ceremony to
//! work on, and one that can tell "no such account" from "wrong passkey"
//! gets an account oracle for free.

use axum::extract::State;
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use factory0_auth_core::{
    CREDENTIAL_PASSKEY, Login, credentials_by_user, issue as issue_session, mark_passkey_suspect,
    passkey_by_credential_id, set_cookie, touch_credential_used, update_passkey_sign_count,
    user_by_primary_email,
};
use factory0_core::{Json, Problem, Scope};
use http::HeaderMap;
use http::header;
use serde::Deserialize;
use serde_json::json;
use std::sync::Arc;
use webauthn_rs_proto::{
    AllowCredentials, PublicKeyCredential, PublicKeyCredentialRequestOptions,
    RequestChallengeResponse, UserVerificationPolicy,
};

use crate::ModuleState;
use crate::challenge::{self, PURPOSE_LOGIN};
use crate::request::{ceremony_failed, client_hints, internal, ok, ports};
use crate::webauthn::{StoredPasskey, UserVerification, WebauthnError, verify_assertion};

pub(crate) const EVENT_LOGGED_IN: &str = "auth-passkeys.logged_in";

/// RFC 8176 authentication-method references recorded on the session and
/// copied into every access token minted against it. `user` is user
/// presence, which WebAuthn always requires; `mfa` is added when the
/// authenticator verified the user, because a passkey with user
/// verification is possession plus knowledge or inherence.
const AMR_PASSKEY: &str = "passkey";
const AMR_USER_PRESENT: &str = "user";
const AMR_MULTI_FACTOR: &str = "mfa";

pub(crate) fn router() -> axum::Router<Arc<ModuleState>> {
    axum::Router::new()
        .route("/login/options", post(options))
        .route("/login/verify", post(verify))
}

#[derive(Debug, Default, Deserialize)]
pub(crate) struct OptionsBody {
    /// Optional. Absent means discoverable credentials, which is what
    /// conditional UI (autofill) pre-fetches.
    #[serde(default)]
    email: Option<String>,
}

async fn options(
    State(state): State<Arc<ModuleState>>,
    scope: Scope,
    body: axum::body::Bytes,
) -> Result<Response, Problem> {
    let rp = state.rp()?;
    let (db, clock, id_gen) = ports(&state)?;
    // Taken as raw bytes rather than through the JSON extractor because an
    // empty body is valid here: conditional UI pre-fetches options before
    // the person has typed anything, and some browsers send nothing at all.
    let parsed: OptionsBody = if body.is_empty() {
        OptionsBody::default()
    } else {
        serde_json::from_slice(&body)
            .map_err(|err| Problem::validation_failed(format!("body is not valid JSON: {err}")))?
    };
    let email = parsed
        .email
        .map(|email| factory0_core::normalize_email(&email))
        .filter(|email| !email.is_empty());

    let mut allow = Vec::new();
    let mut user_id = None;
    if let Some(email) = email.as_deref() {
        // An unknown address gets an empty list and a real challenge, the
        // same as an account with no passkeys. Nothing here says whether
        // the account exists.
        if let Some(user) = user_by_primary_email(db, email).await.map_err(|err| {
            tracing::error!(error = %err, "could not look up the account");
            internal(&scope)
        })? {
            let credentials = credentials_by_user(db, &user.id).await.map_err(|err| {
                tracing::error!(error = %err, "could not read credentials");
                internal(&scope)
            })?;
            allow = credentials
                .iter()
                .filter(|row| row.kind == CREDENTIAL_PASSKEY && row.passkey_suspect_at.is_none())
                .filter_map(|row| row.passkey_credential_id.as_ref())
                .map(|id| AllowCredentials {
                    type_: "public-key".to_owned(),
                    id: challenge::credential_id_bytes(id).to_vec().into(),
                    transports: None,
                })
                .collect();
            if !allow.is_empty() {
                user_id = Some(user.id);
            }
        }
    }

    let issued = challenge::issue(
        db,
        clock,
        id_gen,
        PURPOSE_LOGIN,
        user_id.as_deref(),
        rp.challenge_ttl_secs,
    )
    .await
    .map_err(|err| {
        tracing::error!(error = %err, "could not issue a login challenge");
        internal(&scope)
    })?;

    let response = RequestChallengeResponse {
        public_key: PublicKeyCredentialRequestOptions {
            challenge: issued.into(),
            timeout: Some(rp.timeout_ms),
            rp_id: rp.rp_id.clone(),
            allow_credentials: allow,
            user_verification: match rp.user_verification {
                UserVerification::Required => UserVerificationPolicy::Required,
                UserVerification::Preferred => UserVerificationPolicy::Preferred,
            },
            hints: None,
            extensions: None,
        },
        mediation: None,
    };
    Ok(ok(serde_json::to_value(response).unwrap_or_default()))
}

#[derive(Debug, Deserialize)]
pub(crate) struct VerifyBody {
    credential: PublicKeyCredential,
}

/// The stored credential this assertion claims to be, with the three
/// refusals that come before any cryptography: unknown id, a credential
/// already flagged as a possible clone, and a challenge that was issued for
/// a different account.
async fn lookup(
    db: &dyn factory0_core::Database,
    scope: &Scope,
    consumed: &crate::challenge::Consumed,
    credential: &PublicKeyCredential,
) -> Result<factory0_auth_core::CredentialRow, Problem> {
    let credential_id = credential.get_credential_id().to_vec();
    let stored = passkey_by_credential_id(db, &credential_id)
        .await
        .map_err(|err| {
            tracing::error!(error = %err, "could not look up the credential");
            internal(scope)
        })?
        .ok_or_else(|| {
            tracing::warn!("a login presented an unknown credential id");
            ceremony_failed(scope)
        })?;

    // A credential flagged after a counter regression stays refused until a
    // person removes it: the authenticator may be a clone.
    if stored.passkey_suspect_at.is_some() {
        tracing::warn!(credential = %stored.id, "a suspect passkey was presented");
        return Err(ceremony_failed(scope));
    }

    // When the options call named an account, the assertion has to be for
    // that account. Without this, a challenge issued for one user could be
    // spent with another user's passkey.
    if let Some(expected) = consumed.user_id.as_deref()
        && expected != stored.user_id
    {
        tracing::warn!("a login challenge was spent by a different account");
        return Err(ceremony_failed(scope));
    }
    Ok(stored)
}

/// Issues the session a successful assertion earns, with the
/// authentication-method references that say how it was earned.
async fn start_session(
    db: &dyn factory0_core::Database,
    clock: &dyn factory0_core::Clock,
    id_gen: &dyn factory0_core::IdGen,
    headers: &HeaderMap,
    user_id: &str,
    user_verified: bool,
) -> Result<factory0_auth_core::IssuedSession, factory0_auth_core::SessionError> {
    let mut amr = vec![AMR_PASSKEY, AMR_USER_PRESENT];
    if user_verified {
        // A passkey the authenticator verified is possession plus knowledge
        // or inherence, which is what `mfa` claims.
        amr.push(AMR_MULTI_FACTOR);
    }
    let (ip, user_agent) = client_hints(headers);
    issue_session(
        db,
        clock,
        id_gen,
        Login {
            user_id,
            ip: ip.as_deref(),
            user_agent: user_agent.as_deref(),
            // Any cookie the login request carried is revoked before the new
            // session exists, which is auth-core's fixation defence.
            presented_cookie: factory0_auth_core::cookie_value(headers).as_deref(),
            amr: &amr,
        },
    )
    .await
}

/// Checks the assertion against the stored key, and turns the one failure
/// that means something beyond "no" into a lasting mark: a counter that went
/// backwards is the only clone signal WebAuthn gives a relying party.
async fn check_assertion(
    db: &dyn factory0_core::Database,
    clock: &dyn factory0_core::Clock,
    scope: &Scope,
    rp: &crate::RelyingParty,
    challenge_bytes: &[u8],
    stored: &factory0_auth_core::CredentialRow,
    credential: &PublicKeyCredential,
) -> Result<crate::webauthn::VerifiedAssertion, Problem> {
    let (Some(cose_key), Some(stored_credential_id)) = (
        stored.passkey_public_key_cose.as_ref(),
        stored.passkey_credential_id.as_ref(),
    ) else {
        tracing::error!(credential = %stored.id, "a passkey row is missing its key material");
        return Err(ceremony_failed(scope));
    };
    let sign_count = u32::try_from(stored.passkey_sign_count.unwrap_or_default()).unwrap_or(0);

    match verify_assertion(
        &rp.rp_id,
        &rp.origins,
        challenge_bytes,
        rp.user_verification,
        &StoredPasskey {
            credential_id: challenge::credential_id_bytes(stored_credential_id),
            cose_key: &cose_key.0,
            sign_count,
        },
        credential,
    ) {
        Ok(verified) => Ok(verified),
        Err(WebauthnError::CounterRegression {
            stored: was,
            presented: now,
        }) => {
            tracing::warn!(
                credential = %stored.id,
                stored = was,
                presented = now,
                "signature counter went backwards; marking the passkey suspect"
            );
            let at = crate::iso(clock.now());
            if let Err(err) = mark_passkey_suspect(db, &stored.id, &at).await {
                tracing::error!(error = %err, "could not mark the passkey suspect");
            }
            Err(ceremony_failed(scope))
        }
        Err(err) => {
            tracing::warn!(error = %err, "passkey assertion refused");
            Err(ceremony_failed(scope))
        }
    }
}

async fn verify(
    State(state): State<Arc<ModuleState>>,
    scope: Scope,
    headers: HeaderMap,
    Json(body): Json<VerifyBody>,
) -> Result<Response, Problem> {
    let rp = state.rp()?;
    let (db, clock, id_gen) = ports(&state)?;

    let presented = body.credential.response.client_data_json.as_slice();
    let challenge_bytes =
        challenge_from_client_data(presented).ok_or_else(|| ceremony_failed(&scope))?;

    let consumed = challenge::consume(db, clock, PURPOSE_LOGIN, &challenge_bytes)
        .await
        .map_err(|err| {
            tracing::error!(error = %err, "could not consume the login challenge");
            internal(&scope)
        })?
        .ok_or_else(|| ceremony_failed(&scope))?;

    let stored = lookup(db, &scope, &consumed, &body.credential).await?;

    let verified = check_assertion(
        db,
        clock,
        &scope,
        rp,
        &challenge_bytes,
        &stored,
        &body.credential,
    )
    .await?;

    // A discoverable credential names its account through the user handle;
    // when one is present it has to agree with the credential we matched.
    if let Some(handle) = verified.user_handle.as_deref()
        && handle != stored.user_id.as_bytes()
    {
        tracing::warn!("the user handle does not match the credential's account");
        return Err(ceremony_failed(&scope));
    }

    let now = crate::iso(clock.now());
    if let Err(err) =
        update_passkey_sign_count(db, &stored.id, i64::from(verified.sign_count), &now).await
    {
        tracing::error!(error = %err, "could not store the signature counter");
        return Err(internal(&scope));
    }
    if let Err(err) = touch_credential_used(db, &stored.id, &now).await {
        tracing::warn!(error = %err, "could not record the credential's last use");
    }

    let session = start_session(
        db,
        clock,
        id_gen,
        &headers,
        &stored.user_id,
        verified.user_verified,
    )
    .await
    .map_err(|err| {
        tracing::error!(error = %err, "could not issue a session");
        internal(&scope)
    })?;

    state.ctx.events.emit_in(
        &scope,
        EVENT_LOGGED_IN,
        json!({
            "user_id": stored.user_id,
            "credential_id": stored.id,
            "user_verified": verified.user_verified,
        }),
    );

    Ok((
        [(header::SET_COOKIE, set_cookie(&session.value))],
        Json(json!({
            "user_id": stored.user_id,
            "session_id": session.session_id,
            "user_verified": verified.user_verified,
        })),
    )
        .into_response())
}

fn challenge_from_client_data(raw: &[u8]) -> Option<Vec<u8>> {
    let parsed: webauthn_rs_proto::CollectedClientData = serde_json::from_slice(raw).ok()?;
    Some(parsed.challenge.as_slice().to_vec())
}
