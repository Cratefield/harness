//! Passkey-first sign-up without an email address (issue #914).
//!
//! An anonymous caller makes a passkey and thereby an account: a discoverable
//! credential, user verification required, and an account id as the user
//! handle. No email is asked for. The caller accepts the deployment's current
//! terms and privacy versions in the same step, which are recorded with the
//! account. The answer carries one-time recovery codes, shown once, and a
//! session.
//!
//! Both steps pass the same guards as the rest of anonymous auth: the rate
//! limiter (required, and failing closed) and the captcha, when one is
//! configured.

use axum::extract::State;
use axum::http::HeaderMap;
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use cratefield_auth_core::{Login, UserRow, issue as issue_session, passkey_by_credential_id};
use cratefield_core::{Problem, ProblemDef, Scope};
use serde::Deserialize;
use serde_json::json;
use std::sync::Arc;
use webauthn_rs_proto::{
    AttestationConveyancePreference, AuthenticatorSelectionCriteria, CreationChallengeResponse,
    PubKeyCredParams, PublicKeyCredentialCreationOptions, RegisterPublicKeyCredential,
    RelyingParty as ProtoRelyingParty, ResidentKeyRequirement, User, UserVerificationPolicy,
};

use crate::challenge::{self, PURPOSE_SIGNUP};
use crate::register::{challenge_from_client_data, transports_of};
use crate::request::{ceremony_failed, internal, ok, ports};
use crate::webauthn::{UserVerification, verify_registration};
use crate::{COSE_EDDSA, COSE_ES256, COSE_RS256, ModuleState};

/// A sign-up the guards refused, or the terms did not match. One answer, so
/// the response says nothing about which check failed.
pub(crate) const SIGNUP_REFUSED: ProblemDef = ProblemDef {
    slug: "auth/signup-refused",
    status: axum::http::StatusCode::FORBIDDEN,
    title: "Sign-up refused",
    description: "The sign-up could not be completed",
};

/// The display name a passkey account may carry: optional, trimmed, capped.
const MAX_DISPLAY_NAME_CHARS: usize = 64;

#[derive(Debug, Deserialize)]
struct OptionsBody {
    #[serde(default, rename = "captchaToken")]
    captcha_token: Option<String>,
    #[serde(default)]
    display_name: Option<String>,
}

#[derive(Debug, Deserialize)]
struct Acceptance {
    #[serde(default)]
    accepted: bool,
    terms_version: Option<String>,
    privacy_version: Option<String>,
}

#[derive(Debug, Deserialize)]
struct VerifyBody {
    credential: RegisterPublicKeyCredential,
    #[serde(default)]
    label: Option<String>,
    #[serde(default)]
    display_name: Option<String>,
    #[serde(default, rename = "captchaToken")]
    captcha_token: Option<String>,
    terms: Acceptance,
}

fn display_name_of(raw: Option<&str>) -> Option<String> {
    raw.map(str::trim)
        .filter(|name| !name.is_empty())
        .map(|name| name.chars().take(MAX_DISPLAY_NAME_CHARS).collect())
}

/// The answer to an anonymous step the limiter or captcha refused, or could not
/// judge, or `None` when the step may proceed.
async fn guarded(
    scope: &Scope,
    state: &ModuleState,
    headers: &HeaderMap,
    captcha_token: Option<&str>,
) -> Option<Response> {
    match cratefield_auth_core::guard_anonymous(&state.ctx, headers, "signup").await {
        cratefield_auth_core::Guard::Allow => {}
        cratefield_auth_core::Guard::Limited(decision) => {
            return Some(cratefield_core::rate_limited(&decision).into_response());
        }
        cratefield_auth_core::Guard::Failed => {
            return Some(
                Problem::new(&SIGNUP_REFUSED)
                    .instance(&scope.request_id)
                    .into_response(),
            );
        }
    }
    if !cratefield_auth_core::captcha_passes(&state.ctx, captcha_token, headers).await {
        return Some(
            Problem::new(&SIGNUP_REFUSED)
                .instance(&scope.request_id)
                .into_response(),
        );
    }
    None
}

/// Step one: a challenge the new authenticator will sign, for a new account
/// id that the challenge row carries until step two. The answer names the
/// terms the account is asked to accept.
async fn options(
    scope: Scope,
    State(state): State<Arc<ModuleState>>,
    headers: HeaderMap,
    body: Option<axum::Json<OptionsBody>>,
) -> Result<Response, Problem> {
    let body = body.map(|axum::Json(body)| body);
    let captcha = body.as_ref().and_then(|b| b.captcha_token.clone());
    if let Some(response) = guarded(&scope, &state, &headers, captcha.as_deref()).await {
        return Ok(response);
    }
    let rp = state.rp()?;
    let (db, clock, id_gen) = ports(&state)?;
    let Some((terms_version, privacy_version)) =
        cratefield_auth_core::terms_versions(&*state.ctx.config)
    else {
        return Err(Problem::not_ready(
            "sign-up is not configured: no terms version is set",
        ));
    };
    let user_id = id_gen.ulid();
    let display = display_name_of(body.as_ref().and_then(|b| b.display_name.as_deref()));
    let issued = challenge::issue(
        db,
        clock,
        id_gen,
        PURPOSE_SIGNUP,
        Some(&user_id),
        rp.challenge_ttl_secs,
    )
    .await
    .map_err(|err| {
        tracing::error!(error = %err, "could not issue a sign-up challenge");
        internal(&scope)
    })?;
    let response = CreationChallengeResponse {
        public_key: PublicKeyCredentialCreationOptions {
            rp: ProtoRelyingParty {
                name: rp.rp_name.clone(),
                id: rp.rp_id.clone(),
            },
            user: User {
                // The account id is the user handle: a discoverable credential
                // names the account without any address.
                id: user_id.as_bytes().to_vec().into(),
                name: user_id.clone(),
                display_name: display
                    .clone()
                    .unwrap_or_else(|| "Passkey account".to_owned()),
            },
            challenge: issued.clone().into(),
            pub_key_cred_params: [COSE_ES256, COSE_RS256, COSE_EDDSA]
                .into_iter()
                .map(|alg| PubKeyCredParams {
                    type_: "public-key".to_owned(),
                    alg,
                })
                .collect(),
            timeout: Some(rp.timeout_ms),
            exclude_credentials: None,
            // Sign-up is passkey-first: the credential must be discoverable and
            // the person must verify themselves (issue #914).
            authenticator_selection: Some(AuthenticatorSelectionCriteria {
                authenticator_attachment: None,
                resident_key: Some(ResidentKeyRequirement::Required),
                require_resident_key: true,
                user_verification: UserVerificationPolicy::Required,
            }),
            hints: None,
            attestation: Some(AttestationConveyancePreference::None),
            attestation_formats: None,
            extensions: None,
        },
    };
    let mut body = serde_json::to_value(response).unwrap_or_default();
    if let Some(public_key) = body.get_mut("publicKey") {
        public_key["extensions"] = json!({ "prf": {} });
    }
    body["terms"] = json!({ "terms_version": terms_version, "privacy_version": privacy_version });
    Ok(ok(body))
}

/// Step two: check the ceremony, create the account, record the terms, and
/// answer with the session and the recovery codes (shown once).
#[allow(clippy::too_many_lines)]
async fn verify(
    scope: Scope,
    State(state): State<Arc<ModuleState>>,
    headers: HeaderMap,
    raw: axum::body::Bytes,
) -> Result<Response, Problem> {
    let body: VerifyBody = serde_json::from_slice(&raw).map_err(|err| {
        Problem::validation_failed(format!("body is not a sign-up: {err}"))
            .instance(&scope.request_id)
    })?;
    if let Some(response) = guarded(&scope, &state, &headers, body.captcha_token.as_deref()).await {
        return Ok(response);
    }
    let rp = state.rp()?;
    let (db, clock, id_gen) = ports(&state)?;
    let Some((terms_version, privacy_version)) =
        cratefield_auth_core::terms_versions(&*state.ctx.config)
    else {
        return Err(Problem::not_ready(
            "sign-up is not configured: no terms version is set",
        ));
    };
    // The terms are accepted now, at the versions this deployment shows.
    if !body.terms.accepted
        || body.terms.terms_version.as_deref() != Some(terms_version.as_str())
        || body.terms.privacy_version.as_deref() != Some(privacy_version.as_str())
    {
        return Err(Problem::validation_failed(
            "the current terms and privacy versions must be accepted",
        )
        .instance(&scope.request_id));
    }
    let presented = body.credential.response.client_data_json.as_slice();
    let challenge = challenge_from_client_data(presented).ok_or_else(|| ceremony_failed(&scope))?;
    let consumed = challenge::consume(db, clock, PURPOSE_SIGNUP, &challenge)
        .await
        .map_err(|err| {
            tracing::error!(error = %err, "could not consume the sign-up challenge");
            internal(&scope)
        })?
        .ok_or_else(|| ceremony_failed(&scope))?;
    let user_id = consumed.user_id.ok_or_else(|| ceremony_failed(&scope))?;

    // A passkey account is only ever made with a user-verified ceremony.
    let registered = verify_registration(
        &rp.rp_id,
        &rp.origins,
        &challenge,
        UserVerification::Required,
        &body.credential,
    )
    .map_err(|err| {
        tracing::warn!(error = %err, "sign-up refused");
        ceremony_failed(&scope)
    })?;
    if passkey_by_credential_id(db, &registered.credential_id)
        .await
        .map_err(|_| internal(&scope))?
        .is_some()
    {
        return Err(ceremony_failed(&scope));
    }

    let now = crate::iso(clock.now());
    let user = UserRow {
        id: user_id.clone(),
        display_name: display_name_of(body.display_name.as_deref()),
        primary_email: None,
        primary_email_verified: false,
        locale: None,
        status: cratefield_auth_core::STATUS_ACTIVE.to_owned(),
        created_at: now.clone(),
        updated_at: now.clone(),
    };
    // The first passkey of a new account: no change to a quiet period, because
    // there is nothing yet to be quiet about (issue #914).
    let credential = credential_row(
        &user_id,
        id_gen.ulid(),
        &registered,
        transports_of(&body.credential),
        body.label
            .as_deref()
            .map(str::trim)
            .filter(|l| !l.is_empty()),
        &now,
    );
    // The account, its passkey, the terms and the recovery codes are one batch:
    // either all of them exist afterwards or none does. A concurrent sign-up with
    // the same authenticator fails the batch on the credential, and leaves nothing.
    let codes = cratefield_auth_core::create_passkey_account(
        db,
        clock,
        id_gen,
        &user,
        &credential,
        (&terms_version, &privacy_version),
    )
    .await
    .map_err(|err| {
        tracing::warn!(error = %err, "sign-up batch refused");
        ceremony_failed(&scope)
    })?;

    let mut amr = vec!["passkey", "user"];
    if registered.user_verified {
        amr.push("mfa");
    }
    let ip = cratefield_core::client_ip(&headers);
    let issued = issue_session(
        db,
        clock,
        id_gen,
        Login {
            user_id: &user_id,
            ip: ip.as_deref(),
            user_agent: None,
            presented_cookie: None,
            presented_session_id: None,
            amr: &amr,
        },
    )
    .await
    .map_err(|_| internal(&scope))?;
    let mut response = (
        axum::http::StatusCode::CREATED,
        axum::Json(json!({
            "sub": user_id,
            "email_required": false,
            "recovery_codes": codes,
            "shown_once": true,
        })),
    )
        .into_response();
    if let Ok(cookie) = axum::http::HeaderValue::from_str(&issued.cookie) {
        response
            .headers_mut()
            .append(axum::http::header::SET_COOKIE, cookie);
    }
    Ok(response)
}

pub(crate) fn router() -> axum::Router<Arc<ModuleState>> {
    axum::Router::new()
        .route("/signup/options", post(options))
        .route("/signup/verify", post(verify))
}

/// The passkey row for a new account's first credential.
fn credential_row(
    user_id: &str,
    credential_id: String,
    registered: &crate::webauthn::RegisteredCredential,
    transports: Option<String>,
    label: Option<&str>,
    now: &str,
) -> cratefield_auth_core::CredentialRow {
    use cratefield_auth_core::{Bytes, CREDENTIAL_PASSKEY, CredentialRow};
    CredentialRow {
        id: credential_id,
        user_id: user_id.to_owned(),
        kind: CREDENTIAL_PASSKEY.to_owned(),
        passkey_credential_id: Some(Bytes(registered.credential_id.clone())),
        passkey_public_key_cose: Some(Bytes(registered.cose_key_raw.clone())),
        passkey_sign_count: Some(i64::from(registered.sign_count)),
        passkey_aaguid: registered.aaguid.map(|id| Bytes(id.to_vec())),
        passkey_transports: transports,
        password_hash: None,
        label: label.map(str::to_owned),
        created_at: now.to_owned(),
        last_used_at: None,
        passkey_suspect_at: None,
        failed_attempts: 0,
        failed_window_started_at: None,
        locked_until: None,
    }
}
