//! Token issuing (issue #9): ES256 access tokens with a published JWKS,
//! paired with opaque single-use refresh tokens.
//!
//! The decision is recorded in `docs/adr/0201-token-issuing.md`. In
//! short: consuming apps verify access tokens locally against
//! `/.well-known/jwks.json`, so they stay up when this service is down
//! for the token's 10-minute lifetime; refresh tokens are
//! `single_use_tokens` rows bound to the session, so revoking the
//! session cuts off refreshing immediately and the revocation gap is
//! bounded by the access-token lifetime.
//!
//! Signing is hand-framed JWT on `p256` (the ADR 0200 stack), not
//! `jsonwebtoken`: its `rust_crypto` backend does not build for
//! wasm32 — it pulls `rand` 0.8 → `getrandom` 0.2, which hard-errors
//! on `wasm32-unknown-unknown` without a feature hack, and it drags
//! `rsa` (RUSTSEC-2023-0071) into the main tree for algorithms this
//! service never uses. The finding and the deviation are recorded in
//! the ADR and `PROGRESS.md`.
//!
//! Rules this module enforces:
//!
//! 1. **The private half of a signing key never reaches an output.**
//!    [`SigningKeys`] has a manual `Debug` printing key ids only, and
//!    the JWKS is built from the derived public point, never from
//!    configured input.
//! 2. **Refresh tokens are single-use, and reuse is an alarm**: a
//!    presented refresh token whose row is already consumed revokes
//!    the session it was bound to before the request is refused
//!    (reuse detection).
//! 3. **Every timestamp comes from the `Clock` port** (ADR 0200) and
//!    every token value is 32 random bytes, base64url — the same
//!    shape as session values and client secrets.

use axum::extract::State;
use axum::http::{StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use base64ct::{Base64UrlUnpadded, Encoding};
use cratefield_core::{
    Clock, Config, Database, DbError, IdGen, Json, ModuleConfig, Problem, Scope,
};
use p256::ecdsa::{self, signature::Signer};
use serde::Serialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::sync::{Arc, RwLock};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

use crate::store::{self, TOKEN_REFRESH};

/// Access-token lifetime: 10 minutes (issue #9 recommendation).
pub const ACCESS_TOKEN_SECS: i64 = 600;

/// Refresh-token lifetime: 30 days, aligned with the session slide
/// window — a refresh token can never outlive a session that stays
/// live, and a session that goes quiet expires them both.
pub const REFRESH_TOKEN_DAYS: i64 = crate::sessions::SLIDE_WINDOW_DAYS;

/// `Cache-Control` on the JWKS endpoint: keys rotate rarely, consumers
/// may cache for five minutes.
pub const JWKS_CACHE_CONTROL: &str = "public, max-age=300";

/// `Cache-Control` on `openid-configuration`.
pub const OIDC_CACHE_CONTROL: &str = "public, max-age=3600";

/// The one answer of the discovery endpoints and the token endpoints
/// when signing keys are not configured: `503`, stable, and naming
/// nothing but the misconfiguration.
pub const TOKENS_UNCONFIGURED: cratefield_core::ProblemDef = cratefield_core::ProblemDef {
    slug: "auth/tokens-unconfigured",
    status: StatusCode::SERVICE_UNAVAILABLE,
    title: "Token issuing is not configured",
    description: "Signing keys are absent; no token can be minted or published",
};

/// Where this module's routers mount (the discovery documents advertise
/// absolute URLs built on the configured issuer).
const MODULE_PREFIX: &str = "/v1/auth-core";

/// A signing-key configuration problem: malformed keys, a missing
/// active key id, a missing issuer. Collected by `validate_config`
/// and logged (never including key material) when the router degrades.
#[derive(Debug, thiserror::Error)]
#[error("signing-key configuration: {0}")]
pub struct TokenConfigError(pub String);

/// Failure while minting a token. The token value, when one existed,
/// never leaves the failing call.
#[derive(Debug, thiserror::Error)]
pub enum TokenError {
    #[error("no signing keys are configured")]
    Unconfigured,
    #[error("entropy source failed: {0}")]
    Entropy(String),
    #[error(transparent)]
    Db(#[from] DbError),
}

/// One configured signing key: the id it signs with, the p256 signer,
/// and the public JWK derived from it (never the configured input —
/// the public half is re-derived from `d`, so a mis-published `x`/`y`
/// cannot mislead the JWKS).
#[derive(Clone)]
pub struct SigningKey {
    pub kid: String,
    signing: ecdsa::SigningKey,
    public_jwk: Value,
}

impl std::fmt::Debug for SigningKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Key ids only: the private half must never reach a log.
        f.debug_struct("SigningKey")
            .field("kid", &self.kid)
            .finish_non_exhaustive()
    }
}

impl SigningKey {
    fn parse(jwk: &Value) -> Result<Self, TokenConfigError> {
        let reject = |what: &str| TokenConfigError(format!("AUTH_CORE_SIGNING_KEYS: {what}"));
        if jwk.get("kty").and_then(Value::as_str) != Some("EC")
            || jwk.get("crv").and_then(Value::as_str) != Some("P-256")
        {
            return Err(reject("every key must be an EC JWK on P-256"));
        }
        let Some(kid) = jwk.get("kid").and_then(Value::as_str) else {
            return Err(reject("every key needs a `kid`"));
        };
        if kid.is_empty() || kid.len() > 128 {
            return Err(reject("`kid` must be 1..=128 bytes"));
        }
        let Some(d) = jwk.get("d").and_then(Value::as_str) else {
            return Err(reject("every key needs a private `d`"));
        };
        let bytes = Base64UrlUnpadded::decode_vec(d)
            .map_err(|_| reject("`d` must be base64url without padding"))?;
        let secret = p256::SecretKey::from_slice(&bytes)
            .map_err(|_| reject("`d` is not a valid P-256 scalar"))?;
        let signing = ecdsa::SigningKey::from(&secret);
        // Uncompressed SEC1 point: 0x04 || x[32] || y[32] — the public
        // half is re-derived from `d`, never taken from the config.
        let coordinates = signing.verifying_key().to_sec1_point(false);
        let coordinates = coordinates.as_bytes();
        let public_jwk = json!({
            "kty": "EC",
            "crv": "P-256",
            "kid": kid,
            "use": "sig",
            "alg": "ES256",
            "x": Base64UrlUnpadded::encode_string(&coordinates[1..33]),
            "y": Base64UrlUnpadded::encode_string(&coordinates[33..65]),
        });
        Ok(Self {
            kid: kid.to_owned(),
            signing,
            public_jwk,
        })
    }
}

/// The resolved signing configuration: every configured key (current
/// and previous) plus which one signs. Rotation is operational: add a
/// key to `AUTH_CORE_SIGNING_KEYS`, switch `AUTH_CORE_SIGNING_KEY_ACTIVE`,
/// and drop the old key once the longest token lifetime has passed —
/// the JWKS publishes whatever the configuration holds.
#[derive(Clone)]
pub struct SigningKeys {
    issuer: String,
    active_kid: String,
    keys: Vec<SigningKey>,
}

impl std::fmt::Debug for SigningKeys {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SigningKeys")
            .field("issuer", &self.issuer)
            .field("active_kid", &self.active_kid)
            .field(
                "kids",
                &self.keys.iter().map(|k| k.kid.as_str()).collect::<Vec<_>>(),
            )
            .finish_non_exhaustive()
    }
}

impl SigningKeys {
    /// Reads `AUTH_CORE_SIGNING_KEYS` (a JSON array of private EC
    /// JWKs), `AUTH_CORE_SIGNING_KEY_ACTIVE` (the signing `kid`) and
    /// `AUTH_CORE_ISSUER` (the absolute issuer URL). `Ok(None)` when
    /// no keys are configured at all.
    ///
    /// # Errors
    ///
    /// [`TokenConfigError`] naming the rule the configuration broke —
    /// never the key material.
    pub fn from_config(config: &dyn Config) -> Result<Option<Self>, TokenConfigError> {
        let module = ModuleConfig::new("auth-core", config);
        let Some(raw) = config.get(&module.key("SIGNING_KEYS")) else {
            return Ok(None);
        };
        if raw.trim().is_empty() {
            return Ok(None);
        }
        let jwks: Vec<Value> = serde_json::from_str(&raw).map_err(|_| {
            TokenConfigError("AUTH_CORE_SIGNING_KEYS: must be a JSON array of JWKs".to_owned())
        })?;
        if jwks.is_empty() {
            return Err(TokenConfigError(
                "AUTH_CORE_SIGNING_KEYS: at least one key is required when set".to_owned(),
            ));
        }
        if jwks.len() > 16 {
            return Err(TokenConfigError(
                "AUTH_CORE_SIGNING_KEYS: at most 16 keys".to_owned(),
            ));
        }
        let keys: Vec<SigningKey> = jwks
            .iter()
            .map(SigningKey::parse)
            .collect::<Result<_, _>>()?;
        let mut kids: Vec<&str> = Vec::new();
        for key in &keys {
            if kids.contains(&key.kid.as_str()) {
                return Err(TokenConfigError(format!(
                    "AUTH_CORE_SIGNING_KEYS: duplicate `kid` {}",
                    key.kid
                )));
            }
            kids.push(key.kid.as_str());
        }
        let Some(active_kid) = config.get(&module.key("SIGNING_KEY_ACTIVE")) else {
            return Err(TokenConfigError(
                "AUTH_CORE_SIGNING_KEY_ACTIVE: required when signing keys are set".to_owned(),
            ));
        };
        if !kids.contains(&active_kid.as_str()) {
            return Err(TokenConfigError(format!(
                "AUTH_CORE_SIGNING_KEY_ACTIVE: {active_kid:?} is not one of the configured key ids"
            )));
        }
        let issuer = module.get_str("ISSUER", "");
        let issuer = issuer.trim_end_matches('/').to_owned();
        if !issuer.starts_with("https://") && !issuer.starts_with("http://") {
            return Err(TokenConfigError(
                "AUTH_CORE_ISSUER: absolute http(s) issuer URL required when signing keys are set"
                    .to_owned(),
            ));
        }
        Ok(Some(Self {
            issuer,
            active_kid,
            keys,
        }))
    }

    /// The key id access tokens are signed with.
    #[must_use]
    pub fn active_kid(&self) -> &str {
        &self.active_kid
    }

    fn active(&self) -> &SigningKey {
        self.keys
            .iter()
            .find(|key| key.kid == self.active_kid)
            .expect("from_config guarantees the active kid exists")
    }

    /// The published JWKS document: every configured key's public half.
    #[must_use]
    pub fn jwks(&self) -> Value {
        json!({ "keys": self.keys.iter().map(|key| key.public_jwk.clone()).collect::<Vec<_>>() })
    }

    /// The published `openid-configuration` document: issuer, the
    /// endpoints this module serves, and exactly what it supports —
    /// the authorization-code grant with S256 PKCE, no implicit flow,
    /// no password grant, no `plain`.
    #[must_use]
    pub fn openid_configuration(&self) -> Value {
        json!({
            "issuer": self.issuer,
            "authorization_endpoint": format!("{issuer}{MODULE_PREFIX}/authorize", issuer = self.issuer),
            "token_endpoint": format!("{issuer}{MODULE_PREFIX}/token", issuer = self.issuer),
            "end_session_endpoint": format!("{issuer}{MODULE_PREFIX}/logout", issuer = self.issuer),
            "jwks_uri": format!("{issuer}/.well-known/jwks.json", issuer = self.issuer),
            "response_types_supported": ["code"],
            "response_modes_supported": ["query"],
            "grant_types_supported": ["authorization_code", "refresh_token"],
            "code_challenge_methods_supported": ["S256"],
            "token_endpoint_auth_methods_supported": ["client_secret_post", "none"],
            "subject_types_supported": ["public"],
            "id_token_signing_alg_values_supported": ["ES256"],
            "claims_supported": [
                "iss", "sub", "aud", "exp", "iat", "sid",
                "email", "email_verified", "amr"
            ],
        })
    }
}

/// The serialized access-token claims. Field names are the JWT claim
/// names; `email` and `email_verified` appear only when the user has
/// an email.
#[derive(Serialize)]
struct AccessClaims<'a> {
    iss: &'a str,
    sub: &'a str,
    aud: &'a str,
    exp: i64,
    iat: i64,
    sid: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    email: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    email_verified: Option<bool>,
    amr: &'a [String],
}

fn b64url(bytes: &[u8]) -> String {
    Base64UrlUnpadded::encode_string(bytes)
}

fn iso(t: OffsetDateTime) -> String {
    t.replace_nanosecond(0)
        .expect("truncation stays in range")
        .format(&Rfc3339)
        .expect("rfc3339 formats")
}

/// Mints one ES256 access token (RFC 9068 shape: `typ: at+jwt`,
/// `kid` in the header) for one session and client: `sub` the user
/// id, `aud` the client id, `sid` the session id, `exp`/`iat` from
/// the `Clock` port, `amr` the session's login methods.
///
/// # Errors
///
/// [`TokenError::Unconfigured`] when no signing keys resolved;
/// [`TokenError::Entropy`] never — signing is deterministic
/// (RFC 6979).
///
/// # Panics
///
/// Never in practice: the documented panics are the `time` crate's
/// nanosecond truncation and RFC 3339 formatting, both infallible on
/// this path.
pub fn mint_access_token(
    keys: &SigningKeys,
    clock: &dyn Clock,
    session_id: &str,
    user_id: &str,
    user_email: Option<(&str, bool)>,
    client_id: &str,
    amr: &[String],
) -> Result<String, TokenError> {
    let now = clock.now().replace_nanosecond(0).expect("in range");
    let claims = AccessClaims {
        iss: &keys.issuer,
        sub: user_id,
        aud: client_id,
        exp: now.unix_timestamp() + ACCESS_TOKEN_SECS,
        iat: now.unix_timestamp(),
        sid: session_id,
        email: user_email.map(|(email, _)| email),
        email_verified: user_email.map(|(_, verified)| verified),
        amr,
    };
    let header = json!({
        "alg": "ES256",
        "typ": "at+jwt",
        "kid": keys.active_kid(),
    });
    let signing_input = format!(
        "{}.{}",
        b64url(
            serde_json::to_string(&header)
                .expect("header serializes")
                .as_bytes()
        ),
        b64url(
            serde_json::to_string(&claims)
                .expect("claims serialize")
                .as_bytes()
        ),
    );
    let active = keys.active();
    let signature: ecdsa::Signature = active.signing.sign(signing_input.as_bytes());
    Ok(format!("{signing_input}.{}", b64url(&signature.to_bytes())))
}

/// 32 random bytes, base64url — the shape of every opaque token value
/// this module hands out (refresh tokens now, authorization codes in
/// issue #10).
fn random_value() -> Result<String, TokenError> {
    let mut bytes = [0u8; 32];
    getrandom::fill(&mut bytes).map_err(|err| TokenError::Entropy(err.to_string()))?;
    Ok(b64url(&bytes))
}

fn sha256(bytes: &[u8]) -> Vec<u8> {
    Sha256::digest(bytes).to_vec()
}

/// Mints one opaque single-use refresh token bound to the session and
/// the client: only its SHA-256 is stored, in a `single_use_tokens`
/// row of kind `refresh_token` whose payload names the session.
///
/// # Errors
///
/// [`TokenError::Entropy`] when the OS entropy source fails;
/// [`TokenError::Db`] when the write fails.
///
/// # Panics
///
/// Never in practice: the documented panics are the `time` crate's
/// nanosecond truncation and RFC 3339 formatting, both infallible on
/// this path.
pub async fn mint_refresh_token(
    db: &dyn Database,
    clock: &dyn Clock,
    id_gen: &dyn IdGen,
    session_id: &str,
    user_id: &str,
    client_id: &str,
) -> Result<String, TokenError> {
    let value = random_value()?;
    let now = clock.now().replace_nanosecond(0).expect("in range");
    store::insert_single_use_token(
        db,
        &store::SingleUseTokenRow {
            id: id_gen.ulid(),
            kind: TOKEN_REFRESH.to_owned(),
            token_hash: store::Redacted(sha256(value.as_bytes())),
            user_id: Some(user_id.to_owned()),
            client_id: Some(client_id.to_owned()),
            payload: Some(json!({ "sid": session_id }).to_string()),
            expires_at: iso(now.saturating_add(time::Duration::days(REFRESH_TOKEN_DAYS))),
            consumed_at: None,
        },
    )
    .await?;
    Ok(value)
}

/// What a successfully exchanged refresh token grants: the session and
/// client it is bound to. The caller still checks the session is live
/// and mints the next pair.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RefreshGrant {
    pub session_id: String,
    pub user_id: String,
    pub client_id: String,
}

/// The outcome of presenting a refresh token: granted, or refused
/// without a reason the caller could distinguish.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RefreshOutcome {
    Granted,
    Refused,
}

/// Exchanges one refresh token, enforcing the two refresh rules of
/// issue #9: single use (the guarded consume decides the winner), and
/// **reuse detection** — a token whose row is already consumed revokes
/// the session it was bound to before the request is refused. A token
/// presented for the wrong client is refused *without* being consumed,
/// so a wrong-client presentation cannot burn the rightful client's
/// token.
///
/// # Errors
///
/// [`DbError`] when a read, the consume or the revocation write fails.
///
/// # Panics
///
/// Never in practice: the documented panics are the `time` crate's
/// nanosecond truncation and RFC 3339 formatting, both infallible on
/// this path.
pub async fn exchange_refresh_token(
    db: &dyn Database,
    clock: &dyn Clock,
    presented: &str,
    client_id: &str,
) -> Result<(RefreshOutcome, Option<RefreshGrant>), DbError> {
    let now = iso(clock.now().replace_nanosecond(0).expect("in range"));
    let Some(row) = store::single_use_token_by_hash(db, &sha256(presented.as_bytes())).await?
    else {
        return Ok((RefreshOutcome::Refused, None));
    };
    if row.kind != TOKEN_REFRESH
        || row.client_id.as_deref() != Some(client_id)
        || row.user_id.is_none()
    {
        return Ok((RefreshOutcome::Refused, None));
    }
    let Some(payload) = row.payload.as_deref() else {
        return Ok((RefreshOutcome::Refused, None));
    };
    let Ok(payload) = serde_json::from_str::<Value>(payload) else {
        return Ok((RefreshOutcome::Refused, None));
    };
    let Some(session_id) = payload.get("sid").and_then(Value::as_str) else {
        return Ok((RefreshOutcome::Refused, None));
    };
    if row.consumed_at.is_some() {
        // Reuse of a consumed refresh token: revoke the session, then
        // refuse. The revocation is the alarm; the refusal is uniform.
        store::revoke_session(db, session_id, &now).await?;
        tracing::warn!(
            audit = true,
            action = "token.refresh-reuse",
            client_id,
            "refresh-token reuse detected; session revoked"
        );
        return Ok((RefreshOutcome::Refused, None));
    }
    let Some(consumed) = store::consume_single_use_token(db, &row.id, &now).await? else {
        return Ok((RefreshOutcome::Refused, None));
    };
    Ok((
        RefreshOutcome::Granted,
        Some(RefreshGrant {
            session_id: session_id.to_owned(),
            user_id: consumed.user_id.unwrap_or_default(),
            client_id: consumed.client_id.unwrap_or_default(),
        }),
    ))
}

/// The cell `router()` fills and the `/.well-known` handlers read:
/// `Module::well_known` is called without a `ModuleContext` (harness
/// issue #46), so the resolved keys travel through shared state that
/// the router assembly — which does see the config — populates before
/// any request can flow.
pub type SigningKeysCell = Arc<RwLock<Option<Arc<SigningKeys>>>>;

fn unconfigured(scope: &Scope) -> Problem {
    Problem::new(&TOKENS_UNCONFIGURED).instance(&scope.request_id)
}

async fn jwks(scope: Scope, State(cell): State<SigningKeysCell>) -> Result<Response, Problem> {
    let keys = cell.read().expect("jwks cell uncontended").clone();
    let Some(keys) = keys else {
        return Err(unconfigured(&scope));
    };
    Ok((
        [(header::CACHE_CONTROL, JWKS_CACHE_CONTROL)],
        Json(keys.jwks()),
    )
        .into_response())
}

async fn openid_configuration(
    scope: Scope,
    State(cell): State<SigningKeysCell>,
) -> Result<Response, Problem> {
    let keys = cell.read().expect("openid cell uncontended").clone();
    let Some(keys) = keys else {
        return Err(unconfigured(&scope));
    };
    Ok((
        [(header::CACHE_CONTROL, OIDC_CACHE_CONTROL)],
        Json(keys.openid_configuration()),
    )
        .into_response())
}

/// The `/.well-known` router (harness issue #46): `jwks.json` and
/// `openid-configuration` at the root — the reason the JWKS endpoint
/// can live where consuming apps expect it, outside `/v1`.
pub(crate) fn well_known_router(cell: SigningKeysCell) -> axum::Router {
    axum::Router::new()
        .route("/jwks.json", get(jwks))
        .route("/openid-configuration", get(openid_configuration))
        .with_state(cell)
}

#[cfg(test)]
mod tests {
    use super::*;
    use cratefield_core::MapConfig;
    use cratefield_testing::FixedClock;
    use p256::ecdsa::{self, signature::Verifier};

    /// A throwaway key generated in the test, never a real one.
    fn dummy_jwk(kid: &str) -> (Value, ecdsa::SigningKey) {
        let mut bytes = [0u8; 32];
        getrandom::fill(&mut bytes).expect("entropy");
        bytes[0] = 1; // keep the scalar valid while staying obviously fake
        let secret = p256::SecretKey::from_slice(&bytes).expect("scalar");
        let signing = ecdsa::SigningKey::from(&secret);
        let d = b64url(&secret.to_bytes());
        (
            json!({ "kty": "EC", "crv": "P-256", "kid": kid, "d": d }),
            signing,
        )
    }

    fn config_with(keys: &Value, active: &str) -> MapConfig {
        MapConfig::from_pairs([
            (
                "AUTH_CORE_SIGNING_KEYS",
                serde_json::to_string(keys).expect("keys json"),
            ),
            ("AUTH_CORE_SIGNING_KEY_ACTIVE", active.to_owned()),
            ("AUTH_CORE_ISSUER", "https://auth.test.example".to_owned()),
        ])
    }

    #[test]
    fn from_config_resolves_keys_and_the_active_kid() {
        let (jwk_a, _) = dummy_jwk("2026-09-a");
        let (jwk_b, _) = dummy_jwk("2026-10-b");
        let keys = serde_json::to_value(vec![jwk_a, jwk_b]).expect("array");
        let resolved = SigningKeys::from_config(&config_with(&keys, "2026-10-b"))
            .expect("valid")
            .expect("configured");
        assert_eq!(resolved.active_kid(), "2026-10-b");
        let jwks = resolved.jwks();
        let kids: Vec<&str> = jwks["keys"]
            .as_array()
            .expect("keys array")
            .iter()
            .map(|key| key["kid"].as_str().expect("kid"))
            .collect();
        assert_eq!(kids, ["2026-09-a", "2026-10-b"]);
        assert!(
            !jwks.to_string().contains("\"d\""),
            "the JWKS must never carry private material"
        );
    }

    #[test]
    fn from_config_rejects_broken_configurations() {
        let (jwk, _) = dummy_jwk("only");
        let single = serde_json::to_value(vec![jwk]).expect("array");

        let unset = MapConfig::default();
        assert!(matches!(SigningKeys::from_config(&unset), Ok(None)));

        for (keys, active) in [
            (
                serde_json::to_value(Vec::<Value>::new()).expect("empty"),
                "x",
            ),
            (
                json!([{ "kty": "EC", "crv": "P-256", "kid": "k", "d": "not-base64!" }]),
                "k",
            ),
            (
                json!([{ "kty": "OKP", "crv": "P-256", "kid": "k", "d": "AAAA" }]),
                "k",
            ),
            (
                json!([{ "kty": "EC", "crv": "P-384", "kid": "k", "d": "AAAA" }]),
                "k",
            ),
            (
                json!([{ "kty": "EC", "crv": "P-256", "kid": "", "d": "AAAA" }]),
                "",
            ),
            (json!([{ "kty": "EC", "crv": "P-256", "kid": "k" }]), "k"),
            (single.clone(), "not-a-configured-kid"),
        ] {
            let outcome = SigningKeys::from_config(&config_with(&keys, active));
            assert!(outcome.is_err(), "must reject keys={keys} active={active}");
        }

        // Active id and issuer are required once keys exist.
        let keys_only = MapConfig::from_pairs([(
            "AUTH_CORE_SIGNING_KEYS",
            serde_json::to_string(&single).expect("json"),
        )]);
        assert!(SigningKeys::from_config(&keys_only).is_err());
        let no_issuer = MapConfig::from_pairs([
            (
                "AUTH_CORE_SIGNING_KEYS",
                serde_json::to_string(&single).expect("json"),
            ),
            ("AUTH_CORE_SIGNING_KEY_ACTIVE", "only".to_owned()),
        ]);
        assert!(SigningKeys::from_config(&no_issuer).is_err());
    }

    #[test]
    fn a_minted_token_verifies_and_carries_the_recommended_claims() {
        let (jwk, signing_key) = dummy_jwk("active-kid");
        let keys = SigningKeys::from_config(&config_with(
            &serde_json::to_value(vec![jwk]).expect("array"),
            "active-kid",
        ))
        .expect("valid")
        .expect("configured");

        let clock = FixedClock(OffsetDateTime::from_unix_timestamp(1_800_000_000).expect("epoch"));
        let amr = vec!["user".to_owned(), "passkey".to_owned()];
        let token = mint_access_token(
            &keys,
            &clock,
            "sess_1",
            "user_1",
            Some(("user@example.com", true)),
            "client_1",
            &amr,
        )
        .expect("mint");

        let mut parts = token.split('.');
        let header = parts.next().expect("header");
        let claims = parts.next().expect("claims");
        let signature = parts.next().expect("signature");
        assert!(parts.next().is_none());

        let header_json: Value =
            serde_json::from_slice(&Base64UrlUnpadded::decode_vec(header).expect("header b64"))
                .expect("header json");
        assert_eq!(header_json["alg"], "ES256");
        assert_eq!(header_json["typ"], "at+jwt");
        assert_eq!(header_json["kid"], "active-kid");

        let signing_input = format!("{header}.{claims}");
        let raw = Base64UrlUnpadded::decode_vec(signature).expect("signature b64");
        assert_eq!(raw.len(), 64, "ES256 signatures are r||s, 64 bytes");
        let signature = ecdsa::Signature::from_slice(&raw).expect("signature parses");
        signing_key
            .verifying_key()
            .verify(signing_input.as_bytes(), &signature)
            .expect("the signature verifies");

        let claims: Value =
            serde_json::from_slice(&Base64UrlUnpadded::decode_vec(claims).expect("claims b64"))
                .expect("claims json");
        assert_eq!(claims["iss"], "https://auth.test.example");
        assert_eq!(claims["sub"], "user_1");
        assert_eq!(claims["aud"], "client_1");
        assert_eq!(claims["sid"], "sess_1");
        assert_eq!(claims["iat"], 1_800_000_000);
        assert_eq!(claims["exp"], 1_800_000_000 + ACCESS_TOKEN_SECS);
        assert_eq!(claims["email"], "user@example.com");
        assert_eq!(claims["email_verified"], true);
        assert_eq!(claims["amr"], json!(["user", "passkey"]));

        // No email: the claims are omitted, not null.
        let bare = mint_access_token(&keys, &clock, "sess_1", "user_1", None, "client_1", &[])
            .expect("mint");
        let bare_claims = bare.split('.').nth(1).expect("claims");
        let bare_claims: Value =
            serde_json::from_slice(&Base64UrlUnpadded::decode_vec(bare_claims).expect("b64"))
                .expect("json");
        assert!(bare_claims.get("email").is_none());
        assert_eq!(bare_claims["amr"], json!([]));
    }

    #[test]
    fn openid_configuration_advertises_exactly_the_supported_surface() {
        let (jwk, _) = dummy_jwk("k");
        let keys = SigningKeys::from_config(&config_with(
            &serde_json::to_value(vec![jwk]).expect("array"),
            "k",
        ))
        .expect("valid")
        .expect("configured");
        let doc = keys.openid_configuration();
        assert_eq!(doc["issuer"], "https://auth.test.example");
        assert_eq!(
            doc["jwks_uri"],
            "https://auth.test.example/.well-known/jwks.json"
        );
        assert_eq!(
            doc["authorization_endpoint"],
            "https://auth.test.example/v1/auth-core/authorize"
        );
        assert_eq!(
            doc["token_endpoint"],
            "https://auth.test.example/v1/auth-core/token"
        );
        assert_eq!(
            doc["end_session_endpoint"],
            "https://auth.test.example/v1/auth-core/logout"
        );
        assert_eq!(doc["response_types_supported"], json!(["code"]));
        assert_eq!(
            doc["grant_types_supported"],
            json!(["authorization_code", "refresh_token"])
        );
        assert_eq!(doc["code_challenge_methods_supported"], json!(["S256"]));
        assert_eq!(
            doc["token_endpoint_auth_methods_supported"],
            json!(["client_secret_post", "none"])
        );
    }
}
