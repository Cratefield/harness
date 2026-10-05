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
//!    (reuse detection). A short [`RefreshReuseGrace`] forgoes the
//!    alarm for the *same client* re-presenting a token within seconds
//!    of a legitimate rotation — separate Worker isolates racing a
//!    page's parallel refreshes — handing each claimant its own sibling
//!    successor instead of revoking (issue #655).
//! 3. **Every timestamp comes from the `Clock` port** (ADR 0200) and
//!    every token value is 32 random bytes, base64url — the same
//!    shape as session values and client secrets.

use axum::extract::State;
use axum::http::{StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use base64ct::{Base64UrlUnpadded, Encoding};
use cratefield_core::{
    Clock, Config, Database, DbError, IdGen, Json, ModuleConfig, Problem, Scope, subject_hash,
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

/// Default cap on how many grace uses a consumed refresh token may grant
/// inside its grace window (issue #655), used when
/// `AUTH_CORE_REFRESH_REUSE_GRACE_MAX_USES` is unset.
pub const DEFAULT_REFRESH_REUSE_GRACE_MAX_USES: u32 = 3;

/// The largest `AUTH_CORE_REFRESH_REUSE_GRACE_SECONDS` accepted. The
/// grace exists for a page firing several refreshes from separate
/// Worker isolates at once; it is not a second lifetime for a token
/// whose reuse should revoke.
pub const MAX_REFRESH_REUSE_GRACE_SECS: u32 = 300;

/// The largest `AUTH_CORE_REFRESH_REUSE_GRACE_MAX_USES` accepted: a
/// graced reuse absorbs a race, and a page cannot lose more than a
/// handful of parallel refreshes; a bigger cap is a mistake, not a
/// setting.
pub const MAX_REFRESH_REUSE_GRACE_USES: u32 = 10;

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
/// absolute URLs built on the configured issuer). `locale` reads it too:
/// the `ui_locales` a login method must honour only counts when the
/// `return_to` is this module's `/authorize`.
pub(crate) const MODULE_PREFIX: &str = "/v1/auth-core";

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
                "email", "email_verified", "amr", "sso_connection"
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
    /// The enterprise SSO connection the session was signed in through
    /// (issue #627), present only while that connection belongs to the
    /// client this token is for (`aud`). Omitted otherwise, so an ordinary
    /// login and a foreign client's token never carry it.
    #[serde(skip_serializing_if = "Option::is_none")]
    sso_connection: Option<&'a str>,
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
/// `sso_connection` is the connection id to name in the token, already
/// resolved by the caller to "the session's connection, and only while it
/// belongs to `client_id`" — the ownership rule is not a token-shape rule
/// and lives in the token endpoint (`token_endpoint`), where the client is known.
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
// The eight arguments are the eight things an RFC 9068 token says; bundling
// them into a struct would only move the list somewhere the claims are read
// from, and `sso_connection` adding the eighth is what issue #627 is.
#[allow(clippy::too_many_arguments)]
pub fn mint_access_token(
    keys: &SigningKeys,
    clock: &dyn Clock,
    session_id: &str,
    user_id: &str,
    user_email: Option<(&str, bool)>,
    client_id: &str,
    sso_connection: Option<&str>,
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
        sso_connection,
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
    let (_, value) =
        insert_refresh_row(db, clock, id_gen, session_id, user_id, client_id, None).await?;
    Ok(value)
}

/// [`mint_refresh_token`] that also returns the new row's id, so the
/// caller can name it among the successors of the row it consumes.
/// `parent` is the row this token succeeds, recorded in the payload so a
/// later rotation can find its siblings (issue #655); the code grant
/// mints a root with none.
async fn insert_refresh_row(
    db: &dyn Database,
    clock: &dyn Clock,
    id_gen: &dyn IdGen,
    session_id: &str,
    user_id: &str,
    client_id: &str,
    parent: Option<&str>,
) -> Result<(String, String), TokenError> {
    let value = random_value()?;
    let now = clock.now().replace_nanosecond(0).expect("in range");
    let id = id_gen.ulid();
    let payload = match parent {
        Some(parent) => json!({ "sid": session_id, "parent": parent }),
        None => json!({ "sid": session_id }),
    };
    store::insert_single_use_token(
        db,
        &store::SingleUseTokenRow {
            id: id.clone(),
            kind: TOKEN_REFRESH.to_owned(),
            token_hash: store::Redacted(sha256(value.as_bytes())),
            user_id: Some(user_id.to_owned()),
            client_id: Some(client_id.to_owned()),
            payload: Some(payload.to_string()),
            expires_at: iso(now.saturating_add(time::Duration::days(REFRESH_TOKEN_DAYS))),
            consumed_at: None,
        },
    )
    .await?;
    Ok((id, value))
}

/// The refresh-reuse grace (issue #655): how long after a refresh token is
/// first rotated a second presentation of it, by the same client, still
/// succeeds instead of revoking the session.
///
/// A browser page can fire several requests at once, and on Workers each
/// lands in its own isolate holding the same refresh cookie; without a
/// grace the loser of that race presents an already-consumed token and
/// revokes a session nobody compromised. The window is short on purpose —
/// see [`MAX_REFRESH_REUSE_GRACE_SECS`] — and measured from the original
/// rotation, so grace claims never extend it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RefreshReuseGrace {
    /// `AUTH_CORE_REFRESH_REUSE_GRACE_SECONDS`; `0` (the default) keeps
    /// today's behaviour exactly: any reuse revokes.
    pub seconds: u32,
    /// `AUTH_CORE_REFRESH_REUSE_GRACE_MAX_USES`: how many grace uses one
    /// consumed token may grant before reuse revokes again, in
    /// `1..=`[`MAX_REFRESH_REUSE_GRACE_USES`].
    pub max_uses: u32,
}

impl RefreshReuseGrace {
    /// Reads both keys through the module prefix. Malformed values are
    /// left to `validate_config`,
    /// which reports them at doctor time; here a bad value falls back to
    /// the default, the same way the other auth-core keys resolve.
    #[must_use]
    pub fn from_config(config: &dyn Config) -> Self {
        let module = ModuleConfig::new("auth-core", config);
        Self {
            seconds: module.get_u32("REFRESH_REUSE_GRACE_SECONDS", 0),
            max_uses: module.get_u32(
                "REFRESH_REUSE_GRACE_MAX_USES",
                DEFAULT_REFRESH_REUSE_GRACE_MAX_USES,
            ),
        }
    }

    /// Whether the grace can ever apply: a zero window or a zero cap is
    /// disabled, whatever the other key says.
    fn enabled(self) -> bool {
        self.seconds > 0 && self.max_uses > 0
    }
}

/// What a successfully exchanged refresh token grants: the session and
/// client it is bound to, plus the plaintext of the refresh token that
/// succeeds the one presented. The exchange mints that successor itself
/// (issue #655) so it can record the rotation in the consumed row in the
/// same guarded update; the caller mints only the access token.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RefreshGrant {
    pub session_id: String,
    pub user_id: String,
    pub client_id: String,
    pub refresh_token: String,
}

/// The outcome of presenting a refresh token: granted, or refused
/// without a reason the caller could distinguish.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RefreshOutcome {
    Granted,
    Refused,
}

/// Is `now` inside `seconds` of the instant `consumed_at` names? A
/// negative elapsed (a clock that went backwards) is outside, so the
/// grace never fires on a value it cannot read.
fn within_grace(now: OffsetDateTime, consumed_at: &str, seconds: u32) -> bool {
    if seconds == 0 {
        return false;
    }
    match OffsetDateTime::parse(consumed_at, &Rfc3339) {
        Ok(consumed) => (0..=i64::from(seconds)).contains(&(now - consumed).whole_seconds()),
        Err(_) => false,
    }
}

/// Is the row's `expires_at` at or before `now`? An expiry the module
/// cannot parse is treated as expired: a row this code did not write is
/// not one to mint a successor for.
fn is_expired(expires_at: &str, now: OffsetDateTime) -> bool {
    match OffsetDateTime::parse(expires_at, &Rfc3339) {
        Ok(expires) => expires <= now,
        Err(_) => true,
    }
}

/// Exchanges one refresh token, enforcing the two refresh rules of
/// issue #9: single use (the guarded consume decides the winner), and
/// **reuse detection** — a token whose row is already consumed revokes
/// the session it was bound to before the request is refused. A token
/// presented for the wrong client is refused *without* being consumed,
/// so a wrong-client presentation cannot burn the rightful client's
/// token. A token past its expiry, or one that merely lost the guarded
/// consume, is refused without revoking and without minting anything.
///
/// The exchange mints the successor refresh token itself and records it
/// in the *same* guarded update that consumes the presented row, so the
/// successor's plaintext is returned **only** to the request that won the
/// race. A configured [`RefreshReuseGrace`] lets a *second* presentation
/// of the same token, by the same client and inside the window, claim a
/// grace use instead of revoking: it mints another **sibling** successor
/// and appends it to the consumed row's `kids`, so parallel refreshes
/// each hold a usable token. Siblings stay valid until one of them is
/// used, whereupon its rotation retires the rest — first use wins, and
/// the family converges on the chain the cookie actually kept (issue
/// #655).
///
/// # Errors
///
/// [`DbError`] when a read, a mint's write, the consume, the payload
/// swap or the revocation write fails.
///
/// # Panics
///
/// Never in practice: the documented panics are the `time` crate's
/// nanosecond truncation and RFC 3339 formatting, both infallible on
/// this path.
// One request's whole refresh state machine — the kind/client checks, the
// guarded consume and its lost-race fallback, and the grace claim — read
// top to bottom. Splitting it into fragments would scatter the invariants
// (what is consumed when, and what a granted request may return) that the
// ordering above depends on.
#[allow(clippy::too_many_lines)]
pub async fn exchange_refresh_token(
    db: &dyn Database,
    clock: &dyn Clock,
    id_gen: &dyn IdGen,
    grace: RefreshReuseGrace,
    presented: &str,
    client_id: &str,
) -> Result<(RefreshOutcome, Option<RefreshGrant>), DbError> {
    let now = clock.now().replace_nanosecond(0).expect("in range");
    let now_iso = iso(now);
    let Some(row) = store::single_use_token_by_hash(db, &sha256(presented.as_bytes())).await?
    else {
        return Ok((RefreshOutcome::Refused, None));
    };
    // Kind, client and user are checked *before* the consume and the
    // reuse path: a token presented for the wrong client is neither
    // consumed nor treated as reuse, so a stranger cannot burn the
    // rightful client's token or trip the alarm.
    if row.kind != TOKEN_REFRESH
        || row.client_id.as_deref() != Some(client_id)
        || row.user_id.is_none()
    {
        return Ok((RefreshOutcome::Refused, None));
    }
    let Some(payload_text) = row.payload.as_deref() else {
        return Ok((RefreshOutcome::Refused, None));
    };
    let Ok(payload) = serde_json::from_str::<Value>(payload_text) else {
        return Ok((RefreshOutcome::Refused, None));
    };
    let Some(session_id) = payload.get("sid").and_then(Value::as_str) else {
        return Ok((RefreshOutcome::Refused, None));
    };
    let session_id = session_id.to_owned();
    let user_id = row.user_id.clone().unwrap_or_default();
    // A successor records its parent so a rotation can retire its
    // siblings; a root from the code grant has none.
    let parent = payload
        .get("parent")
        .and_then(Value::as_str)
        .map(str::to_owned);
    // A token past its expiry is stale, not reuse: refuse before minting
    // anything, so replaying an expired token cannot grow the table with
    // a successor that could never be presented.
    if is_expired(&row.expires_at, now) {
        return Ok((RefreshOutcome::Refused, None));
    }
    // Only a row already consumed when we first read it is the reuse the
    // alarm is for. Losing the guarded consume below is a race, and the
    // loser must be refused without revoking (issue #655).
    let consumed_before = row.consumed_at.is_some();
    let mut row = row;

    if row.consumed_at.is_none() {
        // Normal rotation: mint the successor first, then consume the
        // presented row and record the successor in one guarded update.
        // The consume decides the winner of any race.
        let (successor_id, successor_value) = insert_refresh_row(
            db,
            clock,
            id_gen,
            &session_id,
            &user_id,
            client_id,
            Some(row.id.as_str()),
        )
        .await
        .map_err(|err| db_error("minting a refresh token failed", err))?;
        let next_payload =
            json!({ "sid": session_id, "kids": [successor_id], "grace": 0 }).to_string();
        let consumed =
            store::consume_single_use_token_with_payload(db, &row.id, &now_iso, &next_payload)
                .await?;
        if let Some(consumed) = consumed {
            // First use wins: retire this token's siblings so the ones the
            // browser cookie lost are no longer live.
            if let Some(parent_id) = &parent {
                retire_siblings(db, parent_id, &row.id, &now_iso).await?;
            }
            return Ok((
                RefreshOutcome::Granted,
                Some(RefreshGrant {
                    session_id,
                    user_id: consumed.user_id.unwrap_or_default(),
                    client_id: consumed.client_id.unwrap_or_default(),
                    refresh_token: successor_value,
                }),
            ));
        }
        // Lost the race: the winner consumed the row and recorded its own
        // successor. Retire the successor we minted (its plaintext was
        // never returned, so it can never be presented — consuming it just
        // stops the row lingering) and continue with the freshest row.
        store::consume_single_use_token(db, &successor_id, &now_iso).await?;
        let Some(fresh) = store::single_use_token_by_id(db, &row.id).await? else {
            return Ok((RefreshOutcome::Refused, None));
        };
        // Should the row have expired between the two reads, the re-read
        // shows it still unconsumed: a stale token, refused as before.
        if fresh.consumed_at.is_none() {
            return Ok((RefreshOutcome::Refused, None));
        }
        row = fresh;
    }

    // The presented row is consumed: grace a concurrent refresh, or fall
    // through to the reuse decision. Each attempt re-reads the row so a
    // concurrent claim's window and count are seen; a lost swap means
    // another claim won, so the count runs out within the cap — at most
    // `max_uses + 1` attempts are ever needed.
    if grace.enabled() {
        for _ in 0..=grace.max_uses {
            let Some(consumed_at) = row.consumed_at.as_deref() else {
                break;
            };
            if !within_grace(now, consumed_at, grace.seconds) {
                break;
            }
            let Some(old_payload) = row.payload.clone() else {
                break;
            };
            let Ok(state) = serde_json::from_str::<Value>(&old_payload) else {
                break;
            };
            let Some(kids) = state.get("kids").and_then(Value::as_array) else {
                break;
            };
            let claims = state.get("grace").and_then(Value::as_u64).unwrap_or(0);
            if claims >= u64::from(grace.max_uses) {
                break;
            }
            // If any sibling has already been consumed its own chain moved
            // on, so this presentation is the replay the alarm is for.
            let mut moved_on = false;
            for kid in kids {
                if let Some(kid_id) = kid.as_str()
                    && store::single_use_token_by_id(db, kid_id)
                        .await?
                        .is_some_and(|kid| kid.consumed_at.is_some())
                {
                    moved_on = true;
                    break;
                }
            }
            if moved_on {
                break;
            }
            let (new_id, new_value) = insert_refresh_row(
                db,
                clock,
                id_gen,
                &session_id,
                &user_id,
                client_id,
                Some(row.id.as_str()),
            )
            .await
            .map_err(|err| db_error("minting a refresh token failed", err))?;
            let mut kids = kids.clone();
            kids.push(Value::String(new_id.clone()));
            let new_payload =
                json!({ "sid": session_id, "kids": kids, "grace": claims + 1 }).to_string();
            let swapped =
                store::compare_and_swap_payload(db, &row.id, &old_payload, &new_payload).await?;
            if swapped == 0 {
                // Another claim appended first: retire the sibling we
                // minted (never returned, so never presentable) and retry
                // so ours is added after it, not over it.
                store::consume_single_use_token(db, &new_id, &now_iso).await?;
                let Some(fresh) = store::single_use_token_by_id(db, &row.id).await? else {
                    break;
                };
                row = fresh;
                continue;
            }
            // A sibling's rotation racing this append can leave one extra
            // live sibling; accepted, the next rotation converges the family.
            tracing::info!(
                audit = true,
                action = "token.refresh-grace",
                client_id,
                subject_hash = %subject_hash(&user_id),
                grace_uses = claims + 1,
                "refresh token reused inside the grace window; sibling minted"
            );
            return Ok((
                RefreshOutcome::Granted,
                Some(RefreshGrant {
                    session_id,
                    user_id,
                    client_id: client_id.to_owned(),
                    refresh_token: new_value,
                }),
            ));
        }
    }

    // The reuse alarm fires only for a token already consumed when we
    // first read it. A request that merely lost the guarded consume race
    // is refused without revoking, exactly as before the grace existed:
    // it is a race, not a compromise.
    if consumed_before {
        store::revoke_session(db, &session_id, &now_iso).await?;
        tracing::warn!(
            audit = true,
            action = "token.refresh-reuse",
            client_id,
            "refresh-token reuse detected; session revoked"
        );
    }
    Ok((RefreshOutcome::Refused, None))
}

/// Maps a [`TokenError`] from the exchange's own minting onto the
/// [`DbError`] the exchange returns: entropy and unconfigured are not
/// expected on this path (signing keys are checked at the router), so
/// only the wrapped database error can arise.
fn db_error(what: &'static str, err: TokenError) -> DbError {
    match err {
        TokenError::Db(err) => err,
        other => {
            tracing::error!(error = %other, "{what}");
            DbError::Execute(other.to_string())
        }
    }
}

/// Retires the other live successors of `parent` once `winner` has
/// rotated: the family converges on the chain the request actually used,
/// so a sibling the browser cookie lost is no longer live. Its later
/// presentation then finds no `kids` and is ordinary reuse (issue #655).
async fn retire_siblings(
    db: &dyn Database,
    parent_id: &str,
    winner_id: &str,
    now: &str,
) -> Result<(), DbError> {
    let Some(parent) = store::single_use_token_by_id(db, parent_id).await? else {
        return Ok(());
    };
    let kids = parent
        .payload
        .as_deref()
        .and_then(|text| serde_json::from_str::<Value>(text).ok())
        .and_then(|state| state.get("kids").cloned());
    let Some(kids) = kids.as_ref().and_then(Value::as_array) else {
        return Ok(());
    };
    for kid in kids {
        if let Some(kid_id) = kid.as_str()
            && kid_id != winner_id
        {
            store::consume_single_use_token(db, kid_id, now).await?;
        }
    }
    Ok(())
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
            None,
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
        // No SSO connection: the claim is omitted, not null.
        assert!(claims.get("sso_connection").is_none());

        // An SSO login names the connection; it is a claim like any other.
        let sso = mint_access_token(
            &keys,
            &clock,
            "sess_1",
            "user_1",
            None,
            "client_1",
            Some("ssoc_1"),
            &["sso".to_owned()],
        )
        .expect("mint");
        let sso_claims = sso.split('.').nth(1).expect("claims");
        let sso_claims: Value =
            serde_json::from_slice(&Base64UrlUnpadded::decode_vec(sso_claims).expect("b64"))
                .expect("json");
        assert_eq!(sso_claims["sso_connection"], "ssoc_1");
        assert_eq!(sso_claims["amr"], json!(["sso"]));

        // No email: the claims are omitted, not null.
        let bare = mint_access_token(
            &keys,
            &clock,
            "sess_1",
            "user_1",
            None,
            "client_1",
            None,
            &[],
        )
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
