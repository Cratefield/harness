//! Token verification: header, signature, then claims.
//!
//! The order matters. Nothing inside a token is trusted until its
//! signature verifies, so the claim checks run last, on a payload that
//! has already been proven to come from a key we hold.

use base64ct::{Base64UrlUnpadded, Encoding};
use p256::ecdsa::signature::Verifier;
use p256::ecdsa::{Signature, VerifyingKey};
use serde::Deserialize;
use sha2::{Digest, Sha256};

use crate::{ALGORITHM, LEEWAY_SECS};

/// Why a token was refused.
///
/// The variants exist to be logged, not to be shown to a caller: a
/// client that learns *why* its token failed learns something about the
/// verifier. Handlers turn every one of these into the same 401.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum VerifyError {
    #[error("token is not three base64url segments")]
    Malformed,
    #[error("header is not JSON, or omits alg/kid")]
    BadHeader,
    #[error("algorithm {0} is not accepted; only {ALGORITHM} is")]
    Algorithm(String),
    #[error("token type is {0:?}, expected at+jwt: only access tokens are accepted")]
    Type(String),
    #[error("no key with id {0} is published by the issuer")]
    UnknownKey(String),
    #[error("signature does not verify")]
    Signature,
    #[error("payload is not JSON, or omits a required claim")]
    BadPayload,
    #[error("issuer is {got}, expected {want}")]
    Issuer { got: String, want: String },
    #[error("audience is {got}, expected {want}")]
    Audience { got: String, want: String },
    #[error("token expired")]
    Expired,
    #[error("token is not valid yet")]
    NotYetValid,
}

/// The claims a verified access token carries.
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct Claims {
    /// The user this token speaks for.
    pub sub: String,
    /// The client the token was minted for; checked against ours.
    pub aud: String,
    /// The issuing service.
    pub iss: String,
    /// The session behind the token. A consuming app that needs
    /// instant revocation asks the auth service about this id; see the
    /// crate docs for why that is the exception rather than the rule.
    pub sid: String,
    pub exp: i64,
    pub iat: i64,
    #[serde(default)]
    pub email: Option<String>,
    #[serde(default)]
    pub email_verified: Option<bool>,
    /// Authentication methods used at login (RFC 8176).
    #[serde(default)]
    pub amr: Vec<String>,
    /// The enterprise SSO connection this session was signed in through
    /// (issue #627), present only while that connection belongs to the
    /// client the token was minted for — which is this one, or the
    /// audience check above would already have refused the token.
    ///
    /// `None` for every other way in, and for a token minted before the
    /// claim existed.
    #[serde(default)]
    pub sso_connection: Option<String>,
    /// When the person last authenticated in a real ceremony, epoch seconds
    /// (issue #912). `None` only for a token minted before the claim
    /// existed, which [`Claims::authenticated_within`] treats as not fresh.
    #[serde(default)]
    pub auth_time: Option<i64>,
    /// The account's roles in the issuing instance (issue #912), present
    /// only for a client the instance registered to receive them. Empty
    /// otherwise.
    #[serde(default)]
    pub roles: Vec<String>,
    /// The authentication context (`acr`), `urn:cratefield:stepup` when the
    /// session spent a step-up transaction (issue #912). Absent otherwise.
    #[serde(default)]
    pub acr: Option<String>,
}

impl Claims {
    /// Whether the person proved who they are with a passkey or an email link
    /// within the last `max_age_secs` seconds, measured from `now` (issue
    /// #912). This is the check a payment, signature or other irreversible
    /// approval gates on: a password, a federated sign-in or an old login does
    /// not pass it, however recent. `false` when the token has no `auth_time`.
    #[must_use]
    pub fn stepped_up_within(&self, max_age_secs: i64, now: i64) -> bool {
        self.authenticated_within(max_age_secs, now)
            && self
                .amr
                .iter()
                .any(|method| method == "passkey" || method == "email")
    }

    /// Whether the person authenticated within the last `max_age_secs`
    /// seconds, measured from `now` (epoch seconds, taken from the caller's
    /// clock). `false` when the token has no `auth_time`.
    ///
    /// A relying party that is about to approve something checks this itself.
    /// Verification establishes who signed the token, not how recently the
    /// person proved who they are.
    #[must_use]
    pub fn authenticated_within(&self, max_age_secs: i64, now: i64) -> bool {
        self.auth_time.is_some_and(|at| {
            let age = now - at;
            age >= -LEEWAY_SECS && age <= max_age_secs
        })
    }

    /// Whether this token came through one specific enterprise SSO
    /// connection, as opposed to any other way in.
    ///
    /// Both halves are required. A token that named the connection without
    /// `sso` in `amr` would be one from before the claim existed, or one
    /// minted by something that did not go through the SSO flow, and a
    /// caller that gates on enterprise membership should refuse both.
    #[must_use]
    pub fn signed_in_via_sso(&self, connection_id: &str) -> bool {
        self.sso_connection.as_deref() == Some(connection_id)
            && self.amr.iter().any(|method| method == "sso")
    }
}

/// The one `typ` an access token carries (RFC 9068). An ID token is signed
/// by the same key and has the same `aud`, so without this check it would
/// verify as an access token.
pub(crate) const ACCESS_TOKEN_TYPE: &str = "at+jwt";

#[derive(Deserialize)]
struct Header {
    alg: String,
    kid: String,
    #[serde(default)]
    typ: Option<String>,
}

/// The `kid` a token names, without verifying anything.
///
/// Used only to decide whether a forced JWKS refetch might help. A
/// caller must never act on this: it is attacker-controlled until the
/// signature verifies.
pub(crate) fn peek_kid(token: &str) -> Option<String> {
    let header = decode_header(token).ok()?;
    (header.alg == ALGORITHM).then_some(header.kid)
}

fn decode_header(token: &str) -> Result<Header, VerifyError> {
    let encoded = token.split('.').next().ok_or(VerifyError::Malformed)?;
    let bytes = Base64UrlUnpadded::decode_vec(encoded).map_err(|_| VerifyError::Malformed)?;
    serde_json::from_slice(&bytes).map_err(|_| VerifyError::BadHeader)
}

/// Verifies one token against the keys we hold.
///
/// `keys` maps `kid` to the public key published for it.
pub(crate) fn verify_with(
    token: &str,
    keys: &[(String, VerifyingKey)],
    issuer: &str,
    audience: &str,
    now: i64,
) -> Result<Claims, VerifyError> {
    let mut parts = token.split('.');
    let (Some(encoded_header), Some(encoded_payload), Some(encoded_signature), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return Err(VerifyError::Malformed);
    };

    let header: Header = {
        let bytes =
            Base64UrlUnpadded::decode_vec(encoded_header).map_err(|_| VerifyError::Malformed)?;
        serde_json::from_slice(&bytes).map_err(|_| VerifyError::BadHeader)?
    };

    // Algorithm first, before a key is even looked up: `none` and the
    // HMAC families are refused here rather than deeper in, so a token
    // asking us to verify it with the public key as a shared secret
    // never gets the chance.
    if header.alg != ALGORITHM {
        return Err(VerifyError::Algorithm(header.alg));
    }
    // Then the type: this crate verifies access tokens. An ID token has the
    // same signature and audience, and is refused here, before its claims
    // are read as if they were an access token's.
    if header.typ.as_deref() != Some(ACCESS_TOKEN_TYPE) {
        return Err(VerifyError::Type(header.typ.unwrap_or_default()));
    }

    let key = keys
        .iter()
        .find(|(kid, _)| *kid == header.kid)
        .map(|(_, key)| key)
        .ok_or_else(|| VerifyError::UnknownKey(header.kid.clone()))?;

    let signature_bytes =
        Base64UrlUnpadded::decode_vec(encoded_signature).map_err(|_| VerifyError::Malformed)?;
    let signature = Signature::from_slice(&signature_bytes).map_err(|_| VerifyError::Signature)?;
    let signing_input = format!("{encoded_header}.{encoded_payload}");
    key.verify(signing_input.as_bytes(), &signature)
        .map_err(|_| VerifyError::Signature)?;

    // Only now is anything in the payload worth reading.
    let payload_bytes =
        Base64UrlUnpadded::decode_vec(encoded_payload).map_err(|_| VerifyError::Malformed)?;
    let claims: Claims =
        serde_json::from_slice(&payload_bytes).map_err(|_| VerifyError::BadPayload)?;

    if claims.iss != issuer {
        return Err(VerifyError::Issuer {
            got: claims.iss,
            want: issuer.to_owned(),
        });
    }
    // The check every hand-rolled verifier forgets: a token minted for
    // another venture is signed by the same issuer with the same key,
    // and is valid in every respect except that it is not ours.
    if claims.aud != audience {
        return Err(VerifyError::Audience {
            got: claims.aud,
            want: audience.to_owned(),
        });
    }
    if now - LEEWAY_SECS >= claims.exp {
        return Err(VerifyError::Expired);
    }
    if claims.iat - LEEWAY_SECS > now {
        return Err(VerifyError::NotYetValid);
    }
    Ok(claims)
}

/// The SHA-256 of a token, for logging a token without logging it.
#[must_use]
pub fn token_fingerprint(token: &str) -> String {
    use std::fmt::Write as _;
    let digest = Sha256::digest(token.as_bytes());
    digest.iter().take(6).fold(String::new(), |mut out, byte| {
        let _ = write!(out, "{byte:02x}");
        out
    })
}
