//! Challenge storage (issues #13, #14).
//!
//! A WebAuthn challenge is exactly the kind of thing the architecture says
//! must not live in KV: it has to be single-use, and eventual consistency
//! would let a replay through. So it is a `single_use_tokens` row, consumed
//! by auth-core's conditional update, whose affected-row count decides which
//! of two concurrent attempts wins.
//!
//! Only the hash is stored. The challenge itself exists in the response to
//! the options call and in the authenticator's signature, and nowhere else.

use cratefield_core::{Clock, Database, DbError, IdGen};
use factory0_auth_core::{
    Bytes, Redacted, SingleUseTokenRow, TOKEN_WEBAUTHN_CHALLENGE, consume_single_use_token,
    insert_single_use_token, single_use_token_by_hash,
};
use sha2::{Digest, Sha256};

/// Registration and login challenges are not interchangeable: a challenge
/// issued to add a passkey to a signed-in account must never be spendable as
/// a login.
pub(crate) const PURPOSE_REGISTER: &str = "register";
pub(crate) const PURPOSE_LOGIN: &str = "login";

/// 32 bytes, the size the spec recommends and every browser expects.
const CHALLENGE_BYTES: usize = 32;

#[derive(Debug, thiserror::Error)]
pub(crate) enum ChallengeError {
    #[error("no entropy available: {0}")]
    Entropy(String),
    #[error(transparent)]
    Db(#[from] DbError),
}

/// What a consumed challenge carried. `user_id` is set for a registration,
/// and for a login that named an account; a discoverable-credential login
/// leaves it empty because the authenticator has not spoken yet.
pub(crate) struct Consumed {
    pub user_id: Option<String>,
}

fn hash(challenge: &[u8]) -> Vec<u8> {
    Sha256::digest(challenge).to_vec()
}

fn payload(purpose: &str) -> String {
    serde_json::json!({ "purpose": purpose }).to_string()
}

fn purpose_of(row: &SingleUseTokenRow) -> Option<String> {
    let raw = row.payload.as_deref()?;
    serde_json::from_str::<serde_json::Value>(raw)
        .ok()?
        .get("purpose")?
        .as_str()
        .map(str::to_owned)
}

/// Issues a fresh challenge and stores its hash. Returns the raw bytes,
/// which the caller sends to the browser and never stores.
pub(crate) async fn issue(
    db: &dyn Database,
    clock: &dyn Clock,
    id_gen: &dyn IdGen,
    purpose: &str,
    user_id: Option<&str>,
    ttl_secs: i64,
) -> Result<Vec<u8>, ChallengeError> {
    let mut challenge = [0u8; CHALLENGE_BYTES];
    getrandom::fill(&mut challenge).map_err(|err| ChallengeError::Entropy(err.to_string()))?;

    let expires_at = clock
        .now()
        .saturating_add(time::Duration::seconds(ttl_secs));
    insert_single_use_token(
        db,
        &SingleUseTokenRow {
            id: id_gen.ulid(),
            kind: TOKEN_WEBAUTHN_CHALLENGE.to_owned(),
            token_hash: Redacted(hash(&challenge)),
            user_id: user_id.map(str::to_owned),
            client_id: None,
            payload: Some(payload(purpose)),
            expires_at: crate::iso(expires_at),
            consumed_at: None,
        },
    )
    .await?;
    Ok(challenge.to_vec())
}

/// Spends a challenge. `Ok(None)` covers every way a challenge can be
/// unusable — unknown, expired, already spent, or issued for the other
/// ceremony — because the caller answers all of them identically.
pub(crate) async fn consume(
    db: &dyn Database,
    clock: &dyn Clock,
    purpose: &str,
    presented: &[u8],
) -> Result<Option<Consumed>, ChallengeError> {
    let Some(row) = single_use_token_by_hash(db, &hash(presented)).await? else {
        return Ok(None);
    };
    if row.kind != TOKEN_WEBAUTHN_CHALLENGE {
        return Ok(None);
    }
    let now = crate::iso(clock.now());
    // The conditional update is the single-use guarantee: expiry and
    // prior consumption are both checked inside it.
    let Some(consumed) = consume_single_use_token(db, &row.id, &now).await? else {
        return Ok(None);
    };
    if purpose_of(&consumed).as_deref() != Some(purpose) {
        // Spent, and deliberately not returned: a registration challenge
        // presented at login is burned rather than left for a second try.
        return Ok(None);
    }
    Ok(Some(Consumed {
        user_id: consumed.user_id,
    }))
}

/// The stored credential id, as the database holds it.
pub(crate) fn credential_id_bytes(value: &Bytes) -> &[u8] {
    &value.0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_payload_round_trips_its_purpose() {
        let row = SingleUseTokenRow {
            id: "t".to_owned(),
            kind: TOKEN_WEBAUTHN_CHALLENGE.to_owned(),
            token_hash: Redacted(Vec::new()),
            user_id: None,
            client_id: None,
            payload: Some(payload(PURPOSE_LOGIN)),
            expires_at: String::new(),
            consumed_at: None,
        };
        assert_eq!(purpose_of(&row).as_deref(), Some(PURPOSE_LOGIN));
    }

    #[test]
    fn a_row_without_a_readable_purpose_is_not_usable() {
        let mut row = SingleUseTokenRow {
            id: "t".to_owned(),
            kind: TOKEN_WEBAUTHN_CHALLENGE.to_owned(),
            token_hash: Redacted(Vec::new()),
            user_id: None,
            client_id: None,
            payload: None,
            expires_at: String::new(),
            consumed_at: None,
        };
        assert_eq!(purpose_of(&row), None);
        row.payload = Some("not json".to_owned());
        assert_eq!(purpose_of(&row), None);
        row.payload = Some(r#"{"purpose":42}"#.to_owned());
        assert_eq!(purpose_of(&row), None);
    }

    #[test]
    fn the_hash_is_what_is_stored_not_the_challenge() {
        let challenge = b"a-challenge";
        let stored = hash(challenge);
        assert_eq!(stored.len(), 32);
        assert_ne!(stored.as_slice(), challenge.as_slice());
    }
}
