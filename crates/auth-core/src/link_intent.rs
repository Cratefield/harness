//! The venture-side record of a Factory Zero link request (venture linking).
//!
//! The control panel's Link button opens the venture's `factory-zero/start`
//! with `intent=link`. A link needs a live venture session to attach to. A
//! person without one is shown the venture's sign-in first, and the link is
//! resumed after they sign in. That resume has to be single use and short
//! lived, so the intent is a row of `single_use_tokens` (kind `link_intent`)
//! whose id is named by a signed token that `cratefield-auth-oidc` seals and
//! checks. This module owns only the row. Spending it is a guarded update,
//! so two presentations of one token cannot both win.
//!
//! Nothing here decides linking. The linking rules in [`crate::linking`] are
//! unchanged, and a resumed link still goes through them.

use cratefield_core::{Clock, Database, DbError};
use sha2::{Digest, Sha256};
use time::Duration;

use crate::sessions::iso;
use crate::store::{self, Redacted, SingleUseTokenRow, TOKEN_LINK_INTENT};

/// How long a person has to sign in to the venture before the link lapses.
pub const LINK_INTENT_TTL_SECS: i64 = 600;

/// Records a link intent under `id`, which the caller generated and signed.
///
/// # Errors
///
/// [`DbError`] when the row cannot be written.
pub async fn issue(db: &dyn Database, clock: &dyn Clock, id: &str) -> Result<(), DbError> {
    let expires = clock.now() + Duration::seconds(LINK_INTENT_TTL_SECS);
    store::insert_single_use_token(
        db,
        &SingleUseTokenRow {
            id: id.to_owned(),
            kind: TOKEN_LINK_INTENT.to_owned(),
            token_hash: Redacted(Sha256::digest(id.as_bytes()).to_vec()),
            user_id: None,
            client_id: None,
            payload: None,
            expires_at: iso(expires),
            consumed_at: None,
        },
    )
    .await
}

/// Spends the intent `id`. `true` only for the one caller that wins: the
/// row must exist, be a link intent, be unspent, and not have expired.
///
/// # Errors
///
/// [`DbError`] when the database cannot be read or updated.
pub async fn spend(db: &dyn Database, clock: &dyn Clock, id: &str) -> Result<bool, DbError> {
    let now = iso(clock.now());
    let Some(row) = store::consume_single_use_token(db, id, &now).await? else {
        return Ok(false);
    };
    Ok(row.kind == TOKEN_LINK_INTENT)
}
