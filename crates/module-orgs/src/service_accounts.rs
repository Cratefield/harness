//! Service accounts (issue #878): non-human principals an organization owns —
//! an agent, a CI job, an integration — and the API keys they authenticate
//! with.
//!
//! A service account is never a person. It has a name, a description, the
//! member who owns it (`owner_sub`, who answers for it) and the one who made
//! it (`created_by`), and it can be **disabled**, which refuses every key it
//! holds at once. It has no password, no sign-in and no session: the only
//! credential it ever has is a key from [`mint_key`].
//!
//! ## Keys
//!
//! A key is `{brand}_{id}_{secret}` — `brand` the venture's few lowercase
//! letters, `id` 16 hex characters, `secret` 64 hex characters (256 bits).
//! `{brand}_{id}` is the **prefix**: public, stored in the clear, the handle a
//! settings page shows and revokes by. The whole key reaches the table only as
//! its SHA-256, compared in constant time, so a dump or a query log holds
//! nothing that can be replayed. The key is returned exactly once, by
//! [`mint_key`] (and [`rotate_key`], which is a mint plus a revoke).
//!
//! [`verify_key`] is the one entry point: a malformed key, an unknown prefix,
//! a wrong secret, a revoked or expired key, a disabled or deleted account —
//! every one is `None`, because telling a caller *which* would tell a stranger
//! what exists.

use cratefield_core::{Database, DbError, Row, Statement, constant_time_eq};
use sha2::{Digest, Sha256};
use time::OffsetDateTime;

use crate::clock::{iso, parse};

/// The service accounts table.
pub const ACCOUNTS_TABLE: &str = "org_service_accounts";
/// The service account keys table.
pub const KEYS_TABLE: &str = "org_service_account_keys";

/// Random bytes in a key's id half.
const ID_BYTES: usize = 8;
/// Random bytes in a key's secret half: 256 bits.
const SECRET_BYTES: usize = 32;
/// The longest a name may be, in characters.
const MAX_NAME: usize = 100;
/// The longest a description may be, in characters.
const MAX_DESCRIPTION: usize = 1000;

/// One service account.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServiceAccount {
    /// Its id, chosen by the caller (`agt_…`, say).
    pub id: String,
    /// The organization it belongs to.
    pub org_id: String,
    /// What people call it.
    pub name: String,
    /// What it is for.
    pub description: String,
    /// The member who answers for it.
    pub owner_sub: String,
    /// The member who created it.
    pub created_by: String,
    /// When (RFC 3339).
    pub created_at: String,
    /// When it was disabled, or `None` while it is enabled.
    pub disabled_at: Option<String>,
}

impl ServiceAccount {
    /// Whether it may authenticate.
    #[must_use]
    pub fn is_enabled(&self) -> bool {
        self.disabled_at.is_none()
    }
}

/// One key, as a settings page lists it: never the secret, never its hash.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyInfo {
    /// The public prefix, `{brand}_{id}`.
    pub prefix: String,
    /// The account it belongs to.
    pub account_id: String,
    /// The label it was minted with.
    pub name: String,
    /// The space-separated scope list it was cut down to; empty for none.
    pub scopes: String,
    /// When it was minted.
    pub created_at: String,
    /// When it stops working, or `None`.
    pub expires_at: Option<String>,
    /// When it was revoked, or `None`.
    pub revoked_at: Option<String>,
    /// When it last authenticated a request, or `None`.
    pub last_used_at: Option<String>,
}

/// A freshly minted key: the only time the whole value exists.
///
/// `Debug` prints the prefix and never the key.
#[derive(Clone, PartialEq, Eq)]
pub struct MintedKey {
    /// The whole key — hand it to the caller once and drop it.
    pub key: String,
    /// What is stored and listed.
    pub info: KeyInfo,
}

impl std::fmt::Debug for MintedKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MintedKey")
            .field("prefix", &self.info.prefix)
            .finish_non_exhaustive()
    }
}

/// Who a verified key speaks for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyPrincipal {
    /// The account.
    pub account: ServiceAccount,
    /// The key's public prefix, for the audit trail.
    pub prefix: String,
    /// The key's scope list, `None` when it carries everything the account
    /// holds.
    pub scopes: Option<Vec<String>>,
}

/// What a create or mint asks for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewServiceAccount<'a> {
    /// Its id.
    pub id: &'a str,
    /// What people call it.
    pub name: &'a str,
    /// What it is for.
    pub description: &'a str,
    /// The member who answers for it.
    pub owner_sub: &'a str,
    /// The member creating it.
    pub created_by: &'a str,
}

/// Why a service account or key could not be written.
#[derive(Debug, thiserror::Error)]
pub enum ServiceAccountError {
    /// A name, description, id, brand or scope list outside its rules.
    #[error("{0}")]
    Invalid(&'static str),
    /// The account is not in this organization.
    #[error("no such service account")]
    NotFound,
    /// The entropy source failed.
    #[error("the entropy source failed")]
    Entropy,
    /// The database refused.
    #[error(transparent)]
    Db(#[from] DbError),
}

fn sha256_hex(value: &str) -> String {
    hex::encode(Sha256::digest(value.as_bytes()))
}

fn printable(value: &str, max: usize, allow_empty: bool) -> bool {
    (allow_empty || !value.trim().is_empty())
        && value.chars().count() <= max
        && !value.chars().any(char::is_control)
}

fn is_brand(brand: &str) -> bool {
    (2..=8).contains(&brand.len()) && brand.bytes().all(|byte| byte.is_ascii_lowercase())
}

fn is_lower_hex(value: &str) -> bool {
    value
        .bytes()
        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

/// Splits a key into its prefix, refusing a malformed one before it costs a
/// query.
fn split_key(key: &str) -> Option<&str> {
    let (prefix, secret) = key.rsplit_once('_')?;
    let (brand, id) = prefix.split_once('_')?;
    (is_brand(brand)
        && id.len() == ID_BYTES * 2
        && is_lower_hex(id)
        && secret.len() == SECRET_BYTES * 2
        && is_lower_hex(secret))
    .then_some(prefix)
}

fn text(row: &Row, name: &str) -> String {
    row.get::<String>(name).unwrap_or_default()
}

fn optional(row: &Row, name: &str) -> Option<String> {
    row.get::<String>(name).filter(|value| !value.is_empty())
}

const ACCOUNT_COLUMNS: &str =
    "id, org_id, name, description, owner_sub, created_by, created_at, disabled_at";

fn account_from(row: &Row) -> ServiceAccount {
    ServiceAccount {
        id: text(row, "id"),
        org_id: text(row, "org_id"),
        name: text(row, "name"),
        description: text(row, "description"),
        owner_sub: text(row, "owner_sub"),
        created_by: text(row, "created_by"),
        created_at: text(row, "created_at"),
        disabled_at: optional(row, "disabled_at"),
    }
}

const KEY_COLUMNS: &str =
    "prefix, account_id, name, scopes, created_at, expires_at, revoked_at, last_used_at";

fn key_from(row: &Row) -> KeyInfo {
    KeyInfo {
        prefix: text(row, "prefix"),
        account_id: text(row, "account_id"),
        name: text(row, "name"),
        scopes: text(row, "scopes"),
        created_at: text(row, "created_at"),
        expires_at: optional(row, "expires_at"),
        revoked_at: optional(row, "revoked_at"),
        last_used_at: optional(row, "last_used_at"),
    }
}

// ---------------------------------------------------------------------------
// Accounts

/// Creates a service account in `org_id`. The id is the caller's; a clash
/// with an existing one is the database's refusal.
///
/// # Errors
///
/// [`ServiceAccountError::Invalid`] for an empty or oversized name or id, an
/// oversized description, or control characters; [`ServiceAccountError::Db`]
/// otherwise.
pub async fn create(
    db: &dyn Database,
    org_id: &str,
    account: &NewServiceAccount<'_>,
    now: OffsetDateTime,
) -> Result<ServiceAccount, ServiceAccountError> {
    if !printable(account.id, 64, false) {
        return Err(ServiceAccountError::Invalid(
            "the id must be 1–64 printable characters",
        ));
    }
    if !printable(account.name, MAX_NAME, false) {
        return Err(ServiceAccountError::Invalid(
            "the name must be 1–100 printable characters",
        ));
    }
    if !printable(account.description, MAX_DESCRIPTION, true) {
        return Err(ServiceAccountError::Invalid(
            "the description must be at most 1000 printable characters",
        ));
    }
    let row = ServiceAccount {
        id: account.id.to_owned(),
        org_id: org_id.to_owned(),
        name: account.name.trim().to_owned(),
        description: account.description.trim().to_owned(),
        owner_sub: account.owner_sub.to_owned(),
        created_by: account.created_by.to_owned(),
        created_at: iso(now),
        disabled_at: None,
    };
    let statement = Statement::with_values(
        "INSERT INTO org_service_accounts \
           (id, org_id, name, description, owner_sub, created_by, created_at) \
         VALUES (?, ?, ?, ?, ?, ?, ?)",
        vec![
            row.id.as_str().into(),
            row.org_id.as_str().into(),
            row.name.as_str().into(),
            row.description.as_str().into(),
            row.owner_sub.as_str().into(),
            row.created_by.as_str().into(),
            row.created_at.as_str().into(),
        ],
    );
    db.execute(&statement).await?;
    Ok(row)
}

/// One service account, inside `org_id` only.
///
/// # Errors
///
/// [`DbError`] when the read fails.
pub async fn get(
    db: &dyn Database,
    org_id: &str,
    id: &str,
) -> Result<Option<ServiceAccount>, DbError> {
    let statement = Statement::with_values(
        format!("SELECT {ACCOUNT_COLUMNS} FROM org_service_accounts WHERE org_id = ? AND id = ?"),
        vec![org_id.into(), id.into()],
    );
    Ok(db.query(&statement).await?.first().map(account_from))
}

/// Every service account in `org_id`, oldest first; with `owner_sub`, only
/// that member's.
///
/// # Errors
///
/// [`DbError`] when the read fails.
pub async fn list(
    db: &dyn Database,
    org_id: &str,
    owner_sub: Option<&str>,
) -> Result<Vec<ServiceAccount>, DbError> {
    let statement = match owner_sub {
        None => Statement::with_values(
            format!(
                "SELECT {ACCOUNT_COLUMNS} FROM org_service_accounts WHERE org_id = ? \
                 ORDER BY created_at, id"
            ),
            vec![org_id.into()],
        ),
        Some(owner) => Statement::with_values(
            format!(
                "SELECT {ACCOUNT_COLUMNS} FROM org_service_accounts \
                 WHERE org_id = ? AND owner_sub = ? ORDER BY created_at, id"
            ),
            vec![org_id.into(), owner.into()],
        ),
    };
    Ok(db
        .query(&statement)
        .await?
        .rows
        .iter()
        .map(account_from)
        .collect())
}

/// Renames or re-describes an account. `None` leaves a field alone.
///
/// # Errors
///
/// [`ServiceAccountError::Invalid`] as [`create`];
/// [`ServiceAccountError::NotFound`] when no row in `org_id` has that id.
pub async fn update(
    db: &dyn Database,
    org_id: &str,
    id: &str,
    name: Option<&str>,
    description: Option<&str>,
) -> Result<(), ServiceAccountError> {
    if name.is_some_and(|name| !printable(name, MAX_NAME, false)) {
        return Err(ServiceAccountError::Invalid(
            "the name must be 1–100 printable characters",
        ));
    }
    if description.is_some_and(|text| !printable(text, MAX_DESCRIPTION, true)) {
        return Err(ServiceAccountError::Invalid(
            "the description must be at most 1000 printable characters",
        ));
    }
    let statement = Statement::with_values(
        "UPDATE org_service_accounts \
            SET name = COALESCE(?, name), description = COALESCE(?, description) \
          WHERE org_id = ? AND id = ?",
        vec![
            name.map(|name| name.trim().to_owned()).into(),
            description.map(|text| text.trim().to_owned()).into(),
            org_id.into(),
            id.into(),
        ],
    );
    if db.execute(&statement).await? == 0 {
        return Err(ServiceAccountError::NotFound);
    }
    Ok(())
}

/// Hands an account to another member. Keys are untouched; a venture that
/// wants a transfer to cut off the old owner's copies rotates them.
///
/// # Errors
///
/// [`ServiceAccountError::NotFound`] when no row in `org_id` has that id.
pub async fn set_owner(
    db: &dyn Database,
    org_id: &str,
    id: &str,
    owner_sub: &str,
) -> Result<(), ServiceAccountError> {
    let statement = Statement::with_values(
        "UPDATE org_service_accounts SET owner_sub = ? WHERE org_id = ? AND id = ?",
        vec![owner_sub.into(), org_id.into(), id.into()],
    );
    if db.execute(&statement).await? == 0 {
        return Err(ServiceAccountError::NotFound);
    }
    Ok(())
}

/// Disables (`true`) or re-enables (`false`) an account. A disabled account's
/// keys stop verifying at once; re-enabling brings back the ones that are
/// neither revoked nor expired.
///
/// # Errors
///
/// [`ServiceAccountError::NotFound`] when no row in `org_id` has that id.
pub async fn set_disabled(
    db: &dyn Database,
    org_id: &str,
    id: &str,
    disabled: bool,
    now: OffsetDateTime,
) -> Result<(), ServiceAccountError> {
    let at: Option<String> = disabled.then(|| iso(now));
    let statement = Statement::with_values(
        "UPDATE org_service_accounts SET disabled_at = ? WHERE org_id = ? AND id = ?",
        vec![at.into(), org_id.into(), id.into()],
    );
    if db.execute(&statement).await? == 0 {
        return Err(ServiceAccountError::NotFound);
    }
    Ok(())
}

/// Disables every account `owner_sub` owns in `org_id` and revokes all their
/// keys, in one transaction — what removing that member does, failing closed.
/// Answers how many accounts were disabled.
///
/// # Errors
///
/// [`DbError`] when the writes fail.
pub async fn disable_owned_by(
    db: &dyn Database,
    org_id: &str,
    owner_sub: &str,
    now: OffsetDateTime,
) -> Result<usize, DbError> {
    let owned = list(db, org_id, Some(owner_sub)).await?;
    let at = iso(now);
    db.batch_atomic(&[
        Statement::with_values(
            "UPDATE org_service_account_keys SET revoked_at = ? \
              WHERE org_id = ? AND revoked_at IS NULL AND account_id IN \
                (SELECT id FROM org_service_accounts WHERE org_id = ? AND owner_sub = ?)",
            vec![
                at.as_str().into(),
                org_id.into(),
                org_id.into(),
                owner_sub.into(),
            ],
        ),
        Statement::with_values(
            "UPDATE org_service_accounts SET disabled_at = ? \
              WHERE org_id = ? AND owner_sub = ? AND disabled_at IS NULL",
            vec![at.as_str().into(), org_id.into(), owner_sub.into()],
        ),
    ])
    .await?;
    Ok(owned.len())
}

/// Deletes an account and every key it held, in one transaction. Answers
/// whether the account existed.
///
/// # Errors
///
/// [`DbError`] when the writes fail.
pub async fn delete(db: &dyn Database, org_id: &str, id: &str) -> Result<bool, DbError> {
    let existed = get(db, org_id, id).await?.is_some();
    db.batch_atomic(&[
        Statement::with_values(
            "DELETE FROM org_service_account_keys WHERE org_id = ? AND account_id = ?",
            vec![org_id.into(), id.into()],
        ),
        Statement::with_values(
            "DELETE FROM org_service_accounts WHERE org_id = ? AND id = ?",
            vec![org_id.into(), id.into()],
        ),
    ])
    .await?;
    Ok(existed)
}

// ---------------------------------------------------------------------------
// Keys

fn random_hex(bytes: usize) -> Result<String, ServiceAccountError> {
    let mut buffer = vec![0_u8; bytes];
    getrandom::fill(&mut buffer).map_err(|_| ServiceAccountError::Entropy)?;
    Ok(hex::encode(buffer))
}

/// What a key is minted with.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewKey<'a> {
    /// The venture's key brand: 2–8 lowercase ASCII letters (`lba`, say).
    pub brand: &'a str,
    /// A label for the settings list.
    pub name: &'a str,
    /// A space-separated scope list in the venture's vocabulary, or `None`
    /// for a key that carries everything its account holds.
    pub scopes: Option<&'a str>,
    /// When the key stops working, or `None`.
    pub expires_at: Option<OffsetDateTime>,
}

/// Mints a key for `account_id` in `org_id` and returns it — the only time it
/// is ever returned. Refused for a disabled account, so a disabled account
/// cannot be given a credential that works the moment it is re-enabled
/// without anybody noticing.
///
/// # Errors
///
/// [`ServiceAccountError::NotFound`] for an account that is not in `org_id`
/// or is disabled; [`ServiceAccountError::Invalid`] for a bad brand, label or
/// an empty scope list (an explicit `Some("")` would read as "everything");
/// [`ServiceAccountError::Entropy`] or [`ServiceAccountError::Db`] otherwise.
pub async fn mint_key(
    db: &dyn Database,
    org_id: &str,
    account_id: &str,
    key: &NewKey<'_>,
    now: OffsetDateTime,
) -> Result<MintedKey, ServiceAccountError> {
    if !is_brand(key.brand) {
        return Err(ServiceAccountError::Invalid(
            "the brand must be 2–8 lowercase ASCII letters",
        ));
    }
    if !printable(key.name, MAX_NAME, true) {
        return Err(ServiceAccountError::Invalid(
            "the label must be at most 100 printable characters",
        ));
    }
    let scopes = match key.scopes {
        None => String::new(),
        Some(scopes) => {
            let normalized = scopes.split_whitespace().collect::<Vec<_>>().join(" ");
            if normalized.is_empty() || !printable(&normalized, 4000, false) {
                return Err(ServiceAccountError::Invalid(
                    "a scope list names at least one scope, in printable characters",
                ));
            }
            normalized
        }
    };
    match get(db, org_id, account_id).await? {
        Some(account) if account.is_enabled() => {}
        _ => return Err(ServiceAccountError::NotFound),
    }
    let prefix = format!("{}_{}", key.brand, random_hex(ID_BYTES)?);
    let whole = format!("{prefix}_{}", random_hex(SECRET_BYTES)?);
    let info = KeyInfo {
        prefix: prefix.clone(),
        account_id: account_id.to_owned(),
        name: key.name.trim().to_owned(),
        scopes,
        created_at: iso(now),
        expires_at: key.expires_at.map(iso),
        revoked_at: None,
        last_used_at: None,
    };
    let statement = Statement::with_values(
        "INSERT INTO org_service_account_keys \
           (prefix, secret_hash, account_id, org_id, name, scopes, created_at, expires_at) \
         VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        vec![
            prefix.as_str().into(),
            sha256_hex(&whole).into(),
            account_id.into(),
            org_id.into(),
            info.name.as_str().into(),
            info.scopes.as_str().into(),
            info.created_at.as_str().into(),
            info.expires_at.clone().into(),
        ],
    );
    db.execute(&statement).await?;
    Ok(MintedKey { key: whole, info })
}

/// Every key `account_id` holds in `org_id`, newest first, revoked ones
/// included.
///
/// # Errors
///
/// [`DbError`] when the read fails.
pub async fn keys(
    db: &dyn Database,
    org_id: &str,
    account_id: &str,
) -> Result<Vec<KeyInfo>, DbError> {
    let statement = Statement::with_values(
        format!(
            "SELECT {KEY_COLUMNS} FROM org_service_account_keys \
             WHERE org_id = ? AND account_id = ? ORDER BY created_at DESC, prefix"
        ),
        vec![org_id.into(), account_id.into()],
    );
    Ok(db
        .query(&statement)
        .await?
        .rows
        .iter()
        .map(key_from)
        .collect())
}

/// Revokes one key of `account_id` in `org_id`. Answers whether a live key
/// was revoked; revoking twice is not an error.
///
/// # Errors
///
/// [`DbError`] when the write fails.
pub async fn revoke_key(
    db: &dyn Database,
    org_id: &str,
    account_id: &str,
    prefix: &str,
    now: OffsetDateTime,
) -> Result<bool, DbError> {
    let statement = Statement::with_values(
        "UPDATE org_service_account_keys SET revoked_at = ? \
          WHERE org_id = ? AND account_id = ? AND prefix = ? AND revoked_at IS NULL",
        vec![
            iso(now).into(),
            org_id.into(),
            account_id.into(),
            prefix.into(),
        ],
    );
    Ok(db.execute(&statement).await? > 0)
}

/// Mints a replacement for one key — same label, scopes and expiry — and
/// revokes the old one. The new key is returned once.
///
/// # Errors
///
/// [`ServiceAccountError::NotFound`] when the old key is not a live key of
/// that account, or the account is disabled; otherwise as [`mint_key`].
pub async fn rotate_key(
    db: &dyn Database,
    org_id: &str,
    account_id: &str,
    prefix: &str,
    brand: &str,
    now: OffsetDateTime,
) -> Result<MintedKey, ServiceAccountError> {
    let old = keys(db, org_id, account_id)
        .await?
        .into_iter()
        .find(|key| key.prefix == prefix && key.revoked_at.is_none())
        .ok_or(ServiceAccountError::NotFound)?;
    let expires_at = old.expires_at.as_deref().map(parse).filter(|at| *at > now);
    if old.expires_at.is_some() && expires_at.is_none() {
        return Err(ServiceAccountError::NotFound);
    }
    let minted = mint_key(
        db,
        org_id,
        account_id,
        &NewKey {
            brand,
            name: &old.name,
            scopes: (!old.scopes.is_empty()).then_some(old.scopes.as_str()),
            expires_at,
        },
        now,
    )
    .await?;
    revoke_key(db, org_id, account_id, prefix, now).await?;
    Ok(minted)
}

/// Verifies a presented key and resolves the account it speaks for, stamping
/// `last_used_at`. `None` for every refusal: malformed, unknown, wrong secret,
/// revoked, expired, account disabled or gone.
///
/// The organization is the key row's own, never the caller's input: a key is
/// a credential for exactly one organization.
///
/// # Errors
///
/// [`DbError`] when a read fails. A failed `last_used_at` stamp is not an
/// error: the key verified, and a bookkeeping write must not refuse it.
pub async fn verify_key(
    db: &dyn Database,
    key: &str,
    now: OffsetDateTime,
) -> Result<Option<KeyPrincipal>, DbError> {
    let Some(prefix) = split_key(key) else {
        return Ok(None);
    };
    let statement = Statement::with_values(
        "SELECT secret_hash, org_id, account_id, scopes, expires_at, revoked_at \
           FROM org_service_account_keys WHERE prefix = ?",
        vec![prefix.into()],
    );
    let rows = db.query(&statement).await?;
    let Some(row) = rows.first() else {
        return Ok(None);
    };
    let expected = text(row, "secret_hash");
    if expected.is_empty()
        || !constant_time_eq(expected.as_bytes(), sha256_hex(key).as_bytes())
        || optional(row, "revoked_at").is_some()
        || optional(row, "expires_at").is_some_and(|at| parse(&at) <= now)
    {
        return Ok(None);
    }
    let org_id = text(row, "org_id");
    let Some(account) = get(db, &org_id, &text(row, "account_id")).await? else {
        return Ok(None);
    };
    if !account.is_enabled() {
        return Ok(None);
    }
    let scopes = text(row, "scopes");
    let scopes =
        (!scopes.is_empty()).then(|| scopes.split_whitespace().map(str::to_owned).collect());
    let stamp = Statement::with_values(
        "UPDATE org_service_account_keys SET last_used_at = ? WHERE prefix = ?",
        vec![iso(now).into(), prefix.into()],
    );
    let _ = db.execute(&stamp).await;
    Ok(Some(KeyPrincipal {
        account,
        prefix: prefix.to_owned(),
        scopes,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_key_splits_only_in_its_one_shape() {
        let id = "ab".repeat(ID_BYTES);
        let secret = "cd".repeat(SECRET_BYTES);
        let key = format!("lba_{id}_{secret}");
        assert_eq!(split_key(&key), Some(format!("lba_{id}").as_str()));
        assert_eq!(split_key(&format!("LBA_{id}_{secret}")), None);
        assert_eq!(split_key(&format!("lba_{id}_{}", "CD".repeat(32))), None);
        assert_eq!(split_key(&format!("lba_{id}")), None);
        assert_eq!(split_key(&format!("lba_{id}x_{secret}")), None);
        assert_eq!(split_key(""), None);
    }

    #[test]
    fn a_minted_key_debug_shows_only_the_prefix() {
        let minted = MintedKey {
            key: "lba_secretvalue".to_owned(),
            info: KeyInfo {
                prefix: "lba_0011".to_owned(),
                account_id: "a".to_owned(),
                name: String::new(),
                scopes: String::new(),
                created_at: String::new(),
                expires_at: None,
                revoked_at: None,
                last_used_at: None,
            },
        };
        let shown = format!("{minted:?}");
        assert!(shown.contains("lba_0011"));
        assert!(!shown.contains("secretvalue"));
    }
}
