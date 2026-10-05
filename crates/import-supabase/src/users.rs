//! Step two of moving a Supabase project onto the harness (issue #659):
//! read `auth.users` and `auth.identities` through the same read-only
//! snapshot [`crate::ReadOnlySession`] gives `inspect`, and shape them into
//! the admin import contract — `POST /v1/auth-core/admin/users/import`
//! (`cratefield-auth-core`).
//!
//! A user becomes an [`ImportRecord`]: `external_provider` `supabase`,
//! `external_id` the `auth.users.id`, the address and whether the source
//! confirmed it, the bcrypt hash when the source has one, and the OIDC
//! links the harness can hold. Password hashes are bcrypt `$2a$`/`$2b$`/
//! `$2y$` only and are carried verbatim; the login path upgrades them to
//! argon2id on the first sign-in. A user created through Supabase's admin
//! API has a random bcrypt hash we cannot tell apart from a real one, so it
//! passes through too — harmless, and it upgrades the same way.
//!
//! What the harness cannot hold is reported, not guessed: a phone-only or
//! anonymous account is [`SkippedUser`], and an OAuth identity the harness
//! has no slug for (GitHub, today) or the caller did not list is an
//! [`UnmappedProvider`] — those people sign in by magic link.
//!
//! The [`UserMetadata`] read here does not go to auth (harness accounts
//! have no metadata column yet); it goes to the source-to-account mapping
//! table [`record_mapping`] writes, which step three rewrites the copied
//! data through.

use std::collections::{BTreeMap, BTreeSet};
use std::str::FromStr as _;

use serde::Serialize;
use serde_json::Value;
use sqlx::Connection as _;
use sqlx::postgres::{PgConnectOptions, PgConnection};

use crate::collect::{column_exists, relation_exists};
use crate::secret::Secret;
use crate::session::{InspectError, ReadOnlySession};

/// The `external_provider` every record carries: the source system, so a
/// re-run and another source's ids never collide.
pub const EXTERNAL_PROVIDER: &str = "supabase";

/// Users read per keyset page when none is set on [`UsersOptions`].
pub const DEFAULT_BATCH_SIZE: usize = 500;

/// The mapping table, in the target database. `account_id` is deliberately
/// not unique: `--merge-by-email` maps several source users to one account,
/// so the source id is the only key.
const CREATE_MAPPING_TABLE: &str = "CREATE TABLE IF NOT EXISTS import_supabase_users (\
     supabase_id uuid PRIMARY KEY, account_id text NOT NULL, user_metadata jsonb, \
     app_metadata jsonb, imported_at timestamptz NOT NULL DEFAULT now())";

/// What [`read_users`] needs.
pub struct UsersOptions {
    /// The source database URL, ideally for the read-only role.
    pub db_url: Secret,
    /// Rows per keyset page; the pages are one snapshot regardless.
    pub batch_size: usize,
    /// The Supabase OAuth providers the caller can carry over: an identity
    /// of any other provider is reported unmapped.
    pub oidc_providers: BTreeSet<String>,
}

impl UsersOptions {
    /// Options that read [`DEFAULT_BATCH_SIZE`] a page and map no provider.
    #[must_use]
    pub fn new(db_url: Secret) -> Self {
        Self {
            db_url,
            batch_size: DEFAULT_BATCH_SIZE,
            oidc_providers: BTreeSet::new(),
        }
    }
}

/// One user in the admin import contract. `Debug` prints ids, flags and
/// counts only — never the address, a subject or the hash; the JSON carries
/// the address and the hash for the import to store.
#[derive(Clone, Serialize)]
pub struct ImportRecord {
    /// Always [`EXTERNAL_PROVIDER`].
    pub external_provider: &'static str,
    /// The `auth.users.id`, as text.
    pub external_id: String,
    pub email: String,
    pub email_verified: bool,
    /// Verbatim, when the source has one.
    #[serde(
        skip_serializing_if = "Option::is_none",
        serialize_with = "serialize_password_hash"
    )]
    pub password_hash: Option<Secret>,
    /// RFC 3339, when the row has one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub created_at: Option<String>,
    pub identities: Vec<ImportIdentity>,
}

/// One OIDC link for [`ImportRecord::identities`]: the harness slug and the
/// source's `sub`.
#[derive(Debug, Clone, Serialize)]
pub struct ImportIdentity {
    pub provider: String,
    pub subject: String,
}

// Hand-written so a stray `{:?}` on a record cannot disclose an address or a
// subject: the address is not printed, the subjects are a count, and the
// hash is a `Secret` (`Some([redacted])`).
#[allow(clippy::missing_fields_in_debug)] // `email` is deliberately omitted
impl std::fmt::Debug for ImportRecord {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ImportRecord")
            .field("external_provider", &self.external_provider)
            .field("external_id", &self.external_id)
            .field("email_verified", &self.email_verified)
            .field("password_hash", &self.password_hash)
            .field("created_at", &self.created_at)
            .field("identities", &self.identities.len())
            .finish()
    }
}

// `serialize_with` fixes the receiver to `&Option<Secret>`.
#[allow(clippy::ref_option)]
fn serialize_password_hash<S: serde::Serializer>(
    value: &Option<Secret>,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    match value {
        Some(secret) => serializer.serialize_str(secret.expose()),
        None => serializer.serialize_none(),
    }
}

/// A user's source-side metadata (`raw_user_meta_data` /
/// `raw_app_meta_data`): carried to the mapping table, never to the harness,
/// whose accounts have no metadata column yet. No `Debug`: the values are
/// the source's own, so a stray `{:?}` must not print them.
#[derive(Clone)]
pub struct UserMetadata {
    pub supabase_id: String,
    pub user_metadata: Option<Value>,
    pub app_metadata: Option<Value>,
}

impl UserMetadata {
    /// The mapping row for the account the import created for this user.
    #[must_use]
    pub fn mapping(&self, account_id: impl Into<String>) -> MappedUser {
        MappedUser {
            supabase_id: self.supabase_id.clone(),
            account_id: account_id.into(),
            user_metadata: self.user_metadata.clone(),
            app_metadata: self.app_metadata.clone(),
        }
    }
}

/// Why a user is not imported.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum SkipReason {
    /// A phone-only (or empty) account.
    NoEmail,
    /// An anonymous (guest) account.
    Anonymous,
}

impl SkipReason {
    /// The stable slug a report names it by.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::NoEmail => "no-email",
            Self::Anonymous => "anonymous",
        }
    }
}

/// A user not imported, and why.
#[derive(Debug, Clone, Serialize)]
pub struct SkippedUser {
    pub supabase_id: String,
    pub reason: SkipReason,
}

/// One Supabase OAuth provider none of whose identities were linked, with
/// the users left to sign in by magic link.
#[derive(Debug, Clone, Serialize)]
pub struct UnmappedProvider {
    pub provider: String,
    pub supabase_ids: Vec<String>,
}

/// Everything [`read_users`] read, in `auth.users.id` order; every count is
/// exact (the whole table, not a page of it). `Debug` prints counts only —
/// never a record, an address or the metadata.
#[derive(Default)]
pub struct ImportPlan {
    pub records: Vec<ImportRecord>,
    /// Their metadata, one entry per record, in id order — built by
    /// `plan_user`, which pushes the pair together, so index `n` of
    /// `metadata` is index `n` of `records`. [`ImportPlan::users`] is the
    /// pairing.
    pub metadata: Vec<UserMetadata>,
    pub skipped: Vec<SkippedUser>,
    pub unmapped: Vec<UnmappedProvider>,
}

impl ImportPlan {
    /// Each record with the metadata read alongside it, one pair per user in
    /// id order.
    pub fn users(&self) -> impl Iterator<Item = (&ImportRecord, &UserMetadata)> {
        debug_assert_eq!(
            self.records.len(),
            self.metadata.len(),
            "every record has its metadata"
        );
        self.records.iter().zip(&self.metadata)
    }
}

// Counts, not the values: a plan holds every address and every metadata blob
// the source has, and a `{:?}` on the error path must not print them.
impl std::fmt::Debug for ImportPlan {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ImportPlan")
            .field("records", &self.records.len())
            .field("metadata", &self.metadata.len())
            .field("skipped", &self.skipped.len())
            .field("unmapped", &self.unmapped.len())
            .finish()
    }
}

/// Reads the source's auth users through one read-only snapshot and plans
/// their import.
///
/// # Errors
///
/// [`InspectError::Permission`] when `auth.users` or `auth.identities` has
/// row-level security this role cannot bypass — a read would silently
/// return no rows, so it is refused instead; [`InspectError::Query`] when
/// the `auth` schema is missing; [`InspectError::Connect`] when the
/// database cannot be reached. No message carries a row value.
pub async fn read_users(options: &UsersOptions) -> Result<ImportPlan, InspectError> {
    let mut session = ReadOnlySession::open(&options.db_url).await?;
    guard_auth(&mut session).await?;
    let anonymous = column_exists(&mut session, "auth", "users", "is_anonymous").await?;
    // `provider_id` (a uuid) replaced `identity_data->>'sub'`; either works.
    let subject = if column_exists(&mut session, "auth", "identities", "provider_id").await? {
        "coalesce(provider_id, '')"
    } else {
        "coalesce(identity_data->>'sub', '')"
    };

    let mut plan = ImportPlan::default();
    let mut unmapped: BTreeMap<String, Vec<String>> = BTreeMap::new();
    // Keyset pagination over the whole table, so every page sees the one
    // snapshot and no row is read twice.
    let mut after = "00000000-0000-0000-0000-000000000000".to_owned();
    loop {
        let rows = fetch_users(&mut session, &after, options.batch_size.max(1), anonymous).await?;
        let Some(last) = rows.last() else { break };
        after.clone_from(&last.0);
        let mut identities = fetch_identities(&mut session, &rows, subject).await?;
        for row in rows {
            let links = identities.remove(&row.0).unwrap_or_default();
            plan_user(&mut plan, &mut unmapped, row, links, options);
        }
    }
    plan.unmapped = unmapped
        .into_iter()
        .map(|(provider, supabase_ids)| UnmappedProvider {
            provider,
            supabase_ids,
        })
        .collect();
    session.finish().await?;
    Ok(plan)
}

/// Refuses before reading a row when RLS on an auth table would hide rows
/// from this role without saying so — the silent-zero trap `inspect`
/// reports for `storage.objects` (`collect::read_storage`).
async fn guard_auth(session: &mut ReadOnlySession) -> Result<(), InspectError> {
    for table in ["auth.users", "auth.identities"] {
        if !relation_exists(session, table).await? {
            return Err(InspectError::Query(format!(
                "the source has no {table} table, so there is no Supabase auth to move"
            )));
        }
        let hidden: bool = sqlx::query_scalar(
            "SELECT c.relrowsecurity AND NOT (r.rolsuper OR r.rolbypassrls) AND \
             (c.relforcerowsecurity OR NOT pg_has_role(c.relowner, 'USAGE')) FROM pg_class c JOIN \
             pg_roles r ON r.rolname = current_user WHERE c.oid = to_regclass($1)",
        )
        .bind(table)
        .fetch_one(&mut session.conn)
        .await
        .map_err(|error| session.error(&error))?;
        if hidden {
            return Err(InspectError::Permission(format!(
                "{table} has row-level security and this role cannot bypass it, so the read \
                 would silently return no rows; use a role with BYPASSRLS for the import (an \
                 owner is exempt only when the table is not FORCE ROW LEVEL SECURITY)"
            )));
        }
    }
    Ok(())
}

/// One page's `auth.users` columns, in [`fetch_users`]' select order: id,
/// email, confirmed, hash, `created_at` (RFC 3339), the two jsonb texts, guest.
type UserRow = (
    String,
    Option<String>,
    bool,
    Option<String>,
    Option<String>,
    Option<String>,
    Option<String>,
    bool,
);

async fn fetch_users(
    session: &mut ReadOnlySession,
    after: &str,
    limit: usize,
    anonymous: bool,
) -> Result<Vec<UserRow>, InspectError> {
    let is_anonymous = if anonymous {
        "coalesce(is_anonymous, false)"
    } else {
        "false"
    };
    // `to_char` rather than the driver's own decoding: the text is RFC 3339
    // whatever the session's time zone.
    let rows: Vec<UserRow> = sqlx::query_as(&format!(
        "SELECT id::text, email, email_confirmed_at IS NOT NULL, encrypted_password, \
         to_char(created_at AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS') || 'Z', \
         raw_user_meta_data::text, raw_app_meta_data::text, {is_anonymous} FROM auth.users \
         WHERE id > $1::uuid ORDER BY id LIMIT $2"
    ))
    .bind(after)
    .bind(i64::try_from(limit).unwrap_or(i64::MAX))
    .fetch_all(&mut session.conn)
    .await
    .map_err(|error| session.error(&error))?;
    Ok(rows)
}

/// The identities of the users in one page, keyed by user id.
async fn fetch_identities(
    session: &mut ReadOnlySession,
    rows: &[UserRow],
    subject: &str,
) -> Result<BTreeMap<String, Vec<(String, String)>>, InspectError> {
    let ids = rows
        .iter()
        .map(|row| row.0.as_str())
        .collect::<Vec<_>>()
        .join(",");
    let identities: Vec<(String, String, String)> = sqlx::query_as(&format!(
        "SELECT user_id::text, provider::text, {subject} FROM auth.identities WHERE user_id = \
         ANY(string_to_array($1, ',')::uuid[]) ORDER BY user_id, provider"
    ))
    .bind(ids)
    .fetch_all(&mut session.conn)
    .await
    .map_err(|error| session.error(&error))?;
    let mut by_user: BTreeMap<String, Vec<(String, String)>> = BTreeMap::new();
    for (user_id, provider, subject) in identities {
        by_user
            .entry(user_id)
            .or_default()
            .push((provider, subject));
    }
    Ok(by_user)
}

fn plan_user(
    plan: &mut ImportPlan,
    unmapped: &mut BTreeMap<String, Vec<String>>,
    row: UserRow,
    identities: Vec<(String, String)>,
    options: &UsersOptions,
) {
    let (id, email, email_confirmed, password, created_at, user_metadata, app_metadata, guest) =
        row;
    let email = match email {
        Some(email) if !email.is_empty() && !guest => email,
        _ => {
            let reason = if guest {
                SkipReason::Anonymous
            } else {
                SkipReason::NoEmail
            };
            plan.skipped.push(SkippedUser {
                supabase_id: id,
                reason,
            });
            return;
        }
    };

    let mut links = Vec::new();
    for (provider, subject) in identities {
        // `email`/`phone` are not OAuth: nothing is lost, so not unmapped.
        if matches!(provider.as_str(), "email" | "phone") {
            continue;
        }
        match oidc_slug(&provider) {
            Some(slug) if !subject.is_empty() && options.oidc_providers.contains(&provider) => {
                links.push(ImportIdentity {
                    provider: slug.to_owned(),
                    subject,
                });
            }
            _ => unmapped.entry(provider).or_default().push(id.clone()),
        }
    }

    plan.metadata.push(UserMetadata {
        supabase_id: id.clone(),
        user_metadata: parse_json(user_metadata),
        app_metadata: parse_json(app_metadata),
    });
    plan.records.push(ImportRecord {
        external_provider: EXTERNAL_PROVIDER,
        external_id: id,
        email,
        email_verified: email_confirmed,
        password_hash: password.filter(|hash| is_bcrypt(hash)).map(Secret::new),
        created_at,
        identities: links,
    });
}

/// The harness slug for a Supabase OAuth provider, or `None` when it has
/// none (GitHub, today). Supabase spells Meta's provider `facebook`.
fn oidc_slug(provider: &str) -> Option<&'static str> {
    match provider {
        "google" => Some("google"),
        "apple" => Some("apple"),
        "facebook" => Some("meta"),
        _ => None,
    }
}

/// Only these prefixes are bcrypt; anything else the harness refuses, so it
/// is not worth sending.
fn is_bcrypt(hash: &str) -> bool {
    hash.starts_with("$2a$") || hash.starts_with("$2b$") || hash.starts_with("$2y$")
}

/// jsonb is read as text: the workspace pins sqlx without its json support,
/// and `serde_json` parses what the database guarantees valid.
fn parse_json(text: Option<String>) -> Option<Value> {
    text.and_then(|text| serde_json::from_str(&text).ok())
}

/// One row for the mapping table: a Supabase user, the account the import
/// created for it, and its source metadata.
#[derive(Debug, Clone)]
pub struct MappedUser {
    pub supabase_id: String,
    pub account_id: String,
    pub user_metadata: Option<Value>,
    pub app_metadata: Option<Value>,
}

/// What [`record_mapping`] did.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct MappingCounts {
    /// Rows inserted: a Supabase user mapped for the first time.
    pub inserted: usize,
    /// Rows already mapped to the same account (metadata refreshed).
    pub unchanged: usize,
}

/// Why a mapping write failed.
#[derive(Debug, thiserror::Error)]
pub enum MappingError {
    /// The target database refused the read or the write.
    #[error("could not write the mapping table: {0}")]
    Write(String),
    /// The table disagrees with what is being recorded: the Supabase user
    /// already maps to another account, or the account is already used by
    /// another Supabase user. Step three rewrites every reference through
    /// this map, so a disagreement would move somebody's data to the wrong
    /// person — it stops here instead.
    #[error("the mapping table does not agree with this import: {0}")]
    Drift(String),
}

/// Opens a writable connection to the *target* database — the harness
/// Postgres, not the Supabase source — for [`record_mapping`].
///
/// # Errors
///
/// [`MappingError::Write`] when the URL does not parse or the database
/// cannot be reached. Neither message quotes the URL.
pub async fn connect_mapping(url: &Secret) -> Result<PgConnection, MappingError> {
    let options = PgConnectOptions::from_str(url.expose())
        .map_err(|_| {
            MappingError::Write(
                "the target database URL is not a valid Postgres connection string".to_owned(),
            )
        })?
        .application_name("cratefield-import-supabase-users");
    PgConnection::connect_with(&options)
        .await
        .map_err(|error| MappingError::Write(crate::session::redact(&error.to_string(), url)))
}

/// Creates `import_supabase_users` if needed and upserts `rows` in one
/// transaction: a new Supabase id is inserted; one already mapped to the
/// same account has its metadata refreshed (counted unchanged); a new id may
/// share an account with an existing row (`--merge-by-email` maps several
/// source users to one account). The only drift is an existing id that maps
/// to a *different* account — [`MappingError::Drift`].
///
/// # Errors
///
/// [`MappingError::Write`] when the database refuses a statement;
/// [`MappingError::Drift`] on a disagreement. Write messages are scrubbed of
/// everything `url` holds, as [`connect_mapping`] does; both carry ids only.
pub async fn record_mapping(
    conn: &mut PgConnection,
    url: &Secret,
    rows: &[MappedUser],
) -> Result<MappingCounts, MappingError> {
    let write =
        |error: sqlx::Error| MappingError::Write(crate::session::redact(&error.to_string(), url));
    let json = |value: Option<&Value>| value.map(Value::to_string);
    let mut tx = conn.begin().await.map_err(write)?;
    sqlx::raw_sql(CREATE_MAPPING_TABLE)
        .execute(&mut *tx)
        .await
        .map_err(write)?;
    let mut counts = MappingCounts::default();
    for row in rows {
        // Only the id is a key: an existing row whose account differs is the
        // one disagreement that would move somebody's data to the wrong
        // person, so it stops before the write.
        let existing: Option<String> = sqlx::query_scalar(
            "SELECT account_id FROM import_supabase_users WHERE supabase_id = $1::uuid",
        )
        .bind(&row.supabase_id)
        .fetch_optional(&mut *tx)
        .await
        .map_err(write)?;
        if let Some(account) = &existing
            && account != &row.account_id
        {
            return Err(MappingError::Drift(format!(
                "supabase user {} already maps to account {account}, not {}",
                row.supabase_id, row.account_id
            )));
        }
        sqlx::query(
            "INSERT INTO import_supabase_users (supabase_id, account_id, user_metadata, \
             app_metadata) VALUES ($1::uuid, $2, $3::jsonb, $4::jsonb) ON CONFLICT (supabase_id) \
             DO UPDATE SET user_metadata = EXCLUDED.user_metadata, app_metadata = \
             EXCLUDED.app_metadata",
        )
        .bind(&row.supabase_id)
        .bind(&row.account_id)
        .bind(json(row.user_metadata.as_ref()))
        .bind(json(row.app_metadata.as_ref()))
        .execute(&mut *tx)
        .await
        .map_err(write)?;
        if existing.is_some() {
            counts.unchanged += 1;
        } else {
            counts.inserted += 1;
        }
    }
    tx.commit().await.map_err(write)?;
    Ok(counts)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_bcrypt_is_carried() {
        assert!(is_bcrypt("$2a$10$abc"));
        assert!(is_bcrypt("$2b$10$abc"));
        assert!(is_bcrypt("$2y$10$abc"));
        assert!(!is_bcrypt("$argon2id$v=19$m=1,t=1,p=1$abc"));
        assert!(!is_bcrypt(""));
    }
}
