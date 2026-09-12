//! Accounts and ventures (issue #4): the schema the rest of the control
//! plane hangs off, and a repository over the harness `Database` port.
//!
//! An [`Account`] is one invited customer; a [`Venture`] is one backend
//! they provision. The chosen module set is recorded on the venture
//! because the deployed artifact is a function of it (harness ADR 0009),
//! and [`VentureStatus`] is a typed lifecycle rather than free text.
//!
//! **Isolation is by query, for now.** Until one database per tenant
//! lands (harness #32), the control plane's own database holds every
//! account, so every venture read is scoped to an account id. The
//! [`Repository`] is the only way to reach the tables and it never offers
//! an unscoped venture read; a test proves one account cannot see
//! another's.

#![forbid(unsafe_code)]

use std::sync::Arc;

use cratefield_core::{Database, DbError, Statement};
use sea_query::Value as SeaValue;
use serde::{Deserialize, Serialize};

/// The schema migration, applied the way a harness module's is.
pub const MIGRATION: cratefield_core::SqlMigration = cratefield_core::SqlMigration::new(
    "0001",
    "init",
    include_str!("../migrations/sqlite/0001_init.sql"),
);

/// The environments migration (control-plane #31). Portable SQL: the
/// Postgres set reuses this file, the same way it reuses `0001`.
pub const ENVIRONMENTS_MIGRATION: cratefield_core::SqlMigration =
    cratefield_core::SqlMigration::new(
        "0002",
        "environments",
        include_str!("../migrations/sqlite/0002_environments.sql"),
    );

/// One invited customer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Account {
    pub id: String,
    /// The Google-verified email; the whitelist key and login identity.
    pub identity: String,
    pub name: String,
    pub status: AccountStatus,
    pub created_at: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum AccountStatus {
    Active,
    Suspended,
}

impl AccountStatus {
    fn as_str(self) -> &'static str {
        match self {
            AccountStatus::Active => "active",
            AccountStatus::Suspended => "suspended",
        }
    }
    fn parse(s: &str) -> Option<Self> {
        match s {
            "active" => Some(AccountStatus::Active),
            "suspended" => Some(AccountStatus::Suspended),
            _ => None,
        }
    }
}

/// One backend a customer provisions.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Venture {
    pub id: String,
    pub account_id: String,
    pub slug: String,
    pub subdomain: String,
    /// The resolved module set's content key (sorted slugs, `+`-joined).
    pub module_set: String,
    pub status: VentureStatus,
    pub tenant_id: String,
    pub created_at: String,
    pub updated_at: String,
}

/// A venture's lifecycle. The transitions are a small state machine
/// ([`VentureStatus::can_transition_to`]), so an impossible move — a
/// `live` venture jumping back to `draft` — is caught in code, not left
/// to a free-text column.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum VentureStatus {
    /// Created, not yet provisioning.
    Draft,
    /// The provisioning engine is running.
    Provisioning,
    /// Answering `/__health` on its subdomain.
    Live,
    /// Provisioned once, now failing.
    Degraded,
    /// Stopped, record kept.
    Archived,
}

impl VentureStatus {
    fn as_str(self) -> &'static str {
        match self {
            VentureStatus::Draft => "draft",
            VentureStatus::Provisioning => "provisioning",
            VentureStatus::Live => "live",
            VentureStatus::Degraded => "degraded",
            VentureStatus::Archived => "archived",
        }
    }
    fn parse(s: &str) -> Option<Self> {
        Some(match s {
            "draft" => VentureStatus::Draft,
            "provisioning" => VentureStatus::Provisioning,
            "live" => VentureStatus::Live,
            "degraded" => VentureStatus::Degraded,
            "archived" => VentureStatus::Archived,
            _ => return None,
        })
    }

    /// Whether one status may follow another. Draft, Degraded and Live
    /// lead into Provisioning — a first run, a retry, and a **change**;
    /// Provisioning settles to Live or Degraded; anything but Archived can
    /// be Archived; Archived is terminal.
    ///
    /// `Live -> Provisioning` is the third reason, and it was missing.
    /// Changing a live venture's module set has to re-provision it,
    /// because the deployed artifact is a function of that set (ADR 0009)
    /// — and with only "a first run or a retry" expressible, the engine
    /// refused the move and the change could not be made at all. A
    /// re-provisioning venture keeps serving from the artifact it already
    /// has until the new one replaces it, so the state is honest about
    /// what is happening without claiming the venture is down.
    #[must_use]
    pub fn can_transition_to(self, next: VentureStatus) -> bool {
        use VentureStatus::{Archived, Degraded, Draft, Live, Provisioning};
        matches!(
            (self, next),
            (Draft | Degraded | Live, Provisioning)
                | (Provisioning, Live | Degraded)
                | (Live, Degraded)
                | (Degraded, Live)
                | (Draft | Provisioning | Live | Degraded, Archived)
        )
    }
}

/// What went wrong in the repository.
#[derive(Debug)]
pub enum RepoError {
    Db(DbError),
    /// A venture status change the lifecycle does not allow.
    IllegalTransition {
        from: VentureStatus,
        to: VentureStatus,
    },
    /// A row referenced something that is not there, or was malformed.
    NotFound(String),
    Invalid(String),
}

impl std::fmt::Display for RepoError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RepoError::Db(err) => write!(f, "database: {err}"),
            RepoError::IllegalTransition { from, to } => write!(
                f,
                "a venture cannot go from {} to {}",
                from.as_str(),
                to.as_str()
            ),
            RepoError::NotFound(what) => write!(f, "not found: {what}"),
            RepoError::Invalid(what) => write!(f, "invalid: {what}"),
        }
    }
}

impl From<DbError> for RepoError {
    fn from(err: DbError) -> Self {
        RepoError::Db(err)
    }
}

/// The only way to reach the account and venture tables. Every venture
/// read is scoped to an account id; there is no unscoped venture query on
/// this type, which is what keeps one customer out of another's data
/// while isolation is by query rather than by database (harness #32).
pub struct Repository {
    db: Arc<dyn Database>,
}

impl Repository {
    #[must_use]
    pub fn new(db: Arc<dyn Database>) -> Self {
        Self { db }
    }

    /// Finds the account for a login identity, creating it on first sight.
    /// Idempotent: a second call with the same identity returns the same
    /// account, never a duplicate (the `identity` column is unique, and
    /// this reads before it writes).
    ///
    /// The caller has already checked the allowlist; this does not.
    ///
    /// # Errors
    ///
    /// [`RepoError::Db`].
    pub async fn account_for_login(
        &self,
        identity: &str,
        name: &str,
        id: &str,
        now: &str,
    ) -> Result<Account, RepoError> {
        if let Some(existing) = self.account_by_identity(identity).await? {
            return Ok(existing);
        }
        let account = Account {
            id: id.to_owned(),
            identity: identity.to_owned(),
            name: name.to_owned(),
            status: AccountStatus::Active,
            created_at: now.to_owned(),
        };
        self.db
            .execute(&Statement::with_values(
                "INSERT INTO account (id, identity, name, status, created_at) \
                 VALUES (?, ?, ?, ?, ?)",
                vec![
                    text(&account.id),
                    text(&account.identity),
                    text(&account.name),
                    text(account.status.as_str()),
                    text(&account.created_at),
                ],
            ))
            .await?;
        Ok(account)
    }

    /// The account for a login identity, or `None`.
    ///
    /// # Errors
    ///
    /// [`RepoError::Db`].
    pub async fn account_by_identity(&self, identity: &str) -> Result<Option<Account>, RepoError> {
        let rows = self
            .db
            .query(&Statement::with_values(
                "SELECT id, identity, name, status, created_at FROM account WHERE identity = ?",
                vec![text(identity)],
            ))
            .await?;
        rows.first().map(account_from_row).transpose()
    }

    /// Records a new venture for an account, in `Draft`.
    ///
    /// # Errors
    ///
    /// [`RepoError::Db`], including the unique-subdomain violation surfaced
    /// as a database error the caller turns into "that name is taken".
    #[allow(clippy::too_many_arguments)]
    pub async fn create_venture(
        &self,
        id: &str,
        account_id: &str,
        slug: &str,
        subdomain: &str,
        module_set: &str,
        tenant_id: &str,
        now: &str,
    ) -> Result<Venture, RepoError> {
        let venture = Venture {
            id: id.to_owned(),
            account_id: account_id.to_owned(),
            slug: slug.to_owned(),
            subdomain: subdomain.to_owned(),
            module_set: module_set.to_owned(),
            status: VentureStatus::Draft,
            tenant_id: tenant_id.to_owned(),
            created_at: now.to_owned(),
            updated_at: now.to_owned(),
        };
        self.db
            .execute(&Statement::with_values(
                "INSERT INTO venture \
                 (id, account_id, slug, subdomain, module_set, status, tenant_id, created_at, updated_at) \
                 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                vec![
                    text(&venture.id),
                    text(&venture.account_id),
                    text(&venture.slug),
                    text(&venture.subdomain),
                    text(&venture.module_set),
                    text(venture.status.as_str()),
                    text(&venture.tenant_id),
                    text(&venture.created_at),
                    text(&venture.updated_at),
                ],
            ))
            .await?;
        Ok(venture)
    }

    /// Every venture owned by an account. This is the scoped read; there
    /// is no unscoped one.
    ///
    /// # Errors
    ///
    /// [`RepoError::Db`].
    pub async fn ventures_for(&self, account_id: &str) -> Result<Vec<Venture>, RepoError> {
        let rows = self
            .db
            .query(&Statement::with_values(
                "SELECT id, account_id, slug, subdomain, module_set, status, tenant_id, \
                 created_at, updated_at FROM venture WHERE account_id = ? ORDER BY created_at",
                vec![text(account_id)],
            ))
            .await?;
        rows.rows.iter().map(venture_from_row).collect()
    }

    /// One venture, but only if it belongs to `account_id`. A venture id
    /// from another account reads as `NotFound`, not another customer's
    /// row.
    ///
    /// # Errors
    ///
    /// [`RepoError::Db`].
    pub async fn venture_for(
        &self,
        account_id: &str,
        venture_id: &str,
    ) -> Result<Option<Venture>, RepoError> {
        let rows = self
            .db
            .query(&Statement::with_values(
                "SELECT id, account_id, slug, subdomain, module_set, status, tenant_id, \
                 created_at, updated_at FROM venture WHERE account_id = ? AND id = ?",
                vec![text(account_id), text(venture_id)],
            ))
            .await?;
        rows.first().map(venture_from_row).transpose()
    }

    /// Moves a venture to a new status, refusing a transition the
    /// lifecycle does not allow. Scoped to the account, so it cannot
    /// touch another customer's venture.
    ///
    /// Records a venture's module set.
    ///
    /// The set is the identity of the artifact the venture runs (ADR
    /// 0009), so this write is only ever half of a change: the caller is
    /// responsible for re-provisioning, and for clearing the recorded
    /// progress first so the run rebuilds rather than resuming past the
    /// step that builds the artifact. The repository will not do that for
    /// the caller, because it does not own the provisioning table.
    ///
    /// # Errors
    ///
    /// [`RepoError::NotFound`] if the venture is not this account's.
    pub async fn set_venture_modules(
        &self,
        account_id: &str,
        venture_id: &str,
        module_set: &str,
        now: &str,
    ) -> Result<Venture, RepoError> {
        let Some(venture) = self.venture_for(account_id, venture_id).await? else {
            return Err(RepoError::NotFound(format!("venture {venture_id}")));
        };
        self.db
            .execute(&Statement::with_values(
                "UPDATE venture SET module_set = ?, updated_at = ? WHERE account_id = ? AND id = ?",
                vec![
                    text(module_set),
                    text(now),
                    text(account_id),
                    text(venture_id),
                ],
            ))
            .await?;
        Ok(Venture {
            module_set: module_set.to_owned(),
            updated_at: now.to_owned(),
            ..venture
        })
    }

    /// # Errors
    ///
    /// [`RepoError::NotFound`] if the venture is not this account's,
    /// [`RepoError::IllegalTransition`] for a move the lifecycle forbids.
    pub async fn set_venture_status(
        &self,
        account_id: &str,
        venture_id: &str,
        next: VentureStatus,
        now: &str,
    ) -> Result<Venture, RepoError> {
        let Some(venture) = self.venture_for(account_id, venture_id).await? else {
            return Err(RepoError::NotFound(format!("venture {venture_id}")));
        };
        if venture.status != next && !venture.status.can_transition_to(next) {
            return Err(RepoError::IllegalTransition {
                from: venture.status,
                to: next,
            });
        }
        self.db
            .execute(&Statement::with_values(
                "UPDATE venture SET status = ?, updated_at = ? WHERE account_id = ? AND id = ?",
                vec![
                    text(next.as_str()),
                    text(now),
                    text(account_id),
                    text(venture_id),
                ],
            ))
            .await?;
        Ok(Venture {
            status: next,
            updated_at: now.to_owned(),
            ..venture
        })
    }

    // -------------------------------------------------------------------
    // Environments (#31)
    // -------------------------------------------------------------------

    /// Records a new environment for a venture, starting as a copy of
    /// production: the venture's own module set, on its own fresh tenant
    /// (its own database and secret store) and its own sibling
    /// subdomain. The name is validated — kebab-case, `production`
    /// reserved for the derived environment.
    ///
    /// Copying the set rather than leaving it empty is the point of the
    /// screen: staging starts where production is, and the operator
    /// changes it from there, so the first promotion plan is an honest
    /// "no difference" rather than "everything is new".
    ///
    /// # Errors
    ///
    /// [`RepoError::NotFound`] if the venture is not this account's,
    /// [`RepoError::Invalid`] for a name that cannot be an environment.
    #[allow(clippy::too_many_arguments)]
    pub async fn create_environment(
        &self,
        id: &str,
        account_id: &str,
        venture_id: &str,
        name: &str,
        tenant_id: &str,
        now: &str,
    ) -> Result<Environment, RepoError> {
        if !valid_environment_name(name) {
            return Err(RepoError::Invalid(format!(
                "`{name}` cannot be an environment name: lower-case kebab, not `production`"
            )));
        }
        let Some(venture) = self.venture_for(account_id, venture_id).await? else {
            return Err(RepoError::NotFound(format!("venture {venture_id}")));
        };
        let environment = Environment {
            id: id.to_owned(),
            venture_id: venture.id.clone(),
            name: name.to_owned(),
            tenant_id: tenant_id.to_owned(),
            module_set: venture.module_set.clone(),
            subdomain: environment_subdomain(&venture, name)?,
            created_at: now.to_owned(),
            updated_at: now.to_owned(),
        };
        self.db
            .execute(&Statement::with_values(
                "INSERT INTO environment \
                 (id, venture_id, name, tenant_id, module_set, subdomain, created_at, updated_at) \
                 VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                vec![
                    text(&environment.id),
                    text(&environment.venture_id),
                    text(&environment.name),
                    text(&environment.tenant_id),
                    text(&environment.module_set),
                    text(&environment.subdomain),
                    text(&environment.created_at),
                    text(&environment.updated_at),
                ],
            ))
            .await?;
        Ok(environment)
    }

    /// The venture's named environments, oldest first. Production is not
    /// among them: it is derived ([`Environment::production`]) and the
    /// caller renders it ahead of these.
    ///
    /// # Errors
    ///
    /// [`RepoError::Db`].
    pub async fn environments_for(
        &self,
        account_id: &str,
        venture_id: &str,
    ) -> Result<Vec<Environment>, RepoError> {
        let rows = self
            .db
            .query(&Statement::with_values(
                "SELECT e.id, e.venture_id, e.name, e.tenant_id, e.module_set, e.subdomain, \
                 e.created_at, e.updated_at FROM environment e \
                 JOIN venture v ON e.venture_id = v.id \
                 WHERE v.account_id = ? AND e.venture_id = ? ORDER BY e.created_at, e.id",
                vec![text(account_id), text(venture_id)],
            ))
            .await?;
        rows.rows.iter().map(environment_from_row).collect()
    }

    /// One environment, but only if it belongs to a venture this account
    /// owns. Another account's environment id reads as `NotFound`, the
    /// same rule every venture read follows.
    ///
    /// # Errors
    ///
    /// [`RepoError::Db`].
    pub async fn environment_for(
        &self,
        account_id: &str,
        venture_id: &str,
        environment_id: &str,
    ) -> Result<Option<Environment>, RepoError> {
        let rows = self
            .db
            .query(&Statement::with_values(
                "SELECT e.id, e.venture_id, e.name, e.tenant_id, e.module_set, e.subdomain, \
                 e.created_at, e.updated_at FROM environment e \
                 JOIN venture v ON e.venture_id = v.id \
                 WHERE v.account_id = ? AND e.venture_id = ? AND e.id = ?",
                vec![text(account_id), text(venture_id), text(environment_id)],
            ))
            .await?;
        rows.first().map(environment_from_row).transpose()
    }

    /// Records an environment's module set. The same half-a-change
    /// contract as [`Repository::set_venture_modules`]: the caller is
    /// responsible for re-provisioning the environment and for clearing
    /// its recorded progress first, and this repository will not,
    /// because it does not own the progress table.
    ///
    /// # Errors
    ///
    /// [`RepoError::NotFound`] if the environment is not this account's.
    pub async fn set_environment_modules(
        &self,
        account_id: &str,
        venture_id: &str,
        environment_id: &str,
        module_set: &str,
        now: &str,
    ) -> Result<Environment, RepoError> {
        let Some(environment) = self
            .environment_for(account_id, venture_id, environment_id)
            .await?
        else {
            return Err(RepoError::NotFound(format!("environment {environment_id}")));
        };
        self.db
            .execute(&Statement::with_values(
                "UPDATE environment SET module_set = ?, updated_at = ? WHERE id = ?",
                vec![text(module_set), text(now), text(environment_id)],
            ))
            .await?;
        Ok(Environment {
            module_set: module_set.to_owned(),
            updated_at: now.to_owned(),
            ..environment
        })
    }
}

/// One environment of a venture (control-plane #31): its own database,
/// its own secret store and its own module set, so a schema change can
/// be rehearsed somewhere that is not production.
///
/// **Production is not a row.** [`Environment::production`] derives it
/// from the venture itself — the venture as it exists today, which is
/// what must keep working exactly as it does. A mirrored "production"
/// row was considered and rejected: it would be a second copy of the
/// venture's tenant, module set and subdomain that every existing write
/// path (the module-set editor, the engine's status moves) would have
/// to keep in sync, and one missed path would leave the record lying
/// about what production runs. Deriving it means the venture's screens
/// and the environments screen read the same columns and cannot
/// disagree.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Environment {
    pub id: String,
    pub venture_id: String,
    /// `staging`, and whatever else is named alongside it. `production`
    /// is reserved for the derived one and cannot be inserted.
    pub name: String,
    /// The tenant whose database and secret store this environment owns.
    pub tenant_id: String,
    /// The resolved module set's content key, `'+'`-joined — the
    /// identity of the artifact this environment would run.
    pub module_set: String,
    /// Where this environment would answer, derived from the venture's
    /// own subdomain at creation (`my-app-staging.cratefield.app`).
    pub subdomain: String,
    pub created_at: String,
    pub updated_at: String,
}

impl Environment {
    /// The venture's production environment: the venture itself. The id
    /// is the venture's id on purpose, so the venture's own provisioning
    /// progress — keyed by venture id — *is* production's progress, with
    /// no second ledger to keep true.
    #[must_use]
    pub fn production(venture: &Venture) -> Self {
        Self {
            id: venture.id.clone(),
            venture_id: venture.id.clone(),
            name: "production".to_owned(),
            tenant_id: venture.tenant_id.clone(),
            module_set: venture.module_set.clone(),
            subdomain: venture.subdomain.clone(),
            created_at: venture.created_at.clone(),
            updated_at: venture.updated_at.clone(),
        }
    }

    /// Whether this row is the derived production environment.
    #[must_use]
    pub fn is_production(&self) -> bool {
        self.name == "production"
    }
}

/// The name a new environment may take: lower-case kebab, `production`
/// reserved. A name is a URL segment and a label on a button that says
/// what will move where, so both halves are strict.
fn valid_environment_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 30
        && name != "production"
        && name
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
        && !name.starts_with('-')
        && !name.ends_with('-')
}

/// The subdomain a new environment of `venture` gets: a sibling of the
/// venture's own (`my-app` + `staging` → `my-app-staging.cratefield.app`),
/// so the parent domain is inherited rather than restated. The venture's
/// subdomain is `slug.domain`; everything after the first dot is the
/// domain. A venture whose subdomain has no dot has no parent domain to
/// sit beside, and that is the caller's configuration problem to name,
/// not ours to paper over.
fn environment_subdomain(venture: &Venture, name: &str) -> Result<String, RepoError> {
    let Some((_, domain)) = venture.subdomain.split_once('.') else {
        return Err(RepoError::Invalid(format!(
            "the venture's subdomain `{}` has no parent domain to put an \
             environment beside",
            venture.subdomain
        )));
    };
    Ok(format!("{}-{}.{}", venture.slug, name, domain))
}

fn account_from_row(row: &cratefield_core::Row) -> Result<Account, RepoError> {
    Ok(Account {
        id: field(row, "id")?,
        identity: field(row, "identity")?,
        name: field(row, "name")?,
        status: AccountStatus::parse(&field(row, "status")?)
            .ok_or_else(|| RepoError::Invalid("account status".to_owned()))?,
        created_at: field(row, "created_at")?,
    })
}

fn venture_from_row(row: &cratefield_core::Row) -> Result<Venture, RepoError> {
    Ok(Venture {
        id: field(row, "id")?,
        account_id: field(row, "account_id")?,
        slug: field(row, "slug")?,
        subdomain: field(row, "subdomain")?,
        module_set: field(row, "module_set")?,
        status: VentureStatus::parse(&field(row, "status")?)
            .ok_or_else(|| RepoError::Invalid("venture status".to_owned()))?,
        tenant_id: field(row, "tenant_id")?,
        created_at: field(row, "created_at")?,
        updated_at: field(row, "updated_at")?,
    })
}

fn environment_from_row(row: &cratefield_core::Row) -> Result<Environment, RepoError> {
    Ok(Environment {
        id: field(row, "id")?,
        venture_id: field(row, "venture_id")?,
        name: field(row, "name")?,
        tenant_id: field(row, "tenant_id")?,
        module_set: field(row, "module_set")?,
        subdomain: field(row, "subdomain")?,
        created_at: field(row, "created_at")?,
        updated_at: field(row, "updated_at")?,
    })
}

fn field(row: &cratefield_core::Row, name: &str) -> Result<String, RepoError> {
    row.get(name)
        .ok_or_else(|| RepoError::Invalid(format!("row has no `{name}`")))
}

fn text(value: &str) -> SeaValue {
    SeaValue::String(Some(Box::new(value.to_owned())))
}

#[cfg(test)]
mod tests {
    use super::*;
    use cratefield_adapter_sqlite::SqliteDatabase;

    fn repo() -> Repository {
        let db = SqliteDatabase::in_memory().expect("db");
        db.apply_migrations("accounts", &[MIGRATION])
            .expect("schema");
        Repository::new(Arc::new(db))
    }

    #[test]
    fn the_lifecycle_allows_only_sensible_moves() {
        use VentureStatus::{Archived, Degraded, Draft, Live, Provisioning};
        assert!(Draft.can_transition_to(Provisioning));
        assert!(Provisioning.can_transition_to(Live));
        assert!(Provisioning.can_transition_to(Degraded));
        assert!(Degraded.can_transition_to(Provisioning), "a retry");
        assert!(
            Live.can_transition_to(Provisioning),
            "a change: the artifact is a function of the module set, so editing \
             the set of a live venture re-provisions it"
        );
        assert!(Live.can_transition_to(Archived));
        // nonsense moves
        assert!(!Live.can_transition_to(Draft));
        assert!(!Draft.can_transition_to(Live), "must provision first");
        assert!(!Archived.can_transition_to(Live), "archived is terminal");
    }

    #[pollster::test]
    async fn account_creation_on_login_is_idempotent() {
        let repo = repo();
        let a = repo
            .account_for_login("ada@example.com", "Ada", "acc_1", "t0")
            .await
            .expect("creates");
        let b = repo
            .account_for_login("ada@example.com", "Ada Lovelace", "acc_2", "t1")
            .await
            .expect("second login");
        assert_eq!(a.id, b.id, "same account, not a duplicate");
        assert_eq!(b.name, "Ada", "the first record wins; no accidental rename");
        assert_eq!(a.status, AccountStatus::Active);
    }

    #[pollster::test]
    async fn one_account_cannot_see_anothers_ventures() {
        let repo = repo();
        repo.account_for_login("a@x.co", "A", "acc_a", "t0")
            .await
            .unwrap();
        repo.account_for_login("b@x.co", "B", "acc_b", "t0")
            .await
            .unwrap();
        repo.create_venture(
            "v1",
            "acc_a",
            "site-a",
            "a.cratefield.app",
            "email-signup",
            "ten_a",
            "t0",
        )
        .await
        .expect("A's venture");

        let a_sees = repo.ventures_for("acc_a").await.unwrap();
        let b_sees = repo.ventures_for("acc_b").await.unwrap();
        assert_eq!(a_sees.len(), 1);
        assert!(b_sees.is_empty(), "B sees nothing of A's");

        // and a direct fetch of A's venture id under B's account is NotFound
        assert!(repo.venture_for("acc_b", "v1").await.unwrap().is_none());
        assert!(repo.venture_for("acc_a", "v1").await.unwrap().is_some());
    }

    #[pollster::test]
    async fn a_venture_moves_through_its_lifecycle_and_illegal_moves_are_refused() {
        let repo = repo();
        repo.account_for_login("a@x.co", "A", "acc_a", "t0")
            .await
            .unwrap();
        repo.create_venture("v1", "acc_a", "s", "s.cratefield.app", "cms", "ten", "t0")
            .await
            .unwrap();

        let v = repo
            .set_venture_status("acc_a", "v1", VentureStatus::Provisioning, "t1")
            .await
            .expect("draft -> provisioning");
        assert_eq!(v.status, VentureStatus::Provisioning);
        repo.set_venture_status("acc_a", "v1", VentureStatus::Live, "t2")
            .await
            .expect("provisioning -> live");

        let err = repo
            .set_venture_status("acc_a", "v1", VentureStatus::Draft, "t3")
            .await
            .expect_err("live cannot go back to draft");
        assert!(matches!(err, RepoError::IllegalTransition { .. }), "{err}");

        // another account cannot move it at all
        repo.account_for_login("b@x.co", "B", "acc_b", "t0")
            .await
            .unwrap();
        let err = repo
            .set_venture_status("acc_b", "v1", VentureStatus::Degraded, "t4")
            .await
            .expect_err("not B's venture");
        assert!(matches!(err, RepoError::NotFound(_)), "{err}");
    }

    #[pollster::test]
    async fn a_duplicate_subdomain_is_refused_by_the_database() {
        let repo = repo();
        repo.account_for_login("a@x.co", "A", "acc_a", "t0")
            .await
            .unwrap();
        repo.create_venture(
            "v1",
            "acc_a",
            "s",
            "taken.cratefield.app",
            "cms",
            "ten1",
            "t0",
        )
        .await
        .expect("first");
        let err = repo
            .create_venture(
                "v2",
                "acc_a",
                "s2",
                "taken.cratefield.app",
                "cms",
                "ten2",
                "t0",
            )
            .await
            .expect_err("same subdomain");
        assert!(matches!(err, RepoError::Db(_)), "{err}");
    }

    // -------------------------------------------------------------------
    // Environments (#31)
    // -------------------------------------------------------------------

    /// A repository with both migrations applied, the way the console's
    /// composition applies them, and one venture to hang environments
    /// off.
    async fn env_repo() -> (Repository, Venture) {
        let db = SqliteDatabase::in_memory().expect("db");
        db.apply_migrations("accounts", &[MIGRATION, ENVIRONMENTS_MIGRATION])
            .expect("schema");
        let repo = Repository::new(Arc::new(db));
        repo.account_for_login("a@x.co", "A", "acc_a", "t0")
            .await
            .unwrap();
        let venture = repo
            .create_venture(
                "v1",
                "acc_a",
                "my-app",
                "my-app.cratefield.app",
                "cms+waitlist",
                "ten_1",
                "t0",
            )
            .await
            .expect("venture");
        (repo, venture)
    }

    #[pollster::test]
    async fn production_is_derived_from_the_venture_not_stored_beside_it() {
        let (repo, venture) = env_repo().await;
        let production = Environment::production(&venture);
        assert_eq!(production.name, "production");
        assert!(production.is_production());
        // The id is the venture's, so the venture's provisioning progress
        // is production's progress — one ledger, not two to keep true.
        assert_eq!(production.id, venture.id);
        assert_eq!(production.tenant_id, venture.tenant_id);
        assert_eq!(production.module_set, venture.module_set);
        assert_eq!(production.subdomain, venture.subdomain);

        // And nothing was written: the environments table is empty, so
        // the migration introduced the concept without inventing rows.
        let named = repo.environments_for("acc_a", "v1").await.unwrap();
        assert!(named.is_empty(), "production is derived, never stored");
    }

    #[pollster::test]
    async fn a_staging_environment_starts_as_production_on_its_own_tenant() {
        let (repo, venture) = env_repo().await;
        let staging = repo
            .create_environment("env_1", "acc_a", "v1", "staging", "ten_stg", "t1")
            .await
            .expect("create");
        // The set is copied from the venture; the tenant is its own.
        assert_eq!(staging.module_set, venture.module_set);
        assert_eq!(staging.tenant_id, "ten_stg");
        assert_eq!(staging.subdomain, "my-app-staging.cratefield.app");
        assert_eq!(staging.venture_id, "v1");

        let named = repo.environments_for("acc_a", "v1").await.unwrap();
        assert_eq!(named, vec![staging.clone()]);

        // A second environment of the same venture, differently named.
        repo.create_environment("env_2", "acc_a", "v1", "qa", "ten_qa", "t2")
            .await
            .expect("second");
        assert_eq!(repo.environments_for("acc_a", "v1").await.unwrap().len(), 2);
    }

    #[pollster::test]
    async fn production_is_a_reserved_environment_name() {
        let (repo, _) = env_repo().await;
        let err = repo
            .create_environment("env_1", "acc_a", "v1", "production", "ten_x", "t1")
            .await
            .expect_err("reserved");
        assert!(matches!(err, RepoError::Invalid(_)), "{err}");
        // The other names that cannot be environments.
        for bad in ["", "Staging", "two words", "-lead", "trail-", "a_b"] {
            let err = repo
                .create_environment("env_x", "acc_a", "v1", bad, "ten_x", "t1")
                .await
                .expect_err("invalid name");
            assert!(matches!(err, RepoError::Invalid(_)), "{bad}: {err}");
        }
    }

    #[pollster::test]
    async fn a_duplicate_name_for_one_venture_is_refused() {
        let (repo, _) = env_repo().await;
        repo.create_environment("env_1", "acc_a", "v1", "staging", "ten_s", "t1")
            .await
            .expect("first");
        let err = repo
            .create_environment("env_2", "acc_a", "v1", "staging", "ten_t", "t2")
            .await
            .expect_err("same venture, same name");
        assert!(matches!(err, RepoError::Db(_)), "{err}");
    }

    #[pollster::test]
    async fn one_account_cannot_see_or_edit_anothers_environment() {
        let (repo, _) = env_repo().await;
        repo.account_for_login("b@x.co", "B", "acc_b", "t0")
            .await
            .unwrap();
        repo.create_environment("env_1", "acc_a", "v1", "staging", "ten_s", "t1")
            .await
            .expect("A's staging");

        // Creating for a venture that is not B's: NotFound, not a row.
        let err = repo
            .create_environment("env_2", "acc_b", "v1", "staging", "ten_x", "t2")
            .await
            .expect_err("not B's venture");
        assert!(matches!(err, RepoError::NotFound(_)), "{err}");

        assert!(
            repo.environments_for("acc_b", "v1")
                .await
                .unwrap()
                .is_empty()
        );
        assert!(
            repo.environment_for("acc_b", "v1", "env_1")
                .await
                .unwrap()
                .is_none()
        );
        let err = repo
            .set_environment_modules("acc_b", "v1", "env_1", "cms", "t3")
            .await
            .expect_err("not B's environment");
        assert!(matches!(err, RepoError::NotFound(_)), "{err}");
    }

    #[pollster::test]
    async fn an_environments_module_set_is_recorded_and_scoped() {
        let (repo, _) = env_repo().await;
        repo.create_environment("env_1", "acc_a", "v1", "staging", "ten_s", "t1")
            .await
            .expect("staging");
        let updated = repo
            .set_environment_modules("acc_a", "v1", "env_1", "cms+waitlist+notifications", "t2")
            .await
            .expect("record");
        assert_eq!(updated.module_set, "cms+waitlist+notifications");
        // The venture's own set is untouched: staging rehearsing a change
        // is exactly not production making it.
        let venture = repo.venture_for("acc_a", "v1").await.unwrap().unwrap();
        assert_eq!(venture.module_set, "cms+waitlist");
    }
}
