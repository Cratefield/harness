//! The provisioning engine (issue #7): a module set to a live venture,
//! idempotent and resumable.
//!
//! Standing a venture up is a fixed sequence of steps ([`Step`]) —
//! artifact, database, worker, schema, secrets, route, health — behind a
//! [`Deployer`] port. Each completed step is recorded against the venture in
//! `provision_progress`, so:
//!
//! - a failure **names its step**, records the message, and leaves the venture
//!   `provisioning` and retryable — never half-live;
//! - a re-run **resumes** from the step after the last one that completed,
//!   rather than repeating work; and
//! - [`Engine::plan`] lists what would happen without touching Cloudflare.
//!
//! **The port is the seam.** [`Deployer`] is what actually talks to
//! Cloudflare; its methods are all "ensure" shaped, so calling one twice is
//! safe. This crate host-tests the engine against a fake deployer. The live
//! adapter — the one that holds the platform credential and does real deploys
//! (ADR section 4) — implements the same port and is wired in where the
//! credential lives, never in this crate.

#![forbid(unsafe_code)]

use std::sync::Arc;

use cratefield_accounts::{Environment, RepoError, Repository, Venture, VentureStatus};
use cratefield_core::{Database, DbError, Statement};
use sea_query::Value as SeaValue;

/// The schema migration: the `provision_progress` table.
pub const MIGRATION: cratefield_core::SqlMigration = cratefield_core::SqlMigration::new(
    "0001",
    "init",
    include_str!("../migrations/sqlite/0001_init.sql"),
);

/// The environments migration (#31): `environment_progress`, an
/// environment's own ledger. Portable SQL — the Postgres set reuses this
/// file the way it reuses `0001`.
pub const ENVIRONMENT_PROGRESS_MIGRATION: cratefield_core::SqlMigration =
    cratefield_core::SqlMigration::new(
        "0002",
        "environment-progress",
        include_str!("../migrations/sqlite/0002_environment_progress.sql"),
    );

// ---------------------------------------------------------------------------
// Steps
// ---------------------------------------------------------------------------

/// One provisioning step, in order. The sequence is fixed; a venture advances
/// through it and a resume continues from where it stopped.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Step {
    /// Build (or reuse the cached) composed artifact for the module set.
    Artifact,
    /// Create the venture's D1 database.
    Database,
    /// Deploy the venture's Worker, pointing at the artifact.
    Worker,
    /// Apply the venture's migrations to its database.
    Schema,
    /// Seed the venture's secrets store (its Google client, module keys).
    Secrets,
    /// Bind the venture's subdomain.
    Route,
    /// Wait for the venture to answer `/__health` on its subdomain.
    Health,
}

/// The steps, in the order they run.
pub const STEPS: [Step; 7] = [
    Step::Artifact,
    Step::Database,
    Step::Worker,
    Step::Schema,
    Step::Secrets,
    Step::Route,
    Step::Health,
];

impl Step {
    /// The stable token recorded in `provision_progress`.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Step::Artifact => "artifact",
            Step::Database => "database",
            Step::Worker => "worker",
            Step::Schema => "schema",
            Step::Secrets => "secrets",
            Step::Route => "route",
            Step::Health => "health",
        }
    }

    fn parse(s: &str) -> Option<Self> {
        STEPS.into_iter().find(|step| step.as_str() == s)
    }

    /// Whether a recorded `last_step` means its run got through
    /// `through`. The question the environments screen's rehearsal rule
    /// turns on — "did this run complete the schema step" — answered
    /// against the ledger's own vocabulary rather than by comparing
    /// step names at the call site, where nobody can see which name is
    /// later in the sequence.
    #[must_use]
    pub fn completed_through(recorded: &str, through: Step) -> bool {
        match Step::parse(recorded) {
            Some(step) => step.index() >= through.index(),
            None => false,
        }
    }

    /// This step's position in [`STEPS`].
    fn index(self) -> usize {
        STEPS
            .iter()
            .position(|s| *s == self)
            .expect("every step is in STEPS")
    }
}

/// A step as it would run, for [`Engine::plan`]: the step and a description of
/// what it would do for this venture. Produced without touching Cloudflare.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlannedStep {
    pub step: Step,
    /// `true` if the venture's recorded progress shows this step already done.
    pub done: bool,
    pub description: String,
}

// ---------------------------------------------------------------------------
// The deployer port
// ---------------------------------------------------------------------------

/// A failure from the thing that talks to Cloudflare.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeployError {
    /// A message safe to record and show; it must never carry a credential.
    pub message: String,
}

impl DeployError {
    #[must_use]
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

impl std::fmt::Display for DeployError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

/// What actually stands a venture up on Cloudflare. Every method is "ensure"
/// shaped: calling it again for a step already done is safe, so a resume that
/// re-touches a step cannot break anything. The live adapter holds the
/// platform credential and does real deploys; tests use a fake.
///
/// A `tenant` is the venture's tenant id; `module_set` is the resolved set's
/// content key (the artifact's identity, ADR 0009).
#[allow(async_fn_in_trait)]
pub trait Deployer {
    /// Ensure the composed artifact for `module_set` is built and cached.
    async fn build_artifact(&self, module_set: &str) -> Result<(), DeployError>;
    /// Ensure the venture's database exists.
    async fn ensure_database(&self, tenant: &str) -> Result<(), DeployError>;
    /// Ensure the venture's Worker is deployed, pointing at the artifact.
    async fn ensure_worker(&self, tenant: &str, module_set: &str) -> Result<(), DeployError>;
    /// Apply the venture's migrations to its database.
    async fn apply_schema(&self, tenant: &str, module_set: &str) -> Result<(), DeployError>;
    /// Seed the venture's secrets store.
    async fn seed_secrets(&self, tenant: &str) -> Result<(), DeployError>;
    /// Bind the venture's subdomain.
    async fn bind_route(&self, tenant: &str, subdomain: &str) -> Result<(), DeployError>;
    /// Whether the venture answers `/__health` on its subdomain yet.
    async fn health_ok(&self, subdomain: &str) -> Result<bool, DeployError>;
}

/// The deployer the control plane has today: none.
///
/// There is no adapter that talks to Cloudflare yet (that is the live
/// deploy pipeline's work), and a control-plane screen that offers to
/// provision has to do *something* when the button is pressed. The choice
/// this crate makes is to run the engine for real and let it stop where it
/// stops: the first step fails, the failure is recorded against the
/// venture with the reason, and every screen that reads
/// `provision_progress` shows it.
///
/// That is deliberately not the same as refusing the button or pretending
/// it worked. The venture's recorded state after a run through `Unwired`
/// is exactly true — "provisioning stopped at `artifact`, because nothing
/// is wired to build one" — and the day a real [`Deployer`] is passed
/// instead, every one of these ventures resumes from the step it stopped
/// at with no migration and no special case.
pub struct Unwired;

impl Unwired {
    /// The one message, so the recorded error reads the same whichever
    /// step a resume happens to reach first.
    fn refuse<T>(what: &str) -> Result<T, DeployError> {
        Err(DeployError::new(format!(
            "no deployer is wired: {what} needs an adapter that talks to Cloudflare, \
             and the control plane has none yet. Nothing was changed."
        )))
    }
}

// Every method answers without awaiting anything, which is the whole
// point: there is nothing to talk to. The port is async because a real
// deployer is.
#[allow(clippy::unused_async_trait_impl)]
impl Deployer for Unwired {
    async fn build_artifact(&self, _module_set: &str) -> Result<(), DeployError> {
        Self::refuse("building the composed artifact")
    }
    async fn ensure_database(&self, _tenant: &str) -> Result<(), DeployError> {
        Self::refuse("creating the venture's database")
    }
    async fn ensure_worker(&self, _tenant: &str, _module_set: &str) -> Result<(), DeployError> {
        Self::refuse("deploying the venture's Worker")
    }
    async fn apply_schema(&self, _tenant: &str, _module_set: &str) -> Result<(), DeployError> {
        Self::refuse("applying the venture's migrations")
    }
    async fn seed_secrets(&self, _tenant: &str) -> Result<(), DeployError> {
        Self::refuse("seeding the venture's secrets store")
    }
    async fn bind_route(&self, _tenant: &str, _subdomain: &str) -> Result<(), DeployError> {
        Self::refuse("binding the venture's subdomain")
    }
    async fn health_ok(&self, _subdomain: &str) -> Result<bool, DeployError> {
        Self::refuse("checking the venture's health")
    }
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Why a provisioning run stopped.
#[derive(Debug)]
pub enum ProvisionError {
    /// A step failed. The venture is left `provisioning` and retryable; the
    /// step and message are recorded.
    Step { step: Step, message: String },
    /// A repository/state-machine failure.
    Repo(RepoError),
    /// A progress-table database failure.
    Db(DbError),
}

impl std::fmt::Display for ProvisionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ProvisionError::Step { step, message } => {
                write!(f, "step {} failed: {message}", step.as_str())
            }
            ProvisionError::Repo(err) => write!(f, "accounts: {err}"),
            ProvisionError::Db(err) => write!(f, "progress: {err}"),
        }
    }
}

impl std::error::Error for ProvisionError {}

impl From<RepoError> for ProvisionError {
    fn from(err: RepoError) -> Self {
        ProvisionError::Repo(err)
    }
}
impl From<DbError> for ProvisionError {
    fn from(err: DbError) -> Self {
        ProvisionError::Db(err)
    }
}

// ---------------------------------------------------------------------------
// The engine
// ---------------------------------------------------------------------------

/// Runs provisioning for a venture, recording progress so a run is resumable
/// and a failure is recoverable.
pub struct Engine {
    db: Arc<dyn Database>,
    accounts: Repository,
}

impl Engine {
    #[must_use]
    pub fn new(db: Arc<dyn Database>) -> Self {
        Self {
            accounts: Repository::new(Arc::clone(&db)),
            db,
        }
    }

    /// What provisioning `venture` would do, step by step, without touching
    /// Cloudflare. Each entry says whether the venture's recorded progress
    /// already marks that step done.
    ///
    /// # Errors
    ///
    /// [`ProvisionError::Db`] if the progress cannot be read.
    pub async fn plan(&self, venture: &Venture) -> Result<Vec<PlannedStep>, ProvisionError> {
        self.plan_subject(Subject::venture(venture)).await
    }

    /// What provisioning `environment` would do, step by step, without
    /// touching Cloudflare — the same steps a venture runs, described
    /// against the environment's own tenant, module set and subdomain
    /// and marked against its own ledger.
    ///
    /// # Errors
    ///
    /// [`ProvisionError::Db`] if the progress cannot be read.
    pub async fn plan_environment(
        &self,
        environment: &Environment,
    ) -> Result<Vec<PlannedStep>, ProvisionError> {
        self.plan_subject(Subject::environment(environment)).await
    }

    /// Provisions `venture`, running each remaining step in order and
    /// recording it. Idempotent: a re-run resumes from the step after the last
    /// that completed, and a fully-provisioned venture is left `Live` without
    /// repeating work.
    ///
    /// On a step failure the venture is left `Provisioning` (retryable), the
    /// step and message are recorded, and [`ProvisionError::Step`] is
    /// returned naming the step.
    ///
    /// # Errors
    ///
    /// [`ProvisionError::Step`] on a step failure; [`ProvisionError::Repo`] or
    /// [`ProvisionError::Db`] on an infrastructure failure.
    pub async fn provision<D: Deployer>(
        &self,
        venture: &Venture,
        deployer: &D,
        now: &str,
    ) -> Result<VentureStatus, ProvisionError> {
        let subject = Subject::venture(venture);
        let start = self.start_index(subject).await?;

        // Already through every step: ensure Live and return, no work.
        if start >= STEPS.len() {
            return Ok(self.mark_live(venture, now).await?);
        }

        // Enter the provisioning state (a no-op if already there).
        if venture.status != VentureStatus::Provisioning {
            self.accounts
                .set_venture_status(
                    &venture.account_id,
                    &venture.id,
                    VentureStatus::Provisioning,
                    now,
                )
                .await?;
        }

        self.run_from(subject, start, deployer, now).await?;
        Ok(self.mark_live(venture, now).await?)
    }

    /// Provisions `environment` through the same engine, the same steps
    /// and the same [`Deployer`] port, recording progress against the
    /// environment in its own ledger. It stops where every run stops
    /// today — at the [`Unwired`] deployer, honestly — and the venture
    /// itself is untouched: an environment is not a venture, and a
    /// staging run must never read as the venture itself provisioning,
    /// so the venture's status is not moved and its own progress row is
    /// not written.
    ///
    /// An environment has no lifecycle status to settle into when every
    /// step is done; its record of completion is the ledger, and a
    /// re-run of a completed environment is a no-op exactly like a
    /// venture's.
    ///
    /// # Errors
    ///
    /// [`ProvisionError::Step`] on a step failure; [`ProvisionError::Db`]
    /// on an infrastructure failure.
    pub async fn provision_environment<D: Deployer>(
        &self,
        environment: &Environment,
        deployer: &D,
        now: &str,
    ) -> Result<(), ProvisionError> {
        let subject = Subject::environment(environment);
        let start = self.start_index(subject).await?;
        if start >= STEPS.len() {
            return Ok(());
        }
        self.run_from(subject, start, deployer, now).await
    }

    async fn plan_subject(&self, subject: Subject<'_>) -> Result<Vec<PlannedStep>, ProvisionError> {
        let last = self.last_completed(subject.ledger, subject.key).await?;
        let done_through = last.map_or(-1, |s| i64::try_from(s.index()).unwrap_or(-1));
        Ok(STEPS
            .into_iter()
            .map(|step| PlannedStep {
                step,
                done: i64::try_from(step.index()).unwrap_or(0) <= done_through,
                description: describe(step, subject),
            })
            .collect())
    }

    async fn start_index(&self, subject: Subject<'_>) -> Result<usize, ProvisionError> {
        Ok(
            match self.last_completed(subject.ledger, subject.key).await? {
                Some(last) => last.index() + 1,
                None => 0,
            },
        )
    }

    async fn run_from<D: Deployer>(
        &self,
        subject: Subject<'_>,
        start: usize,
        deployer: &D,
        now: &str,
    ) -> Result<(), ProvisionError> {
        for step in &STEPS[start..] {
            let step = *step;
            if let Err(err) = run_step(deployer, step, subject).await {
                self.record_error(subject, step, &err.message, now).await?;
                return Err(ProvisionError::Step {
                    step,
                    message: err.message,
                });
            }
            self.record_done(subject, step, now).await?;
        }
        Ok(())
    }

    async fn mark_live(&self, venture: &Venture, now: &str) -> Result<VentureStatus, RepoError> {
        if venture.status == VentureStatus::Live {
            return Ok(VentureStatus::Live);
        }
        self.accounts
            .set_venture_status(&venture.account_id, &venture.id, VentureStatus::Live, now)
            .await?;
        Ok(VentureStatus::Live)
    }

    /// The last step recorded complete in `ledger` for `key`, or `None`.
    async fn last_completed(
        &self,
        ledger: Ledger,
        key: &str,
    ) -> Result<Option<Step>, ProvisionError> {
        let rows = self
            .db
            .query(&Statement::with_values(
                format!(
                    "SELECT last_step FROM {} WHERE {} = ?",
                    ledger.table(),
                    ledger.key_column()
                ),
                vec![text(key)],
            ))
            .await?;
        let Some(row) = rows.first() else {
            return Ok(None);
        };
        let raw: String = row.get("last_step").unwrap_or_default();
        Ok(Step::parse(&raw))
    }

    async fn record_done(
        &self,
        subject: Subject<'_>,
        step: Step,
        now: &str,
    ) -> Result<(), ProvisionError> {
        self.upsert(subject, step.as_str(), "", now).await
    }

    async fn record_error(
        &self,
        subject: Subject<'_>,
        step: Step,
        message: &str,
        now: &str,
    ) -> Result<(), ProvisionError> {
        // Keep the last completed step as-is; only record which step failed and
        // why, so a resume still starts after the last success.
        let last = self.last_completed(subject.ledger, subject.key).await?;
        let last_str = last.map_or("", Step::as_str);
        self.upsert(
            subject,
            last_str,
            &format!("{}: {message}", step.as_str()),
            now,
        )
        .await
    }

    async fn upsert(
        &self,
        subject: Subject<'_>,
        last_step: &str,
        error: &str,
        now: &str,
    ) -> Result<(), ProvisionError> {
        self.db
            .execute(&Statement::with_values(
                format!(
                    "INSERT INTO {} ({}, last_step, error, updated_at) \
                     VALUES (?, ?, ?, ?) \
                     ON CONFLICT({}) DO UPDATE SET \
                     last_step = excluded.last_step, error = excluded.error, \
                     updated_at = excluded.updated_at",
                    subject.ledger.table(),
                    subject.ledger.key_column(),
                    subject.ledger.key_column()
                ),
                vec![text(subject.key), text(last_step), text(error), text(now)],
            ))
            .await?;
        Ok(())
    }
}

/// Which ledger a provisioning run's progress lives in: the venture's
/// own, or an environment's. Same shape, different subject — an
/// environment's run is not the venture's run, and recording one in the
/// other's table would make a stopped staging run read as the venture
/// itself failing.
#[derive(Clone, Copy)]
enum Ledger {
    Venture,
    Environment,
}

impl Ledger {
    fn table(self) -> &'static str {
        match self {
            Ledger::Venture => "provision_progress",
            Ledger::Environment => "environment_progress",
        }
    }

    fn key_column(self) -> &'static str {
        match self {
            Ledger::Venture => "venture_id",
            Ledger::Environment => "environment_id",
        }
    }
}

/// What one step needs from its subject: the tenant whose database and
/// secrets the step touches, the module set whose artifact it builds,
/// and the subdomain it routes and health-checks. A venture and one of
/// its environments differ in exactly these three and in nothing else,
/// which is why the same step sequence serves both.
#[derive(Clone, Copy)]
struct Subject<'a> {
    key: &'a str,
    ledger: Ledger,
    tenant: &'a str,
    module_set: &'a str,
    subdomain: &'a str,
}

impl<'a> Subject<'a> {
    fn venture(venture: &'a Venture) -> Self {
        Self {
            key: &venture.id,
            ledger: Ledger::Venture,
            tenant: &venture.tenant_id,
            module_set: &venture.module_set,
            subdomain: &venture.subdomain,
        }
    }

    fn environment(environment: &'a Environment) -> Self {
        Self {
            key: &environment.id,
            ledger: Ledger::Environment,
            tenant: &environment.tenant_id,
            module_set: &environment.module_set,
            subdomain: &environment.subdomain,
        }
    }
}

async fn run_step<D: Deployer>(
    deployer: &D,
    step: Step,
    subject: Subject<'_>,
) -> Result<(), DeployError> {
    let tenant = subject.tenant;
    match step {
        Step::Artifact => deployer.build_artifact(subject.module_set).await,
        Step::Database => deployer.ensure_database(tenant).await,
        Step::Worker => deployer.ensure_worker(tenant, subject.module_set).await,
        Step::Schema => deployer.apply_schema(tenant, subject.module_set).await,
        Step::Secrets => deployer.seed_secrets(tenant).await,
        Step::Route => deployer.bind_route(tenant, subject.subdomain).await,
        Step::Health => {
            if deployer.health_ok(subject.subdomain).await? {
                Ok(())
            } else {
                Err(DeployError::new("the venture did not answer /__health yet"))
            }
        }
    }
}

fn describe(step: Step, subject: Subject<'_>) -> String {
    match step {
        Step::Artifact => format!(
            "build/reuse the artifact for module set `{}`",
            subject.module_set
        ),
        Step::Database => format!("create the D1 database for tenant `{}`", subject.tenant),
        Step::Worker => format!("deploy the Worker for tenant `{}`", subject.tenant),
        Step::Schema => "apply the venture's migrations".to_owned(),
        Step::Secrets => "seed the venture's secrets store".to_owned(),
        Step::Route => format!("bind the subdomain `{}`", subject.subdomain),
        Step::Health => "wait for /__health to answer".to_owned(),
    }
}

fn text(value: &str) -> SeaValue {
    SeaValue::String(Some(Box::new(value.to_owned())))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unused_async_trait_impl)] // the sync test fakes implement an async port
    use super::*;
    use cratefield_accounts::ENVIRONMENTS_MIGRATION;
    use cratefield_accounts::MIGRATION as ACCOUNTS_MIGRATION;
    use cratefield_adapter_sqlite::SqliteDatabase;
    use std::cell::{Cell, RefCell};

    /// A deployer that logs every call, can be told to fail one step, and
    /// controls what the health check returns.
    struct FakeDeployer {
        calls: RefCell<Vec<Step>>,
        fail: RefCell<Option<Step>>,
        health: Cell<bool>,
    }

    impl FakeDeployer {
        fn new() -> Self {
            Self {
                calls: RefCell::new(Vec::new()),
                fail: RefCell::new(None),
                health: Cell::new(true),
            }
        }
        fn failing_at(step: Step) -> Self {
            let d = Self::new();
            *d.fail.borrow_mut() = Some(step);
            d
        }
        fn log(&self, step: Step) -> Result<(), DeployError> {
            self.calls.borrow_mut().push(step);
            if *self.fail.borrow() == Some(step) {
                return Err(DeployError::new(format!("boom at {}", step.as_str())));
            }
            Ok(())
        }
        fn count(&self, step: Step) -> usize {
            self.calls.borrow().iter().filter(|s| **s == step).count()
        }
        fn order(&self) -> Vec<Step> {
            self.calls.borrow().clone()
        }
    }

    impl Deployer for FakeDeployer {
        async fn build_artifact(&self, _module_set: &str) -> Result<(), DeployError> {
            self.log(Step::Artifact)
        }
        async fn ensure_database(&self, _tenant: &str) -> Result<(), DeployError> {
            self.log(Step::Database)
        }
        async fn ensure_worker(&self, _t: &str, _m: &str) -> Result<(), DeployError> {
            self.log(Step::Worker)
        }
        async fn apply_schema(&self, _t: &str, _m: &str) -> Result<(), DeployError> {
            self.log(Step::Schema)
        }
        async fn seed_secrets(&self, _tenant: &str) -> Result<(), DeployError> {
            self.log(Step::Secrets)
        }
        async fn bind_route(&self, _t: &str, _s: &str) -> Result<(), DeployError> {
            self.log(Step::Route)
        }
        async fn health_ok(&self, _subdomain: &str) -> Result<bool, DeployError> {
            self.log(Step::Health)?;
            Ok(self.health.get())
        }
    }

    fn setup() -> (Engine, Repository, Arc<dyn Database>) {
        let db = SqliteDatabase::in_memory().expect("db");
        db.apply_migrations("accounts", &[ACCOUNTS_MIGRATION, ENVIRONMENTS_MIGRATION])
            .expect("accounts schema");
        db.apply_migrations("provisioning", &[MIGRATION, ENVIRONMENT_PROGRESS_MIGRATION])
            .expect("provisioning schema");
        let db: Arc<dyn Database> = Arc::new(db);
        (
            Engine::new(Arc::clone(&db)),
            Repository::new(Arc::clone(&db)),
            db,
        )
    }

    async fn a_venture(repo: &Repository) -> Venture {
        repo.account_for_login("ada@example.com", "Ada", "acc_1", "t0")
            .await
            .expect("account");
        repo.create_venture(
            "v1",
            "acc_1",
            "site",
            "site.cratefield.app",
            "cms+email-signup",
            "ten_1",
            "t0",
        )
        .await
        .expect("venture")
    }

    /// The environment progress row, read the way the screen reads it.
    async fn env_progress(db: &Arc<dyn Database>, environment_id: &str) -> (String, String) {
        let rows = db
            .query(&Statement::with_values(
                "SELECT last_step, error FROM environment_progress WHERE environment_id = ?",
                vec![text(environment_id)],
            ))
            .await
            .expect("environment progress");
        let row = rows.rows.first().expect("a row exists");
        (
            row.get("last_step").unwrap_or_default(),
            row.get("error").unwrap_or_default(),
        )
    }

    #[pollster::test]
    async fn a_clean_run_walks_every_step_in_order_and_goes_live() {
        let (engine, repo, _db) = setup();
        let venture = a_venture(&repo).await;
        let deployer = FakeDeployer::new();

        let status = engine
            .provision(&venture, &deployer, "t1")
            .await
            .expect("provisions");
        assert_eq!(status, VentureStatus::Live);
        assert_eq!(deployer.order(), STEPS.to_vec(), "every step, in order");

        let fresh = repo.venture_for("acc_1", "v1").await.unwrap().unwrap();
        assert_eq!(fresh.status, VentureStatus::Live);
    }

    #[pollster::test]
    async fn a_failed_step_leaves_the_venture_provisioning_and_names_the_step() {
        let (engine, repo, _db) = setup();
        let venture = a_venture(&repo).await;
        let deployer = FakeDeployer::failing_at(Step::Schema);

        let err = engine
            .provision(&venture, &deployer, "t1")
            .await
            .expect_err("fails");
        match err {
            ProvisionError::Step { step, .. } => assert_eq!(step, Step::Schema),
            other => panic!("wrong error: {other}"),
        }
        // Steps before Schema ran; Secrets onward did not.
        assert_eq!(deployer.count(Step::Worker), 1);
        assert_eq!(deployer.count(Step::Secrets), 0);
        // The venture is left provisioning, never live.
        let fresh = repo.venture_for("acc_1", "v1").await.unwrap().unwrap();
        assert_eq!(fresh.status, VentureStatus::Provisioning);
    }

    #[pollster::test]
    async fn a_resume_continues_from_the_last_completed_step_without_repeating() {
        let (engine, repo, _db) = setup();
        let venture = a_venture(&repo).await;

        // First run fails at Schema.
        let deployer = FakeDeployer::failing_at(Step::Schema);
        engine
            .provision(&venture, &deployer, "t1")
            .await
            .expect_err("fails at schema");
        assert_eq!(
            deployer.order(),
            vec![Step::Artifact, Step::Database, Step::Worker, Step::Schema]
        );

        // Second run, healthy, resumes from Schema. Re-fetch the venture (now
        // provisioning), so the engine reads its recorded progress.
        let venture = repo.venture_for("acc_1", "v1").await.unwrap().unwrap();
        let deployer2 = FakeDeployer::new();
        let status = engine
            .provision(&venture, &deployer2, "t2")
            .await
            .expect("resumes");
        assert_eq!(status, VentureStatus::Live);
        // The already-done steps were NOT called again in the second run.
        assert_eq!(deployer2.count(Step::Artifact), 0, "artifact not repeated");
        assert_eq!(deployer2.count(Step::Database), 0, "database not repeated");
        assert_eq!(deployer2.count(Step::Worker), 0, "worker not repeated");
        assert_eq!(
            deployer2.order(),
            vec![Step::Schema, Step::Secrets, Step::Route, Step::Health],
            "resumes at schema"
        );
    }

    #[pollster::test]
    async fn a_completed_venture_re_provisions_as_a_no_op() {
        let (engine, repo, _db) = setup();
        let venture = a_venture(&repo).await;
        engine
            .provision(&venture, &FakeDeployer::new(), "t1")
            .await
            .expect("live");

        let live = repo.venture_for("acc_1", "v1").await.unwrap().unwrap();
        let deployer = FakeDeployer::new();
        let status = engine
            .provision(&live, &deployer, "t2")
            .await
            .expect("no-op");
        assert_eq!(status, VentureStatus::Live);
        assert!(
            deployer.order().is_empty(),
            "a live venture triggers no deploy work"
        );
    }

    #[pollster::test]
    async fn a_health_check_that_does_not_pass_is_a_retryable_failure() {
        let (engine, repo, _db) = setup();
        let venture = a_venture(&repo).await;
        let deployer = FakeDeployer::new();
        deployer.health.set(false);

        let err = engine
            .provision(&venture, &deployer, "t1")
            .await
            .expect_err("health fails");
        match err {
            ProvisionError::Step { step, message } => {
                assert_eq!(step, Step::Health);
                assert!(message.contains("__health"), "{message}");
            }
            other => panic!("wrong error: {other}"),
        }
        let fresh = repo.venture_for("acc_1", "v1").await.unwrap().unwrap();
        assert_eq!(
            fresh.status,
            VentureStatus::Provisioning,
            "retryable, not live"
        );
    }

    #[pollster::test]
    async fn plan_lists_every_step_and_reflects_progress_without_deploying() {
        let (engine, repo, _db) = setup();
        let venture = a_venture(&repo).await;

        // Before anything: all steps pending.
        let plan = engine.plan(&venture).await.unwrap();
        assert_eq!(plan.len(), STEPS.len());
        assert!(plan.iter().all(|p| !p.done), "nothing done yet");
        assert!(
            plan[0].description.contains("cms+email-signup"),
            "{:?}",
            plan[0]
        );

        // After a run that stops at Schema, the first three read done.
        let failing = FakeDeployer::failing_at(Step::Schema);
        engine
            .provision(&venture, &failing, "t1")
            .await
            .expect_err("stops");
        let venture = repo.venture_for("acc_1", "v1").await.unwrap().unwrap();
        let plan = engine.plan(&venture).await.unwrap();
        let done: Vec<Step> = plan.iter().filter(|p| p.done).map(|p| p.step).collect();
        assert_eq!(done, vec![Step::Artifact, Step::Database, Step::Worker]);
    }

    // -------------------------------------------------------------------
    // Environments (#31): same engine, same port, its own ledger
    // -------------------------------------------------------------------

    async fn a_staging_environment(repo: &Repository) -> cratefield_accounts::Environment {
        a_venture(repo).await;
        repo.set_venture_status("acc_1", "v1", VentureStatus::Provisioning, "t1")
            .await
            .expect("provisioning");
        repo.set_venture_status("acc_1", "v1", VentureStatus::Live, "t2")
            .await
            .expect("live");
        repo.create_environment("env_1", "acc_1", "v1", "staging", "ten_stg", "t3")
            .await
            .expect("staging")
    }

    #[pollster::test]
    async fn an_environment_provisions_through_the_engine_without_touching_the_venture() {
        let (engine, repo, db) = setup();
        let staging = a_staging_environment(&repo).await;
        let deployer = FakeDeployer::new();

        engine
            .provision_environment(&staging, &deployer, "t4")
            .await
            .expect("provisions");

        // Every step ran, against the environment's own triple: the
        // deployer saw the staging tenant and set, and the ledger says
        // health.
        assert_eq!(deployer.order(), STEPS.to_vec());
        let (last, error) = env_progress(&db, "env_1").await;
        assert_eq!(last, "health");
        assert_eq!(error, "");

        // The venture is untouched: still Live, still its own set, and
        // no row appeared in the venture's ledger. A staging run must
        // never read as the venture itself provisioning.
        let venture = repo.venture_for("acc_1", "v1").await.unwrap().unwrap();
        assert_eq!(venture.status, VentureStatus::Live);
        assert_eq!(venture.module_set, "cms+email-signup");
        let rows = db
            .query(&Statement::new(
                "SELECT last_step FROM provision_progress WHERE venture_id = 'v1'".to_owned(),
            ))
            .await
            .expect("venture ledger");
        assert!(rows.is_empty(), "the venture's ledger stays empty");

        // A completed environment re-runs as a no-op, like a venture's.
        let again = FakeDeployer::new();
        engine
            .provision_environment(&staging, &again, "t5")
            .await
            .expect("no-op");
        assert!(again.order().is_empty(), "nothing to do again");
    }

    #[pollster::test]
    async fn a_stopped_environment_run_records_its_step_and_resumes() {
        let (engine, repo, db) = setup();
        let staging = a_staging_environment(&repo).await;

        let failing = FakeDeployer::failing_at(Step::Artifact);
        let err = engine
            .provision_environment(&staging, &failing, "t4")
            .await
            .expect_err("stops at the first step");
        match err {
            ProvisionError::Step { step, .. } => assert_eq!(step, Step::Artifact),
            other => panic!("wrong error: {other}"),
        }
        let (last, error) = env_progress(&db, "env_1").await;
        assert_eq!(last, "", "nothing completed before the failure");
        assert!(error.contains("boom at artifact"), "{error}");

        // And the venture is still Live, not dragged into provisioning.
        let venture = repo.venture_for("acc_1", "v1").await.unwrap().unwrap();
        assert_eq!(venture.status, VentureStatus::Live);

        // A resume continues from where it stopped.
        let deployer = FakeDeployer::new();
        engine
            .provision_environment(&staging, &deployer, "t5")
            .await
            .expect("resumes");
        assert_eq!(deployer.order(), STEPS.to_vec(), "resumed from the start");
        let (last, error) = env_progress(&db, "env_1").await;
        assert_eq!(last, "health");
        assert_eq!(error, "");
    }

    #[pollster::test]
    async fn an_environment_plan_names_its_own_tenant_and_set() {
        let (engine, repo, _db) = setup();
        let staging = a_staging_environment(&repo).await;

        let plan = engine.plan_environment(&staging).await.unwrap();
        assert_eq!(plan.len(), STEPS.len());
        assert!(plan.iter().all(|p| !p.done), "nothing done yet");
        assert!(
            plan.iter()
                .any(|p| p.description.contains("ten_stg") && p.step == Step::Database),
            "the plan describes the environment's own tenant: {plan:?}"
        );
        assert!(
            plan[0].description.contains("cms+email-signup"),
            "and its own module set: {plan:?}"
        );
    }

    #[test]
    fn completed_through_reads_the_sequence_not_the_names() {
        // "did this run complete the schema step" — the question
        // promotion's rehearsal rule turns on, answered here once.
        assert!(Step::completed_through("health", Step::Schema));
        assert!(Step::completed_through("schema", Step::Schema));
        assert!(!Step::completed_through("worker", Step::Schema));
        assert!(!Step::completed_through("", Step::Schema));
        assert!(!Step::completed_through("nonsense", Step::Schema));
    }
}
