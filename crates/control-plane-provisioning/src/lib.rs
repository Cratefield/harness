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

use cratefield_accounts::{RepoError, Repository, Venture, VentureStatus};
use cratefield_core::{Database, DbError, Statement};
use sea_query::Value as SeaValue;

/// The schema migration: the `provision_progress` table.
pub const MIGRATION: cratefield_core::SqlMigration = cratefield_core::SqlMigration {
    id: "0001",
    name: "init",
    sql: include_str!("../migrations/sqlite/0001_init.sql"),
    transactional: true,
};

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
        let last = self.last_completed(&venture.id).await?;
        let done_through = last.map_or(-1, |s| i64::try_from(s.index()).unwrap_or(-1));
        Ok(STEPS
            .into_iter()
            .map(|step| PlannedStep {
                step,
                done: i64::try_from(step.index()).unwrap_or(0) <= done_through,
                description: describe(step, venture),
            })
            .collect())
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
        let start = match self.last_completed(&venture.id).await? {
            Some(last) => last.index() + 1,
            None => 0,
        };

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

        for step in &STEPS[start..] {
            let step = *step;
            if let Err(err) = run_step(deployer, step, venture).await {
                self.record_error(&venture.id, step, &err.message, now)
                    .await?;
                return Err(ProvisionError::Step {
                    step,
                    message: err.message,
                });
            }
            self.record_done(&venture.id, step, now).await?;
        }

        Ok(self.mark_live(venture, now).await?)
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

    /// The last step recorded complete for a venture, or `None`.
    async fn last_completed(&self, venture_id: &str) -> Result<Option<Step>, ProvisionError> {
        let rows = self
            .db
            .query(&Statement::with_values(
                "SELECT last_step FROM provision_progress WHERE venture_id = ?",
                vec![text(venture_id)],
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
        venture_id: &str,
        step: Step,
        now: &str,
    ) -> Result<(), ProvisionError> {
        self.upsert(venture_id, step.as_str(), "", now).await
    }

    async fn record_error(
        &self,
        venture_id: &str,
        step: Step,
        message: &str,
        now: &str,
    ) -> Result<(), ProvisionError> {
        // Keep the last completed step as-is; only record which step failed and
        // why, so a resume still starts after the last success.
        let last = self.last_completed(venture_id).await?;
        let last_str = last.map_or("", Step::as_str);
        self.upsert(
            venture_id,
            last_str,
            &format!("{}: {message}", step.as_str()),
            now,
        )
        .await
    }

    async fn upsert(
        &self,
        venture_id: &str,
        last_step: &str,
        error: &str,
        now: &str,
    ) -> Result<(), ProvisionError> {
        self.db
            .execute(&Statement::with_values(
                "INSERT INTO provision_progress (venture_id, last_step, error, updated_at) \
                 VALUES (?, ?, ?, ?) \
                 ON CONFLICT(venture_id) DO UPDATE SET \
                 last_step = excluded.last_step, error = excluded.error, \
                 updated_at = excluded.updated_at",
                vec![text(venture_id), text(last_step), text(error), text(now)],
            ))
            .await?;
        Ok(())
    }
}

async fn run_step<D: Deployer>(
    deployer: &D,
    step: Step,
    venture: &Venture,
) -> Result<(), DeployError> {
    let tenant = &venture.tenant_id;
    match step {
        Step::Artifact => deployer.build_artifact(&venture.module_set).await,
        Step::Database => deployer.ensure_database(tenant).await,
        Step::Worker => deployer.ensure_worker(tenant, &venture.module_set).await,
        Step::Schema => deployer.apply_schema(tenant, &venture.module_set).await,
        Step::Secrets => deployer.seed_secrets(tenant).await,
        Step::Route => deployer.bind_route(tenant, &venture.subdomain).await,
        Step::Health => {
            if deployer.health_ok(&venture.subdomain).await? {
                Ok(())
            } else {
                Err(DeployError::new("the venture did not answer /__health yet"))
            }
        }
    }
}

fn describe(step: Step, venture: &Venture) -> String {
    match step {
        Step::Artifact => format!(
            "build/reuse the artifact for module set `{}`",
            venture.module_set
        ),
        Step::Database => format!("create the D1 database for tenant `{}`", venture.tenant_id),
        Step::Worker => format!("deploy the Worker for tenant `{}`", venture.tenant_id),
        Step::Schema => "apply the venture's migrations".to_owned(),
        Step::Secrets => "seed the venture's secrets store".to_owned(),
        Step::Route => format!("bind the subdomain `{}`", venture.subdomain),
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
        db.apply_migrations("accounts", &[ACCOUNTS_MIGRATION])
            .expect("accounts schema");
        db.apply_migrations("provisioning", &[MIGRATION])
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
}
