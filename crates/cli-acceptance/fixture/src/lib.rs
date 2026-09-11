//! Fixture venture for the cratefield-cli tests (issue #8): an
//! `email-signup` and a `waitlist` module with real embedded migrations,
//! plus an extensible `harness_v2` that adds a third module and a second
//! migration to the first — exactly the acceptance scenario.

#![forbid(unsafe_code)]

use cratefield_core::{
    Config, ConfigError, Harness, Migrations, Module, ModuleContext, Port, Runtime, SqlMigration,
    Venture,
};

pub const EMAIL_SIGNUP_INIT: SqlMigration = SqlMigration::new(
    "0001",
    "init",
    "CREATE TABLE IF NOT EXISTS subscribers (
    id TEXT PRIMARY KEY,
    email TEXT NOT NULL,
    email_normalized TEXT NOT NULL UNIQUE,
    status TEXT NOT NULL,
    source TEXT,
    locale TEXT,
    confirmed_at TEXT,
    unsubscribed_at TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);",
);

pub const EMAIL_SIGNUP_ADD_SOURCE: SqlMigration = SqlMigration::new(
    "0002",
    "add_source_index",
    "CREATE INDEX IF NOT EXISTS subscribers_source_idx ON subscribers (source);",
);

pub const WAITLIST_INIT: SqlMigration = SqlMigration::new(
    "0001",
    "init",
    "CREATE TABLE IF NOT EXISTS waitlist_entries (
    id TEXT PRIMARY KEY,
    email TEXT NOT NULL,
    email_normalized TEXT NOT NULL,
    product TEXT NOT NULL,
    status TEXT NOT NULL,
    position INTEGER,
    referral_code TEXT NOT NULL UNIQUE,
    referred_by TEXT,
    referrals INTEGER NOT NULL DEFAULT 0,
    answers TEXT,
    created_at TEXT NOT NULL,
    confirmed_at TEXT
);",
);

pub const AUDIT_INIT: SqlMigration = SqlMigration::new(
    "0001",
    "init",
    "CREATE TABLE IF NOT EXISTS audit_events (
    id TEXT PRIMARY KEY,
    kind TEXT NOT NULL,
    payload TEXT NOT NULL,
    created_at TEXT NOT NULL
);",
);

pub struct EmailSignupFixture {
    pub with_add_source: bool,
}

impl Module for EmailSignupFixture {
    fn name(&self) -> &'static str {
        "email-signup"
    }
    fn version(&self) -> &'static str {
        "0.1.0"
    }
    fn requires(&self) -> &'static [Port] {
        &[]
    }
    fn tables(&self) -> &'static [&'static str] {
        &["subscribers"]
    }
    fn migrations(&self) -> Migrations {
        const ONE: [SqlMigration; 1] = [EMAIL_SIGNUP_INIT];
        const TWO: [SqlMigration; 2] = [EMAIL_SIGNUP_INIT, EMAIL_SIGNUP_ADD_SOURCE];
        let migrations: &'static [SqlMigration] = if self.with_add_source { &TWO } else { &ONE };
        Migrations {
            sqlite: migrations,
            postgres: &[],
        }
    }
    fn validate_config(&self, _cfg: &dyn Config) -> Result<(), ConfigError> {
        Ok(())
    }
    fn router(&self, _ctx: ModuleContext) -> axum::Router {
        axum::Router::new()
    }
}

pub struct WaitlistFixture;

impl Module for WaitlistFixture {
    fn name(&self) -> &'static str {
        "waitlist"
    }
    fn version(&self) -> &'static str {
        "0.1.0"
    }
    fn requires(&self) -> &'static [Port] {
        &[]
    }
    fn tables(&self) -> &'static [&'static str] {
        &["waitlist_entries"]
    }
    fn emits(&self) -> &'static [&'static str] {
        &["waitlist.confirmed"]
    }
    fn migrations(&self) -> Migrations {
        const MIGRATIONS: [SqlMigration; 1] = [WAITLIST_INIT];
        Migrations {
            sqlite: &MIGRATIONS,
            postgres: &[],
        }
    }
    fn validate_config(&self, _cfg: &dyn Config) -> Result<(), ConfigError> {
        Ok(())
    }
    fn router(&self, _ctx: ModuleContext) -> axum::Router {
        axum::Router::new()
    }
}

pub struct AuditLogFixture;

impl Module for AuditLogFixture {
    fn name(&self) -> &'static str {
        "audit-log"
    }
    fn version(&self) -> &'static str {
        "0.1.0"
    }
    fn requires(&self) -> &'static [Port] {
        &[]
    }
    fn tables(&self) -> &'static [&'static str] {
        &["audit_events"]
    }
    fn migrations(&self) -> Migrations {
        const MIGRATIONS: [SqlMigration; 1] = [AUDIT_INIT];
        Migrations {
            sqlite: &MIGRATIONS,
            postgres: &[],
        }
    }
    fn validate_config(&self, _cfg: &dyn Config) -> Result<(), ConfigError> {
        Ok(())
    }
    fn router(&self, _ctx: ModuleContext) -> axum::Router {
        axum::Router::new()
    }
}

/// A module that reports a problem in its own embedded data (issue
/// #190). The notifications module answers `self_check` with every
/// translation its catalog is missing; this fixture stands in for it so
/// the doctor's handling of that answer is testable without composing a
/// venture with a Fluent catalog in it.
pub struct SelfCheckFixture {
    pub problems: &'static [&'static str],
}

impl Module for SelfCheckFixture {
    fn name(&self) -> &'static str {
        "self-check"
    }
    fn version(&self) -> &'static str {
        "0.1.0"
    }
    fn requires(&self) -> &'static [Port] {
        &[]
    }
    fn migrations(&self) -> Migrations {
        Migrations::EMPTY
    }
    fn validate_config(&self, _cfg: &dyn Config) -> Result<(), ConfigError> {
        Ok(())
    }
    fn self_check(&self) -> Vec<String> {
        self.problems
            .iter()
            .map(|text| (*text).to_owned())
            .collect()
    }
    fn router(&self, _ctx: ModuleContext) -> axum::Router {
        axum::Router::new()
    }
}

pub struct AllPorts;

impl Runtime for AllPorts {
    fn provides(&self) -> Vec<Port> {
        Port::ALL.to_vec()
    }
}

pub struct NoCaptchaRuntime;

impl Runtime for NoCaptchaRuntime {
    fn provides(&self) -> Vec<Port> {
        Port::ALL
            .iter()
            .copied()
            .filter(|port| *port != Port::Captcha)
            .collect()
    }
}

fn base_venture() -> Venture {
    Venture::new("fixture-venture", "fixture.example").cors_origins(["https://fixture.example"])
}

/// The v1 harness: email-signup (one migration) + waitlist.
pub fn harness_v1() -> Harness {
    Harness::builder()
        .venture(base_venture())
        .module(EmailSignupFixture {
            with_add_source: false,
        })
        .module(WaitlistFixture)
        .runtime(AllPorts)
        .build()
        .expect("fixture harness v1 builds")
}

/// [`harness_v1`] plus a module that reports its own problems.
#[must_use]
pub fn harness_with_self_check(problems: &'static [&'static str]) -> Harness {
    Harness::builder()
        .venture(base_venture())
        .module(EmailSignupFixture {
            with_add_source: false,
        })
        .module(WaitlistFixture)
        .module(SelfCheckFixture { problems })
        .runtime(AllPorts)
        .build()
        .expect("fixture harness with a self-check builds")
}

/// The v2 harness: adds audit-log and a second email-signup migration.
pub fn harness_v2() -> Harness {
    Harness::builder()
        .venture(base_venture())
        .module(EmailSignupFixture {
            with_add_source: true,
        })
        .module(WaitlistFixture)
        .module(AuditLogFixture)
        .runtime(AllPorts)
        .build()
        .expect("fixture harness v2 builds")
}
