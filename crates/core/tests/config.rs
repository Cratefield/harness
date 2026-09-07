//! `HarnessConfig` + `ModuleConfig` tests (issue #3): missing keys are
//! named together with the module; extra keys are ignored; `Ports::view_for`
//! hides undeclared ports.

use async_trait::async_trait;
use cratefield_core::{
    Config, ConfigError, Database, DbError, HarnessConfig, MapConfig, Migrations, Module,
    ModuleConfig, ModuleContext, Port, Statement,
};
use std::sync::Arc;

// Obvious dummy secret, never real.
const SECRET: &str = "test-secret-0123456789abcdef-0123";

#[test]
fn harness_config_parses_all_keys() {
    let config = MapConfig::from_pairs([
        ("HARNESS_SECRET", SECRET),
        (
            "HARNESS_SECRET_PREVIOUS",
            "test-secret-old-0123456789abcdef-x",
        ),
        ("ADMIN_TOKEN", "test-admin-token"),
        ("ENV", "staging"),
    ]);
    let parsed = HarnessConfig::from_config(&config).expect("parses");
    assert_eq!(parsed.harness_secret, SECRET);
    assert!(parsed.harness_secret_previous.is_some());
    assert_eq!(parsed.admin_token.as_deref(), Some("test-admin-token"));
    assert_eq!(parsed.env, cratefield_core::VentureEnv::Staging);
    parsed.signer();
}

#[test]
fn missing_secret_names_the_key() {
    let errors = HarnessConfig::from_config(&MapConfig::default())
        .expect_err("must fail")
        .problems;
    assert!(
        errors
            .iter()
            .any(|e| e.contains("HARNESS_SECRET is required")),
        "errors: {errors:?}"
    );
}

#[test]
fn short_secret_names_the_minimum() {
    let config = MapConfig::from_pairs([("HARNESS_SECRET", "short")]);
    let errors = HarnessConfig::from_config(&config)
        .expect_err("must fail")
        .problems;
    assert!(
        errors
            .iter()
            .any(|e| e.contains("at least 32 bytes") && e.contains("HARNESS_SECRET")),
        "errors: {errors:?}"
    );
}

#[test]
fn invalid_env_names_the_key_and_value() {
    let config = MapConfig::from_pairs([("HARNESS_SECRET", SECRET), ("ENV", "prod")]);
    let errors = HarnessConfig::from_config(&config)
        .expect_err("must fail")
        .problems;
    assert!(
        errors
            .iter()
            .any(|e| e.contains("ENV") && e.contains("prod")),
        "errors: {errors:?}"
    );
}

#[test]
fn env_defaults_to_development() {
    let config = MapConfig::from_pairs([("HARNESS_SECRET", SECRET)]);
    let parsed = HarnessConfig::from_config(&config).expect("parses");
    assert_eq!(parsed.env, cratefield_core::VentureEnv::Development);
}

/// Module-key reporting: a module missing a required key reports the module
/// name and the fully-qualified key together.
#[test]
fn module_missing_required_key_names_module_and_key() {
    let config = MapConfig::default();
    let module = ModuleConfig::new("email-signup", &config);
    let required = "CONFIRM_TTL_DAYS";
    assert!(module.get_opt(required).is_none(), "key absent");

    // The pattern a module's validate_config uses:
    let mut errors = ConfigError::default();
    if module.get_opt(required).is_none() {
        errors.push(format!(
            "module `email-signup`: missing required config key {}",
            module.key(required)
        ));
    }
    let joined = errors.problems.join("\n");
    assert!(
        joined.contains("module `email-signup`")
            && joined.contains("EMAIL_SIGNUP_CONFIRM_TTL_DAYS"),
        "joined: {joined}"
    );
}

#[test]
fn module_extra_keys_are_ignored() {
    let config = MapConfig::from_pairs([
        ("EMAIL_SIGNUP_CONFIRM_TTL_DAYS", "3"),
        ("EMAIL_SIGNUP_UNKNOWN_EXTRA", "x"),
        ("TOTALLY_UNRELATED", "y"),
    ]);
    let module = ModuleConfig::new("email-signup", &config);
    assert_eq!(module.get_u32("CONFIRM_TTL_DAYS", 7), 3);
    assert_eq!(module.get_str("FROM_NAME", "Factory Zero"), "Factory Zero");
    assert!(!module.get_bool("DOUBLE_OPT_IN", false));
}

#[test]
fn module_key_prefixing_is_screaming_snake() {
    let config = MapConfig::from_pairs([("WAITLIST_PRODUCTS", "kontinuum")]);
    let module = ModuleConfig::new("waitlist", &config);
    assert_eq!(module.get_str("PRODUCTS", ""), "kontinuum");
    assert_eq!(module.key("PRODUCTS"), "WAITLIST_PRODUCTS");
    assert_eq!(
        ModuleConfig::new("email-signup", &config).key("confirm_ttl_days"),
        "EMAIL_SIGNUP_CONFIRM_TTL_DAYS"
    );
}

struct FakeDb;

#[async_trait]
impl Database for FakeDb {
    async fn execute(&self, _stmt: &Statement) -> Result<u64, DbError> {
        Ok(0)
    }
    async fn query(&self, _stmt: &Statement) -> Result<cratefield_core::Rows, DbError> {
        Ok(cratefield_core::Rows::new(vec![]))
    }
    async fn batch(&self, _stmts: &[Statement]) -> Result<(), DbError> {
        Ok(())
    }
}

struct UndeclaringModule;

impl Module for UndeclaringModule {
    fn name(&self) -> &'static str {
        "undeclaring"
    }
    fn version(&self) -> &'static str {
        "0.0.0"
    }
    fn requires(&self) -> &'static [Port] {
        &[]
    }
    fn migrations(&self) -> Migrations {
        Migrations::default()
    }
    fn validate_config(&self, _cfg: &dyn Config) -> Result<(), ConfigError> {
        Ok(())
    }
    fn router(&self, _ctx: ModuleContext) -> axum::Router {
        axum::Router::new()
    }
}

struct DeclaringModule;

impl Module for DeclaringModule {
    fn name(&self) -> &'static str {
        "declaring"
    }
    fn version(&self) -> &'static str {
        "0.0.0"
    }
    fn requires(&self) -> &'static [Port] {
        &[Port::Db]
    }
    fn migrations(&self) -> Migrations {
        Migrations::default()
    }
    fn validate_config(&self, _cfg: &dyn Config) -> Result<(), ConfigError> {
        Ok(())
    }
    fn router(&self, _ctx: ModuleContext) -> axum::Router {
        axum::Router::new()
    }
}

/// `Ports::view_for`: a module reading an undeclared port gets `None`.
#[test]
fn view_for_hides_undeclared_ports() {
    let mut ports = cratefield_core::Ports::empty();
    ports.db = Some(Arc::new(FakeDb));
    assert!(ports.db.is_some(), "fixture: db is provided");

    let view = ports.view_for(&UndeclaringModule);
    assert!(view.db.is_none(), "undeclared Database port must be hidden");

    let view = ports.view_for(&DeclaringModule);
    assert!(view.db.is_some(), "declared Database port stays visible");
}

#[test]
fn statement_renders_sea_query_for_sqlite() {
    use sea_query::{Expr, Query};

    let query = Query::select()
        .column(sea_query::Alias::new("email"))
        .from(sea_query::Alias::new("subscribers"))
        .and_where(Expr::col(sea_query::Alias::new("status")).eq("pending"))
        .limit(1)
        .take();
    let stmt = cratefield_core::Statement::render(&query);
    assert!(stmt.sql.contains("SELECT"));
    assert!(stmt.sql.contains("FROM"));
    assert!(
        stmt.sql.contains('?'),
        "positional placeholders: {}",
        stmt.sql
    );
    // Two bound values: the status literal and the LIMIT.
    assert_eq!(stmt.values.0.len(), 2, "bound values: {:?}", stmt.values.0);
}
