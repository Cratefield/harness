//! The routes and the cron, through the same harness the Worker serves.

use cratefield_core::{MapConfig, Module, Ports, Statement, UlidIdGen};
use cratefield_testing::{TestHarness, request};
use sidecar_module_template::module::Notes;
use std::sync::Arc;
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

fn kit() -> TestHarness {
    TestHarness::new(vec![Box::new(Notes::new())])
}

fn module_ports(kit: &TestHarness) -> Ports {
    let mut ports = Ports::with_config(Arc::new(MapConfig::default()));
    ports.db = Some(kit.db.clone());
    ports.signer = Some(kit.signer.clone());
    ports.mailer = Some(Arc::new(kit.mailer.clone()));
    ports.captcha = Some(Arc::new(kit.captcha.clone()));
    ports.rate_limiter = Some(Arc::new(kit.rate_limiter.clone()));
    ports.clock = Some(Arc::new(kit.clock.clone()));
    ports.id_gen = Some(Arc::new(UlidIdGen));
    ports.defer = Some(Arc::new(kit.defer.clone()));
    ports
}

fn iso_at(days_ago: u32) -> String {
    (OffsetDateTime::now_utc() - time::Duration::days(i64::from(days_ago)))
        .format(&Rfc3339)
        .unwrap_or_default()
}

fn seed(kit: &TestHarness, id: &str, text: &str, created_at: &str) {
    let query = sea_query::Query::insert()
        .into_table(sea_query::Alias::new("sidecar_notes"))
        .columns([
            sea_query::Alias::new("id"),
            sea_query::Alias::new("text"),
            sea_query::Alias::new("created_at"),
        ])
        .values_panic([id.into(), text.into(), created_at.into()])
        .to_owned();
    pollster::block_on(async {
        kit.db
            .execute(&Statement::render(&query))
            .await
            .expect("seed insert");
    });
}

fn count(kit: &TestHarness) -> usize {
    let query = sea_query::Query::select()
        .column(sea_query::Alias::new("id"))
        .from(sea_query::Alias::new("sidecar_notes"))
        .to_owned();
    pollster::block_on(async { kit.db.query(&Statement::render(&query)).await })
        .expect("count select")
        .len()
}

#[pollster::test]
async fn a_written_note_is_the_latest_note() {
    let kit = kit();
    let res = request(
        &kit.router,
        http::Method::POST,
        "/v1/notes",
        Some(r#"{"text":"hello from the sidecar"}"#),
    )
    .await;
    assert_eq!(res.status, http::StatusCode::OK);
    assert!(res.json().get("id").is_some(), "the write answers its id");

    let res = request(&kit.router, http::Method::GET, "/v1/notes/latest", None).await;
    assert_eq!(res.status, http::StatusCode::OK);
    assert_eq!(
        res.json().get("text").and_then(|v| v.as_str()),
        Some("hello from the sidecar")
    );
}

#[pollster::test]
async fn the_purge_deletes_only_expired_notes() {
    let kit = kit();
    seed(&kit, "01 old", "long gone", &iso_at(40));
    seed(&kit, "02 new", "still here", &iso_at(1));

    let ports = module_ports(&kit);
    let module = kit.modules[0].clone();
    let ctx = kit.harness.module_context(module.as_ref(), &ports);
    module
        .scheduled(&ctx, "17 3 * * *")
        .await
        .expect("scheduled run");

    assert_eq!(count(&kit), 1, "only the expired note is purged");
}

#[pollster::test]
async fn a_zero_or_non_numeric_retention_is_rejected() {
    for bad in ["0", "soon"] {
        let config = MapConfig::from_pairs([("NOTES_RETENTION_DAYS", bad)]);
        let err = Notes::new()
            .validate_config(&config)
            .expect_err("the value must be rejected");
        assert!(
            err.to_string().contains("NOTES_RETENTION_DAYS"),
            "the refusal names the variable: {err}"
        );
    }
}

#[test]
fn the_wasm_build_declares_the_same_route_the_tests_exercise() {
    // The Worker's lib is where the route prefix would be hardcoded a
    // second time if anything did; nothing does. This exists to fail the
    // day someone renames the module without noticing the mount depends
    // on the name, and to keep the "one route, one table" shape honest in
    // the face of edits.
    let module = Notes::new();
    assert_eq!(module.name(), "notes");
    assert_eq!(module.tables(), ["sidecar_notes"]);
    assert_eq!(module.emits(), [] as [&str; 0]);
}
