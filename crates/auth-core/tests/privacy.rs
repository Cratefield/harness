//! Issue #265: the declarations, proved against the module that reads them.
//!
//! `Module::personal_data()` is a promise about behaviour that lives in
//! another crate — `cratefield-module-privacy` plans an export and an erasure
//! from it — so asserting the list against itself would prove nothing. These
//! compose the two modules the way a venture does and drive the routes.
//!
//! Every venture composes `auth-core`, so an erasure that does not reach here
//! reaches nothing. A session left behind is a way back in and a credential
//! left behind is *the* way in, and both of those surviving an erasure is the
//! worst of the five modules issue #265 covers.

use axum::http::{Method, StatusCode, header};
use cratefield_core::{Config, MapConfig, Statement};
use cratefield_module_privacy::Privacy;
use cratefield_testing::TestHarness;
use factory0_auth_core::AuthCore;
use serde_json::Value;
use std::sync::Arc;
use tower::ServiceExt;

const ADMIN: &str = "test-admin-token-0123456789abcdef";
const ALICE: &str = "01HCAUTHUSERALICE0000000001";
const BOB: &str = "01HCAUTHUSERBOB000000000002";

/// An argon2id PHC string. Not a bearer token, but crackable offline, and
/// this module already refuses to print it anywhere else.
const PASSWORD_HASH: &str = "$argon2id$v=19$m=19456,t=2,p=1$c2FsdHNhbHQ$hash-of-a-real-password";

/// The `redirect_uri`, the PKCE challenge and a live session id, which is
/// what an authorization code's payload carries.
const CODE_PAYLOAD: &str = r#"{"redirect_uri":"https://app.example.test/callback","code_challenge":"pkce","sid":"sess-1"}"#;

/// Every table the module owns that holds a person **and loses the rows**, in
/// declaration order. `deletion_jobs` holds a person too and is not here: it
/// is [`RETAINED_TABLES`], because erasure keeps it.
const SUBJECT_TABLES: &[&str] = &[
    "users",
    "identities",
    "credentials",
    "sessions",
    "single_use_tokens",
];

/// The tables that hold a person and survive an erasure, with the reason
/// published beside them (issue #272).
///
/// `deletion_jobs` records that a provider asked us to delete somebody and
/// what was done about it. Deleting that row would stop the status page the
/// provider was promised from answering and destroy the evidence that the
/// erasure happened, so it is `Disposition::Retain` — which is a declaration
/// the manifest and the erasure preview both have to show, not a silence.
const RETAINED_TABLES: &[&str] = &["deletion_jobs"];

/// Every table the module declares as holding a person, in declaration order:
/// what `GET /v1/privacy/manifest` publishes and what an erasure plans over.
fn declared_tables() -> Vec<&'static str> {
    SUBJECT_TABLES
        .iter()
        .chain(RETAINED_TABLES)
        .copied()
        .collect()
}

fn privacy_kit() -> TestHarness {
    let config: Arc<dyn Config> = Arc::new(MapConfig::from_pairs([
        ("ADMIN_TOKEN".to_owned(), ADMIN.to_owned()),
        (
            "HARNESS_SECRET".to_owned(),
            "cratefield-testing-dummy-secret-0123456789".to_owned(),
        ),
    ]));
    TestHarness::with_ports(
        vec![Box::new(AuthCore::new()), Box::new(Privacy::new())],
        move |ports| {
            ports.config = Arc::clone(&config);
        },
    )
}

/// One account with one of everything, written straight to the database: the
/// point under test is what the declarations reach, not how the rows got
/// there.
async fn seed(kit: &TestHarness, user: &str, email: &str) {
    let at = "2026-01-01T00:00:00Z";
    let rows: Vec<(&str, &str, Vec<sea_query::Value>)> = vec![
        (
            "users",
            "INSERT INTO users (id, display_name, primary_email, primary_email_verified, status, \
             created_at, updated_at) VALUES (?, ?, ?, 1, 'active', ?, ?)",
            vec![
                user.into(),
                "Alex".into(),
                email.into(),
                at.into(),
                at.into(),
            ],
        ),
        (
            "identities",
            "INSERT INTO identities (id, user_id, provider, provider_subject, email, \
             email_verified, name_at_link, created_at) VALUES (?, ?, 'google', ?, ?, 1, ?, ?)",
            vec![
                format!("id-{user}").into(),
                user.into(),
                format!("google-{user}").into(),
                email.into(),
                "Alex".into(),
                at.into(),
            ],
        ),
        (
            "credentials",
            "INSERT INTO credentials (id, user_id, kind, password_hash, label, created_at, \
             failed_attempts) VALUES (?, ?, 'password', ?, 'laptop', ?, 0)",
            vec![
                format!("cred-{user}").into(),
                user.into(),
                PASSWORD_HASH.into(),
                at.into(),
            ],
        ),
        (
            "sessions",
            "INSERT INTO sessions (id, user_id, token_hash, created_at, last_seen_at, \
             expires_at, ip_hash, ua_family) VALUES (?, ?, ?, ?, ?, ?, ?, 'Firefox')",
            vec![
                format!("sess-{user}").into(),
                user.into(),
                format!("session-cookie-digest-{user}")
                    .as_bytes()
                    .to_vec()
                    .into(),
                at.into(),
                at.into(),
                "2027-01-01T00:00:00Z".into(),
                format!("iphash-{user}").into(),
            ],
        ),
        (
            "single_use_tokens",
            "INSERT INTO single_use_tokens (id, kind, token_hash, user_id, client_id, payload, \
             expires_at) VALUES (?, 'authorization_code', ?, ?, 'app', ?, ?)",
            vec![
                format!("sut-{user}").into(),
                format!("code-digest-{user}").as_bytes().to_vec().into(),
                user.into(),
                CODE_PAYLOAD.into(),
                "2027-01-01T00:00:00Z".into(),
            ],
        ),
    ];
    for (table, sql, values) in rows {
        kit.db
            .execute(&Statement::with_values(sql.to_owned(), values))
            .await
            .unwrap_or_else(|err| panic!("seeding {table} failed: {err}"));
    }
}

/// Rows in one table for one user. `users` keys on `id`, everything else on
/// `user_id` — the same split the declarations make.
async fn count_for(kit: &TestHarness, table: &str, user: &str) -> i64 {
    let column = if table == "users" { "id" } else { "user_id" };
    let rows = kit
        .db
        .query(&Statement::with_values(
            format!("SELECT COUNT(*) AS n FROM {table} WHERE {column} = ?"),
            vec![user.into()],
        ))
        .await
        .unwrap_or_else(|err| panic!("counting {table} failed: {err}"));
    rows.first()
        .and_then(|row| row.get::<i64>("n"))
        .unwrap_or(-1)
}

struct Answer {
    status: StatusCode,
    body: Vec<u8>,
}

impl Answer {
    fn json(&self) -> Value {
        serde_json::from_slice(&self.body)
            .unwrap_or_else(|err| panic!("body is not JSON ({err}): {}", self.text()))
    }

    fn text(&self) -> String {
        String::from_utf8_lossy(&self.body).into_owned()
    }
}

async fn send(
    kit: &TestHarness,
    method: Method,
    path: &str,
    token: Option<&str>,
    body: Option<&str>,
) -> Answer {
    let mut builder = axum::http::Request::builder().method(method).uri(path);
    if let Some(token) = token {
        builder = builder.header(header::AUTHORIZATION, format!("Bearer {token}"));
    }
    let payload = match body {
        Some(json) => {
            builder = builder.header(header::CONTENT_TYPE, "application/json");
            axum::body::Body::from(json.to_owned())
        }
        None => axum::body::Body::empty(),
    };
    let response = kit
        .router
        .clone()
        .oneshot(builder.body(payload).expect("request builds"))
        .await
        .expect("router answers");
    let status = response.status();
    let body = axum::body::to_bytes(response.into_body(), 1024 * 1024)
        .await
        .expect("body reads")
        .to_vec();
    Answer { status, body }
}

#[pollster::test]
async fn an_erasure_reaches_the_account_its_logins_and_its_live_sessions() {
    let kit = privacy_kit();
    seed(&kit, ALICE, "alice@example.test").await;
    seed(&kit, BOB, "bob@example.test").await;

    let preview = send(
        &kit,
        Method::POST,
        "/v1/privacy/erase",
        Some(ADMIN),
        Some(&format!(r#"{{"subject":"{ALICE}"}}"#)),
    )
    .await;
    assert_eq!(preview.status, StatusCode::OK, "{}", preview.text());
    let body = preview.json();
    let plan = body["plan"].as_array().expect("plan");
    for table in SUBJECT_TABLES {
        let row = plan
            .iter()
            .find(|entry| entry["table"] == *table)
            .unwrap_or_else(|| panic!("{table} missing from the preview: {plan:?}"));
        assert_eq!(row["action"], "erase", "{table}: {row}");
        assert_eq!(row["rows"], 1, "{table}: {row}");
    }
    // The deletion queue is planned too, and planned as kept: a preview that
    // listed only what disappears would read as "nothing else is held here"
    // (issue #272). Its reason is shown, because that is the part of the
    // answer a person is least likely to expect.
    for table in RETAINED_TABLES {
        let row = plan
            .iter()
            .find(|entry| entry["table"] == *table)
            .unwrap_or_else(|| panic!("{table} missing from the preview: {plan:?}"));
        assert_eq!(row["action"], "retain", "{table}: {row}");
        assert!(
            row["reason"]
                .as_str()
                .unwrap_or_default()
                .contains("the record that the request was honoured"),
            "{table} has to say why it is kept: {row}"
        );
    }
    // The two registration tables hold no person, so they are not planned.
    let planned: Vec<&str> = plan
        .iter()
        .filter_map(|row| row["table"].as_str())
        .collect();
    assert_eq!(planned, declared_tables(), "{plan:?}");
    // The preview writes nothing.
    assert_eq!(count_for(&kit, "sessions", ALICE).await, 1);

    let confirm = send(
        &kit,
        Method::POST,
        "/v1/privacy/erase/confirm",
        Some(ADMIN),
        Some(&format!(r#"{{"token":{}}}"#, body["confirm_token"])),
    )
    .await;
    assert_eq!(confirm.status, StatusCode::OK, "{}", confirm.text());
    assert_eq!(confirm.json()["verified"], true);

    for table in SUBJECT_TABLES {
        assert_eq!(
            count_for(&kit, table, ALICE).await,
            0,
            "{table} survived an erasure"
        );
        assert_eq!(count_for(&kit, table, BOB).await, 1, "{table} lost Bob");
    }
}

#[pollster::test]
async fn an_export_copies_no_hash_and_no_authorization_payload() {
    let kit = privacy_kit();
    seed(&kit, ALICE, "alice@example.test").await;

    let response = send(
        &kit,
        Method::GET,
        &format!("/v1/privacy/export?subject={ALICE}"),
        Some(ADMIN),
        None,
    )
    .await;
    assert_eq!(response.status, StatusCode::OK, "{}", response.text());
    let raw = response.text();
    assert!(
        !raw.contains(PASSWORD_HASH),
        "the export copied a password hash"
    );
    // The payload carries a redirect URL, a PKCE challenge and a live session
    // id. A URL in an export body is the door five leaks in this epic came
    // through.
    assert!(
        !raw.contains("https://app.example.test/callback") && !raw.contains("pkce"),
        "the export copied an authorization code's payload"
    );

    let body = response.json();
    let table = |name: &str| -> Value {
        body["tables"]
            .as_array()
            .expect("tables")
            .iter()
            .find(|t| t["table"] == name)
            .unwrap_or_else(|| panic!("{name} not exported"))
            .clone()
    };

    // Named, not dropped: "we hold nothing there" is the one answer a subject
    // access request must not give untruthfully.
    assert_eq!(
        table("credentials")["rows"][0]["password_hash"],
        "[redacted]"
    );
    assert_eq!(table("sessions")["rows"][0]["token_hash"], "[redacted]");
    assert_eq!(
        table("single_use_tokens")["rows"][0]["payload"],
        "[redacted]"
    );
    assert_eq!(
        table("single_use_tokens")["rows"][0]["token_hash"],
        "[redacted]"
    );

    // What the account actually is stays visible: it is the answer they asked
    // for.
    assert_eq!(
        table("users")["rows"][0]["primary_email"],
        "alice@example.test"
    );
    assert_eq!(table("identities")["rows"][0]["provider"], "google");
    assert_eq!(table("credentials")["rows"][0]["label"], "laptop");
    // A one-way fingerprint of where they signed in from is theirs to see:
    // nobody can present a hash, so it is not a capability.
    assert_eq!(
        table("sessions")["rows"][0]["ip_hash"],
        format!("iphash-{ALICE}")
    );
    assert_eq!(table("sessions")["rows"][0]["ua_family"], "Firefox");
}

#[pollster::test]
async fn the_manifest_says_the_two_client_tables_hold_software_not_people() {
    let kit = privacy_kit();
    let response = send(&kit, Method::GET, "/v1/privacy/manifest", None, None).await;
    assert_eq!(response.status, StatusCode::OK);
    let body = response.json();

    let not_personal = body["not_personal"].as_array().expect("not_personal");
    let listed: Vec<&str> = not_personal
        .iter()
        .filter_map(|entry| entry["table"].as_str())
        .collect();
    assert_eq!(listed, ["clients", "client_redirect_uris"]);
    for entry in not_personal {
        let reason = entry["reason"].as_str().unwrap_or_default();
        assert!(
            reason.contains("not a person") || reason.contains("not a person."),
            "{} has to say whose it is: {reason:?}",
            entry["table"]
        );
    }

    let holds: Vec<&str> = body["holds"]
        .as_array()
        .expect("holds")
        .iter()
        .filter_map(|entry| entry["table"].as_str())
        .collect();
    assert_eq!(holds, declared_tables());
    assert_eq!(body["holds_personal_data"], true);
}

/// A deletion job is written by the provider callback, which names the person
/// only by the provider's own id for them — so the declaration is keyed on
/// `provider_subject` while every request is made with an account id (issue
/// #281). The export has to find the row through `identities`, and the erasure
/// preview has to count it, or a subject access request reports the one table
/// that proves a deletion was asked for as if it did not exist.
#[pollster::test]
async fn the_deletion_queue_answers_a_request_made_with_the_account_id() {
    let kit = privacy_kit();
    seed(&kit, ALICE, "alice@example.test").await;
    seed(&kit, BOB, "bob@example.test").await;

    // The row the provider callback writes: Alice by her provider id, which
    // is exactly what the seeded `identities` row carries as
    // `provider_subject`.
    let at = "2026-01-01T00:00:00Z";
    kit.db
        .execute(&Statement::with_values(
            "INSERT INTO deletion_jobs (id, provider, provider_subject, confirmation_code, \
             status, outcome, created_at) VALUES (?, 'google', ?, 'code-alice', 'done', \
             'unlinked', ?)"
                .to_owned(),
            vec![
                "job-alice".into(),
                format!("google-{ALICE}").into(),
                at.into(),
            ],
        ))
        .await
        .expect("seeding deletion_jobs failed");

    let export = send(
        &kit,
        Method::GET,
        &format!("/v1/privacy/export?subject={ALICE}"),
        Some(ADMIN),
        None,
    )
    .await;
    assert_eq!(export.status, StatusCode::OK, "{}", export.text());
    let job = export
        .json()
        .clone()
        .pointer("/tables")
        .and_then(|tables| tables.as_array())
        .and_then(|tables| {
            tables
                .iter()
                .find(|table| table["table"] == "deletion_jobs")
                .and_then(|table| table["rows"].as_array())
        })
        .and_then(|rows| rows.first())
        .cloned();
    let job = job.unwrap_or_else(|| {
        panic!(
            "the export found no deletion_jobs row for the account id: {}",
            export.text()
        )
    });
    assert_eq!(job["confirmation_code"], "code-alice", "{job}");
    // And not by somebody else's provider id.
    let bob_export = send(
        &kit,
        Method::GET,
        &format!("/v1/privacy/export?subject={BOB}"),
        Some(ADMIN),
        None,
    )
    .await;
    let bob_rows = bob_export
        .json()
        .pointer("/tables")
        .and_then(|tables| tables.as_array())
        .and_then(|tables| {
            tables
                .iter()
                .find(|table| table["table"] == "deletion_jobs")
                .and_then(|table| table["rows"].as_array())
        })
        .map_or(0, std::vec::Vec::len);
    assert_eq!(bob_rows, 0, "Bob's export picked up Alice's deletion job");

    // The preview tells the truth too: one row, kept, for the account id the
    // operator typed.
    let preview = send(
        &kit,
        Method::POST,
        "/v1/privacy/erase",
        Some(ADMIN),
        Some(&format!(r#"{{"subject":"{ALICE}"}}"#)),
    )
    .await;
    assert_eq!(preview.status, StatusCode::OK, "{}", preview.text());
    let row = preview
        .json()
        .pointer("/plan")
        .and_then(|plan| plan.as_array())
        .and_then(|plan| plan.iter().find(|entry| entry["table"] == "deletion_jobs"))
        .cloned()
        .unwrap_or_else(|| panic!("deletion_jobs missing from the preview"));
    assert_eq!(row["action"], "retain", "{row}");
    assert_eq!(row["rows"], 1, "{row}");
}
