//! Issue #656: this Worker as the **provider** side of the subject-access
//! contract.
//!
//! `auth-core` owns every table a subject is in and declares all of it, and
//! `module-privacy` turns those declarations into an export and an erasure.
//! What was missing was the third door: Google, Apple and Meta do not sign
//! in as a user and do not hold this deployment's `ADMIN_TOKEN` — they call
//! the provider protocol directly, signed with a shared HMAC secret. This
//! suite covers the switch (`PRIVACY_PROVIDER_SECRET`), and the property the
//! issue actually exists for: **once the account provider has had its
//! erasure applied, the person it was about cannot sign in.** A route that
//! answers, and an erasure that stops working sign-in, are the two halves
//! of that one sentence.
//!
//! The second test is why this lives in `auth-worker` rather than
//! `auth-core`: `auth-core` does not depend on `module-privacy`, and adding
//! that would be a dependency from the module onto the module that reads it.
//! This crate depends on both, which is the only place the two can be
//! driven together.

use axum::body::Body;
use axum::http::{HeaderMap, Method, Request, StatusCode, header};
use cratefield_auth_worker::{AuthWorker, AuthWorkerConfig, PRIVACY_PROVIDER_SECRET_KEY};
use cratefield_core::{Config, Database, MapConfig, Module, Port, Ports, Runtime, Statement};
use cratefield_testing::{TestHarness, sign_stripe_style};
use serde_json::{Value, json};
use std::sync::Arc;
use tower::ServiceExt;

/// The provider routes, mounted by the harness under `/v1/privacy`.
const EXPORT: &str = "/v1/privacy/provider/export";
const ERASE_PLAN: &str = "/v1/privacy/provider/erase/plan";
const ERASE_APPLY: &str = "/v1/privacy/provider/erase/apply";

/// The shared HMAC secret a deployment is issued for the provider protocol.
/// An obvious dummy: this is a test fixture, and a real one is a binding
/// secret nobody in this repository holds.
const PROVIDER_SECRET: &str = "privacy-provider-secret-0123456789abcdef";

/// The account provider's own id for the person, which is what it asks
/// about — never the account's own ULID.
const PROVIDER_SUBJECT: &str = "google-subject-alice-0001";

/// A person with a password, so "can this account still sign in?" is a
/// question with an answer either way.
const EMAIL: &str = "alice@example.test";
const PASSWORD: &str = "a long enough password";
const ALICE: &str = "01HCAUTHUSERALICE0000000001";

/// The variables the auth modules read. Deliberately minimal: `Privacy`
/// validates nothing of its own, and `auth-password`'s breach corpus is off
/// so a login never needs the `HttpClient` port.
fn pairs() -> Vec<(&'static str, &'static str)> {
    vec![
        ("AUTH_PUBLIC_URL", "https://auth.example.test"),
        ("AUTH_VENTURE_NAME", "example-auth"),
        ("AUTH_BRAND_NAME", "Example"),
        ("AUTH_CORS_ORIGINS", "https://app.example.test"),
        ("MAIL_FROM", "no-reply@auth.example.test"),
        ("AUTH_PASSWORD_BREACH_CHECK", "false"),
        ("AUTH_PASSWORD_PUBLIC_BASE", "https://auth.example.test"),
        ("AUTH_PASSWORD_MAIL_FROM", "no-reply@auth.example.test"),
        (PRIVACY_PROVIDER_SECRET_KEY, PROVIDER_SECRET),
    ]
}

/// A runtime that advertises every port, so `Harness::build` composes the
/// venture however `Privacy` declares it today.
struct AllPorts;

impl Runtime for AllPorts {
    fn provides(&self) -> Vec<Port> {
        Port::ALL.to_vec()
    }
}

/// The venture as the Worker composes it — through `AuthWorker::builder`,
/// not by assembling the modules here, because what is under test is the
/// Worker's own composition and a test that rebuilt it would prove nothing
/// about it.
///
/// `AuthWorker::builder` takes no runtime, so this drives it directly; the
/// database is built and migrated after, exactly as `tests/acceptance.rs`
/// does for the same reason.
fn build(pairs: Vec<(&'static str, &'static str)>) -> (axum::Router, Arc<dyn Database>) {
    let config =
        AuthWorkerConfig::from_config(&MapConfig::from_pairs(pairs.clone())).expect("config");
    let harness = AuthWorker::new(config)
        .builder()
        .runtime(AllPorts)
        .build()
        .expect("the venture composes");

    let db =
        Arc::new(cratefield_adapter_sqlite::SqliteDatabase::in_memory().expect("in-memory sqlite"));
    for module in harness.modules() {
        db.apply_migrations(module.name(), module.migrations().sqlite)
            .expect("migrations apply");
    }

    let mut ports = Ports::with_config(Arc::new(MapConfig::from_pairs(pairs)));
    ports.db = Some(Arc::clone(&db) as Arc<dyn Database>);
    ports.clock = Some(Arc::new(cratefield_core::SystemClock));
    ports.id_gen = Some(Arc::new(cratefield_core::UlidIdGen));
    // Readiness (issue #437) refuses a venture with public writes or admin
    // routes unless a limiter and a signer both resolve, and this one has
    // both — which is why the deployment wires a `RATE_LIMITER` binding.
    // Left unset, every sign-in below would answer 403 and the erasure's
    // effect on sign-in would be untestable.
    ports.rate_limiter = Some(Arc::new(cratefield_testing::FakeRateLimiter::always_allow()));
    ports.signer = Some(Arc::new(
        cratefield_core::HmacSigner::new(cratefield_testing::TEST_HARNESS_SECRET, None)
            .expect("the test secret is long enough"),
    ));
    ports.captcha = Some(Arc::new(cratefield_testing::FakeCaptcha::allow_all()));
    (harness.router(ports), db)
}

async fn send(router: &axum::Router, request: Request<Body>) -> (StatusCode, HeaderMap, String) {
    let response = router
        .clone()
        .oneshot(request)
        .await
        .expect("the router answers");
    let (parts, body) = response.into_parts();
    let bytes = axum::body::to_bytes(body, usize::MAX)
        .await
        .expect("a readable body");
    (
        parts.status,
        parts.headers,
        String::from_utf8_lossy(&bytes).into_owned(),
    )
}

/// One of the three provider calls, signed the way the contract says a
/// caller signs: the Stripe-style layout
/// `Cratefield-Signature: t=<unix>,v1=<hex>` over `"{t}.{body}"`.
///
/// The signature is minted through the kit's `sign_stripe_style` rather
/// than by re-deriving the HMAC here, so this crosses two independent
/// implementations of the scheme — the caller's and the receiver's — and a
/// drift in either stops this test rather than cancelling out.
fn signed(uri: &str, body: &Value, secret: &str) -> Request<Body> {
    let raw = serde_json::to_vec(body).expect("a JSON object serialises");
    // A fixed instant inside the verifier's 300 s tolerance of "now", which
    // is the wall clock: the check is against real time, not a test clock.
    let now = i64::try_from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("after the epoch")
            .as_secs(),
    )
    .expect("in range");
    let headers = sign_stripe_style("Cratefield-Signature", secret, now, &raw);
    let mut builder = Request::builder()
        .method(Method::POST)
        .uri(uri)
        .header(header::CONTENT_TYPE, "application/json");
    for (name, value) in &headers {
        builder = builder.header(name, value);
    }
    builder.body(Body::from(raw)).expect("request")
}

/// The same call with no signature at all.
fn unsigned(uri: &str, body: &Value) -> Request<Body> {
    Request::builder()
        .method(Method::POST)
        .uri(uri)
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(
            serde_json::to_vec(body).expect("a JSON object serialises"),
        ))
        .expect("request")
}

/// `POST /v1/auth-password/login` from our own page — a same-origin POST,
/// which is the only kind that may complete a sign-in.
///
/// Carries all three signals the login-CSRF guard reads (`host`, `origin`,
/// `sec-fetch-site`), because a sign-in mints a session and a form on
/// another site must not be able to press this button for somebody.
fn login() -> Request<Body> {
    Request::builder()
        .method(Method::POST)
        .uri("/v1/auth-password/login")
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::HOST, "auth.example.test")
        .header(header::ORIGIN, "https://auth.example.test")
        .header("sec-fetch-site", "same-origin")
        .body(Body::from(
            json!({ "email": EMAIL, "password": PASSWORD }).to_string(),
        ))
        .expect("request")
}

/// The account provider's three calls, all signed, in the order the contract
/// has them run: read what is held, preview what would go, apply it.
async fn drive_provider(
    router: &axum::Router,
    subject: &str,
    request_id: &str,
) -> (StatusCode, StatusCode, StatusCode) {
    let (export_status, _, _) = send(
        router,
        signed(
            EXPORT,
            &json!({ "subject": subject, "request_id": request_id }),
            PROVIDER_SECRET,
        ),
    )
    .await;
    let (plan_status, _, _) = send(
        router,
        signed(
            ERASE_PLAN,
            &json!({ "subject": subject, "request_id": request_id }),
            PROVIDER_SECRET,
        ),
    )
    .await;
    let (apply_status, _, _) = send(
        router,
        signed(
            ERASE_APPLY,
            &json!({ "subject": subject, "request_id": request_id }),
            PROVIDER_SECRET,
        ),
    )
    .await;
    (export_status, plan_status, apply_status)
}

// ---------------------------------------------------------------------------
// The switch

/// The three provider routes answer a signed call when the secret is set,
/// and each one is **mounted** — not a stub, and not a 404 dressed as an
/// answer.
///
/// The plan is asserted on its body, not just its status, because a `200`
/// that answered nothing about `auth-passkeys`' challenge budget would leave
/// the one declaration in this venture that erasure cannot reach unsaid: it
/// holds the reader's data and no equality predicate on their id finds the
/// row, which is exactly what a subject is entitled to be told about a
/// retained table. Its reason is published verbatim, and the calling module's
/// own validator refuses a `retain` without one.
#[test]
fn the_provider_routes_answer_a_signed_account_provider() {
    pollster::block_on(async {
        let (router, db) = build(pairs());
        seed_raw(&*db, EMAIL).await;

        let (export, plan, apply) = drive_provider(&router, ALICE, "req-1").await;
        assert_eq!(export, StatusCode::OK, "the export route is not mounted");
        assert_eq!(plan, StatusCode::OK, "the plan route did not answer");
        assert_eq!(apply, StatusCode::OK, "the apply route is not mounted");

        // An export that answers 200 with an empty body would satisfy the
        // route assertions above and prove nothing, so the shape is checked:
        // one section per declared table, carrying no hash.
        let (_, _, body) = send(
            &router,
            signed(
                EXPORT,
                &json!({ "subject": ALICE, "request_id": "req-2" }),
                PROVIDER_SECRET,
            ),
        )
        .await;
        let sections: Vec<String> =
            serde_json::from_str::<Value>(&body).expect("a JSON body")["sections"]
                .as_array()
                .expect("sections")
                .iter()
                .filter_map(|section| section["name"].as_str().map(str::to_owned))
                .collect();
        for table in [
            "users",
            "identities",
            "credentials",
            "sessions",
            "single_use_tokens",
        ] {
            assert!(
                sections.iter().any(|name| name == table),
                "{table} is missing from the provider's export: {sections:?}"
            );
        }
        assert!(
            !body.to_lowercase().contains("argon2"),
            "a password hash reached the provider export: {body}"
        );
    });
}

/// The declaration a plan route cannot answer about is the one
/// `module-privacy` had no arm for: `auth-passkeys` declares its challenge
/// budget with
/// [`Disposition::Unreachable`](cratefield_core::Disposition::Unreachable),
/// which erased rows erasure cannot reach. `AuthWorker::builder` always
/// mounts passkeys, so a plan route with no arm for it answered `500` for
/// every signed caller of every deployment this crate builds.
///
/// It is a `retain`, with the declaration's reason, and the reason is not a
/// formality: the calling module refuses a `retain` carrying no reason, so a
/// plan that dropped it would be discarded whole — taking every other
/// table's action with it.
#[test]
fn a_table_erasure_cannot_reach_is_planned_as_a_retained_one_with_its_reason() {
    pollster::block_on(async {
        let (router, db) = build(pairs());
        seed_raw(&*db, EMAIL).await;

        let (status, _, body) = send(
            &router,
            signed(
                ERASE_PLAN,
                &json!({ "subject": ALICE, "request_id": "req-unreachable" }),
                PROVIDER_SECRET,
            ),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");

        let section = serde_json::from_str::<Value>(&body).expect("a JSON body")["sections"]
            .as_array()
            .expect("sections")
            .iter()
            .find(|section| section["name"] == "auth_passkeys_challenge_budget")
            .cloned()
            .unwrap_or_else(|| panic!("no section for the challenge budget: {body}"));

        assert_eq!(section["action"], "retain", "{section}");
        assert!(
            section["reason"].as_str().is_some_and(|why| !why.trim().is_empty()),
            "a retain with no reason is a plan the calling module rejects: {section}"
        );
        // And the tables this deployment *can* erase are still planned as
        // such: one unreachable declaration must not soften the rest.
        let body: Value = serde_json::from_str(&body).expect("a JSON body");
        let users = body["sections"]
            .as_array()
            .expect("sections")
            .iter()
            .find(|section| section["name"] == "users")
            .cloned()
            .expect("no section for `users`");
        assert_eq!(users["action"], "delete", "{users}");

        // An apply still erases what it said it would.
        let (apply, _, _) = send(
            &router,
            signed(
                ERASE_APPLY,
                &json!({ "subject": ALICE, "request_id": "req-unreachable" }),
                PROVIDER_SECRET,
            ),
        )
        .await;
        assert_eq!(apply, StatusCode::OK);
        assert_eq!(count_raw(&*db, "users", ALICE).await, 0);
    });
}

/// Without the secret the routes do not exist. A mounted router answering
/// "no" would be a smaller surface, and this asserts the smaller surface.
#[test]
fn without_the_secret_the_provider_routes_do_not_exist() {
    pollster::block_on(async {
        let unconfigured: Vec<_> = pairs()
            .into_iter()
            .filter(|(key, _)| *key != PRIVACY_PROVIDER_SECRET_KEY)
            .collect();
        let (router, db) = build(unconfigured);
        seed_raw(&*db, EMAIL).await;

        for uri in [EXPORT, ERASE_PLAN, ERASE_APPLY] {
            let (status, _, _) = send(
                &router,
                signed(uri, &json!({ "subject": ALICE }), PROVIDER_SECRET),
            )
            .await;
            assert_eq!(
                status,
                StatusCode::NOT_FOUND,
                "{uri} answered with the provider server not configured"
            );
        }
        // Nothing was erased on the way past.
        assert_eq!(count_raw(&*db, "users", ALICE).await, 1);
    });
}

/// A mounted route that answers `401` to every signature is not a provider
/// server, it is a wall — and a wrong secret and a missing header must be
/// indistinguishable, so a caller probing the endpoint learns nothing about
/// how it is configured.
#[test]
fn an_unverifiable_call_is_refused_without_saying_why() {
    pollster::block_on(async {
        let (router, db) = build(pairs());
        seed_raw(&*db, EMAIL).await;

        let (wrong_secret, _, wrong_body) = send(
            &router,
            signed(
                EXPORT,
                &json!({ "subject": ALICE }),
                "not-the-secret-this-deployment-was-issued",
            ),
        )
        .await;
        let (unsigned, _, unsigned_body) =
            send(&router, unsigned(EXPORT, &json!({ "subject": ALICE }))).await;

        assert_eq!(wrong_secret, StatusCode::UNAUTHORIZED);
        assert_eq!(unsigned, StatusCode::UNAUTHORIZED);
        assert_eq!(
            problem_type(&wrong_body),
            problem_type(&unsigned_body),
            "a wrong secret and a missing signature must be one answer, not two"
        );
        // Nothing about the subject is echoed in a refusal.
        assert!(!wrong_body.contains(ALICE), "{wrong_body}");
        assert_eq!(count_raw(&*db, "users", ALICE).await, 1);
    });
}

/// The problem `type` a body names — the stable identity of an answer,
/// with the per-request `instance` id taken out.
///
/// Compared instead of the whole body because `instance` is a fresh id on
/// every call by design, and comparing it would make this assert equality of
/// two request ids. Everything a caller can act on — the type, the title,
/// the status — is what has to match.
fn problem_type(body: &str) -> String {
    serde_json::from_str::<Value>(body)
        .expect("a JSON problem body")
        .as_object()
        .expect("a problem is an object")
        .iter()
        .filter(|(key, _)| *key != "instance")
        .map(|(key, value)| format!("{key}={value}"))
        .collect::<Vec<_>>()
        .join(" ")
}

// ---------------------------------------------------------------------------
// The property

/// **The issue in one test.** After the account provider's erasure has been
/// applied, the person it was about can no longer sign in — and the accounts
/// of everybody else are untouched.
///
/// Driven the whole way through HTTP rather than by counting rows, because a
/// row count would pass while the login path kept working off some other
/// table: the assertion that matters is that `POST /v1/auth-password/login`
/// answers with a session before and is refused after, and that a second
/// account keeps its own session throughout.
#[test]
fn after_the_account_provider_erases_them_they_can_no_longer_sign_in() {
    pollster::block_on(async {
        let (router, db) = build(pairs());
        seed_raw(&*db, EMAIL).await;

        // Before: the account works. If this did not, the refusal below
        // would prove nothing.
        let (before, _, _) = send(&router, login()).await;
        assert_eq!(
            before,
            StatusCode::OK,
            "the account could not sign in before the erasure, so the test would pass for the wrong reason"
        );
        assert_eq!(count_raw(&*db, "sessions", ALICE).await, 1);

        // The protocol's `subject` is the **harness** subject id — the
        // account's own ULID, which is what every `auth-core` declaration
        // keys on (`users.id`, `identities.user_id`, …). An account
        // provider holding only its own id for the person cannot drive this
        // route directly; see the note on
        // `an_account_providers_own_subject_id_reaches_no_auth_row`.
        let (export, plan, apply) = drive_provider(&router, ALICE, "req-apply-alice").await;
        assert_eq!(export, StatusCode::OK);
        assert_eq!(plan, StatusCode::OK);
        assert_eq!(apply, StatusCode::OK, "the erasure was not applied");

        // After: refused, and refused the same way a wrong password is —
        // one answer, so the refusal says nothing about which rows went.
        let (after, _, _) = send(&router, login()).await;
        assert_eq!(
            after,
            StatusCode::UNAUTHORIZED,
            "the erased account still signed in"
        );

        // And the rows really are gone, which is what makes the refusal a
        // property of the erasure rather than of a lockout counter.
        for table in [
            "users",
            "identities",
            "credentials",
            "sessions",
            "single_use_tokens",
        ] {
            assert_eq!(
                count_raw(&*db, table, ALICE).await,
                0,
                "{table} survived the account provider's erasure"
            );
        }
    });
}

/// The same property on every engine the kit has (issue #20's dialect axis):
/// SQLite always, Postgres when `FZ_TEST_POSTGRES_URL` names a server.
///
/// The modules are listed here rather than taken from `AuthWorker::builder`
/// because the kit composes and wires them itself — the composition under
/// test in the tests above is the Worker's, and this one varies only the
/// **engine**, which is the axis it exists to cover.
#[test]
fn the_erasure_that_stops_a_sign_in_holds_on_every_engine() {
    let config: Arc<dyn Config> = Arc::new(MapConfig::from_pairs([
        ("AUTH_PASSWORD_BREACH_CHECK".to_owned(), "false".to_owned()),
        (
            "AUTH_PASSWORD_PUBLIC_BASE".to_owned(),
            "https://auth.example.test".to_owned(),
        ),
        (
            PRIVACY_PROVIDER_SECRET_KEY.to_owned(),
            PROVIDER_SECRET.to_owned(),
        ),
    ]));
    let kits = TestHarness::all_dialects_with_ports(
        || {
            vec![
                Box::new(auth_core::AuthCore::new()) as Box<dyn Module>,
                Box::new(auth_password::Password::new()),
                Box::new(
                    cratefield_module_privacy::Privacy::new()
                        .serve_provider(PRIVACY_PROVIDER_SECRET_KEY),
                ),
            ]
        },
        move |ports: &mut Ports| {
            ports.config = Arc::clone(&config);
        },
    );

    for kit in kits {
        let dialect = kit.dialect;
        pollster::block_on(async {
            seed_raw(&*kit.db, EMAIL).await;

            let before = send(&kit.router, login()).await;
            assert_eq!(
                before.0,
                StatusCode::OK,
                "{dialect}: the account could not sign in before the erasure, so the \
                 refusal below would pass for the wrong reason"
            );

            let (export, _plan, apply) = drive_provider(&kit.router, ALICE, "req-dialect").await;
            assert_eq!(export, StatusCode::OK, "{dialect}: export");
            assert_eq!(apply, StatusCode::OK, "{dialect}: apply");

            let after = send(&kit.router, login()).await;
            assert_eq!(
                after.0,
                StatusCode::UNAUTHORIZED,
                "{dialect}: the erased account still signed in"
            );
            for table in ["users", "identities", "credentials", "sessions"] {
                assert_eq!(
                    count_raw(&*kit.db, table, ALICE).await,
                    0,
                    "{dialect}: {table} survived the erasure"
                );
            }
        });
    }
}

/// **A gap, pinned so it cannot be forgotten.** The account provider names a
/// person by *its own* id for them — `google-subject-alice-0001` — and that
/// is the id Google, Apple and Meta will actually send. Every `auth-core`
/// declaration, though, keys on the harness subject: `users.id`,
/// `identities.user_id`, `credentials.user_id`. Only `deletion_jobs` is
/// keyed on `provider_subject`, and it is `Retain`, so it emits no
/// statement.
///
/// So a call naming the provider's own id is answered `200 {"applied":true}`
/// while erasing nothing. That is the protocol working as written — its
/// `subject` is the harness subject id, and the resolution from a provider's
/// id to an account is `auth-core`'s `deletion_jobs` join and its scheduled
/// drain, not this route's. But it is a sharp edge for exactly the caller
/// the route exists for, and the `200` says nothing about it.
///
/// Pinned as an assertion of what happens **today**, so a change that starts
/// resolving provider ids fails here and gets a decision, rather than
/// passing silently.
#[test]
fn an_account_providers_own_subject_id_reaches_no_auth_row() {
    pollster::block_on(async {
        let (router, db) = build(pairs());
        seed_raw(&*db, EMAIL).await;

        let (export, _, apply) = drive_provider(&router, PROVIDER_SUBJECT, "req-provider-id").await;
        assert_eq!(export, StatusCode::OK);
        assert_eq!(apply, StatusCode::OK, "the provider route refused the call");

        // Nothing was erased, and nothing was claimed to be: this is the
        // gap, asserted.
        for table in ["users", "identities", "credentials"] {
            assert_eq!(
                count_raw(&*db, table, ALICE).await,
                1,
                "{table} was erased by a provider-subject call — the gap this test \
                 pins has been closed on the module-privacy side; update it"
            );
        }
        // And the account still signs in, which is the consequence.
        let (status, _, _) = send(&router, login()).await;
        assert_eq!(
            status,
            StatusCode::OK,
            "the account stopped signing in, so the rows above did go"
        );
    });
}

/// [`seed`] over the port type the dialect kits carry, so the same fixture
/// runs on both engines.
async fn seed_raw(db: &dyn Database, email: &str) {
    let at = "2026-01-01T00:00:00Z";
    let hash = auth_core::hash_password(PASSWORD).expect("hash");
    let rows: Vec<(&str, String, Vec<sea_query::Value>)> = vec![
        (
            "users",
            "INSERT INTO users (id, display_name, primary_email, primary_email_verified, \
             status, created_at, updated_at) VALUES (?, 'Alex', ?, 1, 'active', ?, ?)"
                .to_owned(),
            vec![ALICE.into(), email.into(), at.into(), at.into()],
        ),
        (
            "identities",
            "INSERT INTO identities (id, user_id, provider, provider_subject, email, \
             email_verified, name_at_link, created_at) \
             VALUES (?, ?, 'google', ?, ?, 1, 'Alex', ?)"
                .to_owned(),
            vec![
                "id-alice".into(),
                ALICE.into(),
                PROVIDER_SUBJECT.into(),
                email.into(),
                at.into(),
            ],
        ),
        (
            "credentials",
            "INSERT INTO credentials (id, user_id, kind, password_hash, label, created_at, \
             failed_attempts) VALUES (?, ?, 'password', ?, 'laptop', ?, 0)"
                .to_owned(),
            vec!["cred-alice".into(), ALICE.into(), hash.into(), at.into()],
        ),
    ];
    for (table, sql, values) in rows {
        db.execute(&Statement::with_values(sql, values))
            .await
            .unwrap_or_else(|err| panic!("seeding {table} failed: {err}"));
    }
}

/// [`count_for`] over the port type.
async fn count_raw(db: &dyn Database, table: &str, user: &str) -> i64 {
    let column = if table == "users" { "id" } else { "user_id" };
    let rows = db
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
