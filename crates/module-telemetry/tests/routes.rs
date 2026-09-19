//! Issue #413 over the wire: accepted batches accumulate into buckets,
//! rejected batches write nothing, the notice publishes the declared
//! vocabulary, the admin aggregate groups away the install id, and the
//! rate limiter is the abuse control the public ingest route actually
//! has. Runs on every available dialect.

use std::sync::Arc;
use std::time::Duration;

use cratefield_core::{Decision, MapConfig, Statement};
use cratefield_module_telemetry::Telemetry;
use cratefield_testing::{FakeRateLimiter, TestHarness, TestResponse, request, request_as};
use serde_json::json;

const ADMIN: &str = "test-admin-token-0123456789abcdef";
const INSTALL_A: &str = "7b0a1f2c3d4e5f60718293a4b5c6d7e8";
const INSTALL_B: &str = "0f1e2d3c4b5a69788796a5b4c3d2e1f0";

/// A batch body in the published wire shape.
fn batch(install: &str, events: &[(&str, &str, &str, &str, i64)]) -> String {
    let records = events
        .iter()
        .map(|(name, outcome, error, duration, count)| {
            format!(
                r#"{{"name":"{name}","outcome":"{outcome}","error":"{error}","duration":"{duration}","count":{count}}}"#
            )
        })
        .collect::<Vec<_>>()
        .join(",");
    format!(
        r#"{{"schema":1,"install":"{install}","client":{{"kind":"cli","version":"0.4.1","platform":"linux","arch":"aarch64"}},"modules":["telemetry","waitlist"],"events":[{records}]}}"#
    )
}

fn kits() -> Vec<TestHarness> {
    TestHarness::all_dialects_with_ports(
        || {
            vec![Box::new(
                Telemetry::new()
                    .events(["run", "build"])
                    .modules(["telemetry", "waitlist"]),
            )]
        },
        |_| {},
    )
}

fn admin_kits() -> Vec<TestHarness> {
    TestHarness::all_dialects_with_ports(
        || {
            vec![Box::new(
                Telemetry::new()
                    .events(["run"])
                    .modules(["telemetry", "waitlist"]),
            )]
        },
        |ports| {
            ports.config = Arc::new(MapConfig::from_pairs([(
                "ADMIN_TOKEN".to_owned(),
                ADMIN.to_owned(),
            )]));
        },
    )
}

async fn post(kit: &TestHarness, body: &str) -> TestResponse {
    request(
        &kit.router,
        axum::http::Method::POST,
        "/v1/telemetry/events",
        Some(body),
    )
    .await
}

/// `post` with an explicit `Content-Type`. The kit's `request` fixes
/// `application/json`, which is the one header the ingest route inspects
/// itself, so the cases around it need their own request.
async fn post_as(
    kit: &TestHarness,
    body: &str,
    content_type: &str,
) -> (axum::http::StatusCode, String) {
    use tower::ServiceExt;
    let request = axum::http::Request::builder()
        .method(axum::http::Method::POST)
        .uri("/v1/telemetry/events")
        .header(axum::http::header::CONTENT_TYPE, content_type)
        .body(axum::body::Body::from(body.to_owned()))
        .expect("request builds");
    let response = kit
        .router
        .clone()
        .oneshot(request)
        .await
        .expect("router answers");
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), 1024 * 1024)
        .await
        .expect("body reads");
    (status, String::from_utf8_lossy(&bytes).into_owned())
}

/// `(row count, summed events)` — only meaningful for `telemetry_events`.
async fn count(kit: &TestHarness, table: &str) -> (i64, i64) {
    let rows = kit
        .db
        .query(&Statement::with_values(
            format!("SELECT COUNT(*) AS n, COALESCE(SUM(events), 0) AS total FROM {table}"),
            Vec::new(),
        ))
        .await
        .expect("count query");
    let row = rows.rows.first();
    (
        row.and_then(|row| row.get("n")).unwrap_or(0),
        row.and_then(|row| row.get("total")).unwrap_or(0),
    )
}

async fn rows(kit: &TestHarness, table: &str) -> i64 {
    let counted = kit
        .db
        .query(&Statement::with_values(
            format!("SELECT COUNT(*) AS n FROM {table}"),
            Vec::new(),
        ))
        .await
        .expect("count query");
    counted
        .rows
        .first()
        .and_then(|row| row.get("n"))
        .unwrap_or(0)
}

/// The happy path: a batch is accepted, its records land as aggregate
/// buckets (not one row per event), and an identical repeat batch
/// accumulates counts rather than rows.
#[test]
fn a_batch_is_accepted_and_accumulates_into_buckets() {
    pollster::block_on(async {
        for kit in kits() {
            let body = batch(
                INSTALL_A,
                &[
                    ("run", "ok", "none", "1s-10s", 3),
                    ("run", "error", "network", "10s-1m", 1),
                ],
            );
            let accepted = post(&kit, &body).await;
            assert_eq!(
                accepted.status,
                axum::http::StatusCode::ACCEPTED,
                "{:?}",
                accepted.body()
            );
            assert_eq!(accepted.body().as_ref(), br#"{"ok":true}"#);

            // Two distinct dimension tuples from two event records.
            assert_eq!(
                count(&kit, "telemetry_events").await,
                (2, 4),
                "one bucket per dimension tuple, counts summed"
            );
            assert_eq!(
                rows(&kit, "telemetry_modules").await,
                2,
                "each reported module once"
            );

            // The same batch again: counts add up, rows do not.
            let repeat = post(&kit, &body).await;
            assert_eq!(repeat.status, axum::http::StatusCode::ACCEPTED);
            assert_eq!(
                count(&kit, "telemetry_events").await,
                (2, 8),
                "the repeat batch accumulated into the same buckets"
            );

            // The day bucket is the harness fixed clock's day, not the
            // wall clock's.
            let rows = kit
                .db
                .query(&Statement::with_values(
                    "SELECT DISTINCT day FROM telemetry_events".to_owned(),
                    Vec::new(),
                ))
                .await
                .expect("day query");
            let day = rows.rows[0].get::<String>("day").expect("day");
            assert_eq!(
                day,
                kit.clock.0.date().to_string(),
                "the bucket day is the clock port's day"
            );
        }
    });
}

/// A rejected batch is a 400 with a named slug, writes nothing anywhere,
/// and does not quote what the client sent. A schema mismatch gets its own
/// slug: the fix is a client upgrade, not a payload fix.
#[test]
fn a_rejected_batch_writes_nothing() {
    pollster::block_on(async {
        for kit in kits() {
            // An undeclared event.
            let mut body = batch(INSTALL_A, &[("run", "ok", "none", "unknown", 1)]);
            body = body.replace("\"run\"", "\"poetry\"");
            let rejected = post(&kit, &body).await;
            assert_eq!(rejected.status, axum::http::StatusCode::BAD_REQUEST);
            let problem = rejected.json();
            assert!(
                problem["type"]
                    .as_str()
                    .is_some_and(|kind| { kind.ends_with("/problems/telemetry-payload-rejected") }),
                "{problem}"
            );
            assert!(
                !rejected
                    .body()
                    .as_ref()
                    .windows("poetry".len())
                    .any(|w| w == b"poetry"),
                "the rejection echoed what the client sent: {:?}",
                rejected.body()
            );

            // An unsupported schema version.
            let mismatch = batch(INSTALL_A, &[("run", "ok", "none", "unknown", 1)])
                .replace("\"schema\":1", "\"schema\":2");
            let rejected = post(&kit, &mismatch).await;
            assert_eq!(rejected.status, axum::http::StatusCode::BAD_REQUEST);
            assert!(
                rejected.json()["type"]
                    .as_str()
                    .is_some_and(|kind| kind.ends_with("/problems/telemetry-schema-unsupported")),
                "{:?}",
                rejected.body()
            );

            // Both rejections left both tables untouched.
            assert_eq!(
                count(&kit, "telemetry_events").await,
                (0, 0),
                "a rejected batch writes nothing"
            );
            assert_eq!(rows(&kit, "telemetry_modules").await, 0);
        }
    });
}

/// The ingest route's rejections never carry the client's own bytes, on
/// either path a hostile request can take: a body that is not JSON at all
/// (where serde's parse error would quote the client's key, since
/// `serde_path_to_error` prefixes it with it), and a well-formed body
/// whose key is itself the offence. A JSON key may carry newline escapes,
/// so an echo would be a log-injection sink as well — this is the one
/// route built to keep the README's promise that rejections never echo
/// what the client sent.
#[test]
fn an_ingest_rejection_never_carries_the_client_s_own_bytes() {
    pollster::block_on(async {
        for kit in kits() {
            // The second body parses fine; its key is the offence. Even
            // JSON-escaped, no fragment of either key may survive into a
            // response.
            for body in [
                r#"{"TELL-ME-A-SECRET-HERE": notjson}"#,
                r#"{"TELL-ME-A\n-SECRET\n-HERE": 1}"#,
            ] {
                let rejected = post(&kit, body).await;
                assert_eq!(rejected.status, axum::http::StatusCode::BAD_REQUEST);
                assert!(
                    rejected.json()["type"]
                        .as_str()
                        .is_some_and(|kind| kind.ends_with("/problems/telemetry-payload-rejected")),
                    "{:?}",
                    rejected.body()
                );
                // Checked against the whole serialized body, not one
                // field, so no accidental echo route exists. Both needles
                // carry hyphens, which a ULID `instance` cannot contain —
                // the assertion cannot pass by coincidence.
                let text = std::str::from_utf8(rejected.body().as_ref()).expect("body is text");
                for fragment in ["TELL-ME-A", "SECRET-HERE"] {
                    assert!(
                        !text.contains(fragment),
                        "the rejection echoed the client's key: {text}"
                    );
                }
            }
        }
    });
}

/// The content-type guard axum's `Json` extractor used to apply for the
/// route: a body is read only when the request names JSON —
/// `application/json` with parameters and the `application/*+json`
/// subtypes included — and any other type is refused before the body is
/// parsed, under the same slug and status as a payload rejection. The
/// rejection is the route's own fixed sentence, so the type the client
/// sent never comes back in the body.
#[test]
fn a_batch_is_read_only_when_the_request_names_json() {
    pollster::block_on(async {
        for kit in kits() {
            let body = batch(INSTALL_A, &[("run", "ok", "none", "1s-10s", 1)]);

            // A mistyped body is refused before it is parsed, writes
            // nothing, and does not quote the offending type back.
            let (status, text) = post_as(&kit, &body, "text/plain").await;
            assert_eq!(status, axum::http::StatusCode::BAD_REQUEST, "{text}");
            let problem = serde_json::from_str::<serde_json::Value>(&text).expect("problem body");
            assert!(
                problem["type"]
                    .as_str()
                    .is_some_and(|kind| kind.ends_with("/problems/telemetry-payload-rejected")),
                "{text}"
            );
            assert!(
                !text.contains("text/plain"),
                "the rejection echoed the client's content type: {text}"
            );
            assert_eq!(
                count(&kit, "telemetry_events").await,
                (0, 0),
                "a mistyped batch writes nothing"
            );

            // A correct client still lands: the charset parameter and the
            // suffixed vendor subtype axum's extractor accepted are both
            // read as JSON.
            for content_type in [
                "application/json; charset=utf-8",
                "application/vnd.api+json",
            ] {
                let (status, text) = post_as(&kit, &body, content_type).await;
                assert_eq!(
                    status,
                    axum::http::StatusCode::ACCEPTED,
                    "{content_type}: {text}"
                );
            }
            assert_eq!(
                count(&kit, "telemetry_events").await,
                (1, 2),
                "both correctly typed batches landed as one bucket"
            );
        }
    });
}

/// The notice route is the canonical machine-readable consent notice:
/// unauthenticated, and generated from the declared vocabularies, so it
/// cannot be vaguer than the parser.
#[test]
fn the_notice_publishes_the_vocabulary() {
    pollster::block_on(async {
        for kit in kits() {
            let notice = request(
                &kit.router,
                axum::http::Method::GET,
                "/v1/telemetry/notice",
                None,
            )
            .await;
            assert_eq!(notice.status, axum::http::StatusCode::OK);
            let body = notice.json();
            assert_eq!(body["schema"], 1);
            assert_eq!(body["events"], json!(["run", "build"]), "{body}");
            assert_eq!(body["modules"], json!(["telemetry", "waitlist"]));
            assert_eq!(body["opt_out_command"], json!("fz telemetry off"));
            assert_eq!(body["status_command"], json!("fz telemetry status"));

            let text = body["notice"].as_str().expect("notice text");
            assert!(text.contains("fz telemetry off"), "{text}");
            assert!(text.contains("every 30 days"), "{text}");
            assert!(text.contains("prompt"), "{text}");
            assert!(text.contains("run"), "{text}");

            // The field inventory enumerates every payload field, and the
            // event field's permitted values are the declared vocabulary.
            let fields = body["fields"].as_array().expect("field inventory");
            let names = fields
                .iter()
                .filter_map(|field| field["path"].as_str())
                .collect::<Vec<_>>();
            for path in [
                "/schema",
                "/install",
                "/client/kind",
                "/events[]/name",
                "/events[]/count",
            ] {
                assert!(
                    names.contains(&path),
                    "the inventory is missing {path}: {names:?}"
                );
            }
            let event_field = fields
                .iter()
                .find(|field| field["path"] == "/events[]/name")
                .expect("the event field");
            assert_eq!(event_field["values"], json!(["run", "build"]));
        }
    });
}

/// The admin aggregate needs the token, and what it returns is grouped:
/// two installs behind the same dimensions merge into one row, and no
/// install id appears anywhere in the body.
#[test]
fn the_admin_route_needs_the_token_and_groups_away_installs() {
    pollster::block_on(async {
        for kit in admin_kits() {
            post(
                &kit,
                &batch(INSTALL_A, &[("run", "ok", "none", "1s-10s", 3)]),
            )
            .await;
            post(
                &kit,
                &batch(INSTALL_B, &[("run", "ok", "none", "1s-10s", 5)]),
            )
            .await;

            let denied = request(
                &kit.router,
                axum::http::Method::GET,
                "/v1/telemetry/admin/usage",
                None,
            )
            .await;
            assert_eq!(denied.status, axum::http::StatusCode::UNAUTHORIZED);

            let allowed = request_as(
                &kit.router,
                axum::http::Method::GET,
                "/v1/telemetry/admin/usage",
                ADMIN,
                None,
            )
            .await;
            assert_eq!(
                allowed.status,
                axum::http::StatusCode::OK,
                "{:?}",
                allowed.body()
            );
            let body = allowed.json();
            let rows = body["rows"].as_array().expect("rows");
            assert_eq!(
                rows.len(),
                1,
                "the two installs share dimensions and merge: {body}"
            );
            assert_eq!(rows[0]["total"], 8, "3 + 5 across installs");
            assert_eq!(rows[0]["installs"], 2, "both installs are behind the total");
            let text = std::str::from_utf8(allowed.body().as_ref()).expect("body is text");
            assert!(
                !text.contains(INSTALL_A) && !text.contains(INSTALL_B),
                "the aggregate leaked an install id: {text}"
            );
        }
    });
}

/// When `RateLimiter` port refuses the client IP, the batch is a 429
/// with a `retry-after` — and nothing is written. When the limiter errors,
/// the route warns and allows: the closed grammar and the batch ceiling
/// bound the request either way.
#[test]
fn the_rate_limiter_can_refuse_a_batch() {
    let deny = Decision {
        ok: false,
        retry_after: Some(Duration::from_secs(17)),
    };
    let kits = TestHarness::all_dialects_with_ports(
        || {
            vec![Box::new(
                Telemetry::new().events(["run"]).modules(["telemetry"]),
            )]
        },
        move |ports| {
            ports.rate_limiter = Some(Arc::new(FakeRateLimiter::scripted(
                vec![deny.clone()],
                deny.clone(),
            )));
        },
    );
    pollster::block_on(async {
        for kit in kits {
            let refused = post(
                &kit,
                &batch(INSTALL_A, &[("run", "ok", "none", "unknown", 1)]),
            )
            .await;
            assert_eq!(refused.status, axum::http::StatusCode::TOO_MANY_REQUESTS);
            assert_eq!(
                refused
                    .headers
                    .get("retry-after")
                    .map(|value| value.to_str().expect("ascii")),
                Some("17")
            );
            assert_eq!(
                count(&kit, "telemetry_events").await,
                (0, 0),
                "a refused batch writes nothing"
            );
        }
    });
}

/// The fail-closed default: an empty vocabulary means every batch naming
/// an event is rejected, even a perfectly shaped one.
#[test]
fn an_undeclared_vocabulary_rejects_every_batch() {
    pollster::block_on(async {
        let kits =
            TestHarness::all_dialects_with_ports(|| vec![Box::new(Telemetry::new())], |_| {});
        for kit in kits {
            let rejected = post(
                &kit,
                &batch(INSTALL_A, &[("run", "ok", "none", "unknown", 1)]),
            )
            .await;
            assert_eq!(rejected.status, axum::http::StatusCode::BAD_REQUEST);
            assert!(
                rejected.json()["type"]
                    .as_str()
                    .is_some_and(|kind| kind.ends_with("/problems/telemetry-payload-rejected")),
                "{:?}",
                rejected.body()
            );
            assert_eq!(count(&kit, "telemetry_events").await, (0, 0));
        }
    });
}
