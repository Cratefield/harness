//! `fz auth import` (issue #650): loads a JSONL of users into a running
//! venture's `auth-core` module over its admin API.
//!
//! The migration path this serves is the one every venture eventually
//! walks: a system of record already holds the users, and moving them in
//! must not lose the password verifier or the verified email. The server
//! half — `POST <target>/v1/auth-core/admin/users/import`, behind
//! `Authorization: Bearer <ADMIN_TOKEN>` — validates every user and
//! reports one result per user; this command reads the file, aborts on a
//! local defect **before sending anything**, batches what is left, and
//! writes a report.
//!
//! # Dry run by default
//!
//! Without `--apply` the request carries `"dry_run": true`, so the server
//! validates and reports without writing. `--apply` is the one thing that
//! writes.
//!
//! # The report carries no user data
//!
//! The report JSONL holds exactly the server's per-user verdict —
//! `external_provider`, `external_id`, `status`, `sub`, `reason` — and
//! never an email or a password hash. The file this command reads is the
//! only place those appear, and it is never echoed: the summary counts
//! statuses, and the admin token is read from the environment and never
//! printed.
//!
//! # Exit code
//!
//! Non-zero when a batch cannot be sent or the server answers a non-2xx
//! (the run stops at the first such batch, so the report describes a
//! prefix only). A run that completes printing `conflict` or `invalid`
//! results still exits zero: those are the server having *answered*, and
//! a conflict is a fact to act on, not a transport failure to retry. The
//! counts are printed either way.

use std::collections::{BTreeMap, HashSet};
use std::path::{Path, PathBuf};

// The request path exists only where it can run — behind `auth-import`, or
// in the tests that drive it through a fake. Without the feature the
// command refuses before reaching any of it, and an unused copy would fail
// CI's `-D warnings`.
#[cfg(any(feature = "auth-import", test))]
use cratefield_core::HttpClient;
use serde::{Deserialize, Serialize};
use serde_json::Value;
#[cfg(any(feature = "auth-import", test))]
use std::sync::Arc;

/// The `auth-core` admin route, relative to the venture's base URL.
///
/// `auth-core` is mounted at `/v1/<name>` (`crates/core/src/module.rs:2`,
/// `crates/core/src/harness.rs:367`), and its admin router lives under
/// `/admin` (`crates/auth-core/src/clients.rs:53`) behind the harness
/// `require_admin` layer (`crates/core/src/admin.rs`), which reads
/// `Authorization: Bearer <ADMIN_TOKEN>`.
pub const IMPORT_PATH: &str = "/v1/auth-core/admin/users/import";

/// Users per request, when `--batch-size` is not given.
pub const DEFAULT_BATCH_SIZE: usize = 500;

/// The server refuses a request carrying more than this, so a larger
/// `--batch-size` is a local error rather than an HTTP 4xx.
pub const MAX_BATCH_SIZE: usize = 1000;

/// Every status the server reports, in the order the summary prints them.
const STATUSES: [&str; 5] = ["created", "unchanged", "merged", "conflict", "invalid"];

/// Everything `run` needs, assembled by the dispatcher so the token is
/// read from the environment exactly once and travels no further than the
/// request header.
pub struct ImportOptions {
    /// The JSONL file of user objects.
    pub file: PathBuf,
    /// The venture's base URL; `IMPORT_PATH` is appended.
    pub target: String,
    /// The `ADMIN_TOKEN` value, read from the variable `--admin-token-env`
    /// names. Never printed.
    pub admin_token: String,
    /// `--apply`: write. Absent, the run is a dry run.
    pub apply: bool,
    /// `--merge-by-email`: let the server merge into an existing account
    /// sharing the email.
    pub merge_by_email: bool,
    /// `--report`: where the report JSONL goes. Defaults to
    /// `<file>.report.jsonl`.
    pub report: Option<PathBuf>,
    /// Users per request.
    pub batch_size: usize,
}

impl ImportOptions {
    /// Whether this run asks the server to change nothing. `--apply` is
    /// the only way to make it false.
    #[must_use]
    pub fn dry_run(&self) -> bool {
        !self.apply
    }

    /// Where the report is written: `--report`, or `<file>.report.jsonl`.
    #[must_use]
    pub fn report_path(&self) -> PathBuf {
        if let Some(path) = &self.report {
            return path.clone();
        }
        let mut name = self.file.clone().into_os_string();
        name.push(".report.jsonl");
        PathBuf::from(name)
    }
}

/// One user's verdict, as the server reports it. The field set is the
/// report's whole contract, and it is deliberately narrower than the
/// request: no email, no password hash.
#[derive(Debug, Serialize, Deserialize)]
struct ResultRow {
    external_provider: String,
    external_id: String,
    status: String,
    sub: Option<String>,
    reason: Option<String>,
}

/// The server's reply to one batch.
#[cfg(any(feature = "auth-import", test))]
#[derive(Deserialize)]
struct ImportResponse {
    results: Vec<ResultRow>,
}

/// The request body for one batch. The user objects are passed through
/// verbatim, unknown fields included.
#[cfg(any(feature = "auth-import", test))]
#[derive(Serialize)]
struct ImportRequest<'a> {
    dry_run: bool,
    merge_by_email: bool,
    users: &'a [Value],
}

/// What a completed run reports.
#[derive(Debug)]
struct Outcome {
    dry_run: bool,
    results: Vec<ResultRow>,
}

/// `fz auth import`: parse, validate, batch, send, report.
///
/// # Errors
///
/// A local defect in the file (a line that is not a JSON object, a missing
/// required field, a duplicate `(external_provider, external_id)`, an
/// out-of-range `--batch-size`), any batch that cannot be sent, any
/// non-2xx reply, and a report that cannot be written.
pub fn run(options: &ImportOptions) -> Result<(), String> {
    let users = prepare(options)?;
    let outcome = import_dispatch(options, &users)?;
    finish(options, &outcome)
}

/// Reads the file and refuses everything a local check can catch, before
/// a single byte goes to the network.
fn prepare(options: &ImportOptions) -> Result<Vec<Value>, String> {
    if options.batch_size == 0 || options.batch_size > MAX_BATCH_SIZE {
        return Err(format!(
            "--batch-size must be between 1 and {MAX_BATCH_SIZE}, got {}",
            options.batch_size
        ));
    }
    load_users(&options.file)
}

/// Reads one JSON object per line, skipping blank lines, and validates
/// exactly what the server requires of each. The objects are returned
/// unchanged.
fn load_users(path: &Path) -> Result<Vec<Value>, String> {
    let text = std::fs::read_to_string(path)
        .map_err(|err| format!("cannot read {}: {err}", path.display()))?;
    let mut users = Vec::new();
    let mut seen: HashSet<(String, String)> = HashSet::new();
    for (index, raw) in text.lines().enumerate() {
        let line = index + 1;
        if raw.trim().is_empty() {
            continue;
        }
        let value: Value =
            serde_json::from_str(raw).map_err(|err| format!("line {line}: not JSON: {err}"))?;
        let Some(object) = value.as_object() else {
            return Err(format!("line {line}: not a JSON object"));
        };
        for field in ["external_provider", "external_id", "email"] {
            match object.get(field) {
                Some(Value::String(text)) if !text.is_empty() => {}
                Some(Value::String(_)) => {
                    return Err(format!("line {line}: `{field}` must not be empty"));
                }
                Some(_) => return Err(format!("line {line}: `{field}` must be a string")),
                None => return Err(format!("line {line}: missing required field `{field}`")),
            }
        }
        match object.get("email_verified") {
            Some(Value::Bool(_)) => {}
            Some(_) => return Err(format!("line {line}: `email_verified` must be a boolean")),
            None => {
                return Err(format!(
                    "line {line}: missing required field `email_verified`"
                ));
            }
        }
        // Validated above, so the casts cannot fail.
        let provider = object["external_provider"].as_str().unwrap_or_default();
        let id = object["external_id"].as_str().unwrap_or_default();
        if !seen.insert((provider.to_owned(), id.to_owned())) {
            return Err(format!(
                "line {line}: duplicate (external_provider, external_id) — ({provider:?}, {id:?}) \
                 appears twice"
            ));
        }
        users.push(value);
    }
    if users.is_empty() {
        return Err(format!("{}: no users to import", path.display()));
    }
    Ok(users)
}

/// The URL a batch is sent to: the base URL with any trailing slash
/// removed, then [`IMPORT_PATH`].
#[cfg(any(feature = "auth-import", test))]
fn import_url(target: &str) -> String {
    format!("{}{IMPORT_PATH}", target.trim_end_matches('/'))
}

/// Sends every batch in order, stopping at the first failure.
#[cfg(any(feature = "auth-import", test))]
async fn import_all(
    http: &Arc<dyn HttpClient>,
    options: &ImportOptions,
    users: &[Value],
) -> Result<Outcome, String> {
    let url = import_url(&options.target);
    let dry_run = options.dry_run();
    let mut results = Vec::with_capacity(users.len());
    for batch in users.chunks(options.batch_size) {
        results.extend(send_batch(http, &url, options, dry_run, batch).await?);
    }
    Ok(Outcome { dry_run, results })
}

/// Sends one batch and returns its results. The server answers one result
/// per user in request order.
#[cfg(any(feature = "auth-import", test))]
async fn send_batch(
    http: &Arc<dyn HttpClient>,
    url: &str,
    options: &ImportOptions,
    dry_run: bool,
    users: &[Value],
) -> Result<Vec<ResultRow>, String> {
    let uri = url
        .parse::<http::Uri>()
        .map_err(|_| format!("`{}` is not a valid URL", options.target))?;
    let body = serde_json::to_vec(&ImportRequest {
        dry_run,
        merge_by_email: options.merge_by_email,
        users,
    })
    .map_err(|err| format!("cannot encode the import request: {err}"))?;
    // The header value is built without echoing either the token or the
    // builder's error: a malformed token must not reach a terminal.
    let authorization = http::HeaderValue::from_str(&format!("Bearer {}", options.admin_token))
        .map_err(|_| {
            "the environment variable `--admin-token-env` named does not hold a value usable as \
             an `Authorization` header"
                .to_owned()
        })?;
    let request = http::Request::builder()
        .method(http::Method::POST)
        .uri(uri)
        .header(http::header::AUTHORIZATION, authorization)
        .header(http::header::CONTENT_TYPE, "application/json")
        .body(bytes::Bytes::from(body))
        .map_err(|err| format!("cannot build the import request: {err}"))?;
    let response = http
        .send(request)
        .await
        .map_err(|err| format!("the import request to {url} failed: {err}"))?;
    let status = response.status();
    if !status.is_success() {
        return Err(format!(
            "the import request to {url} failed: HTTP {status}{}",
            problem_detail(response.body())
        ));
    }
    let parsed: ImportResponse = serde_json::from_slice(response.body())
        .map_err(|err| format!("the import response was not the expected JSON: {err}"))?;
    if parsed.results.len() != users.len() {
        return Err(format!(
            "the server returned {} results for {} users",
            parsed.results.len(),
            users.len()
        ));
    }
    Ok(parsed.results)
}

/// The `detail` (or `title`) of an RFC 9457 problem body, as a suffix for
/// an error line. Empty when the body is not problem JSON.
#[cfg(any(feature = "auth-import", test))]
fn problem_detail(body: &[u8]) -> String {
    let Ok(value) = serde_json::from_slice::<Value>(body) else {
        return String::new();
    };
    value
        .get("detail")
        .and_then(Value::as_str)
        .or_else(|| value.get("title").and_then(Value::as_str))
        .map(|detail| format!(" — {detail}"))
        .unwrap_or_default()
}

/// Writes the report and prints the summary.
fn finish(options: &ImportOptions, outcome: &Outcome) -> Result<(), String> {
    let path = options.report_path();
    write_report(&path, &outcome.results)?;
    print_summary(outcome, &path);
    Ok(())
}

/// Writes one result per line, exactly the five result fields.
fn write_report(path: &Path, results: &[ResultRow]) -> Result<(), String> {
    let mut out = String::new();
    for row in results {
        let line = serde_json::to_string(row)
            .map_err(|err| format!("cannot encode a report row: {err}"))?;
        out.push_str(&line);
        out.push('\n');
    }
    std::fs::write(path, out).map_err(|err| format!("cannot write {}: {err}", path.display()))
}

/// Prints the dry-run line, one line per status (zeros included, so a
/// status that never appeared is visibly a zero rather than absent), and
/// the report path.
fn print_summary(outcome: &Outcome, path: &Path) {
    if outcome.dry_run {
        println!(
            "fz auth import: dry run — the server validated {} user(s) and wrote nothing; pass \
             --apply to import",
            outcome.results.len()
        );
    } else {
        println!("fz auth import: imported {} user(s)", outcome.results.len());
    }
    let mut counts: BTreeMap<&str, usize> = BTreeMap::new();
    for row in &outcome.results {
        *counts.entry(row.status.as_str()).or_default() += 1;
    }
    for status in STATUSES {
        println!("  {status}: {}", counts.get(status).copied().unwrap_or(0));
    }
    println!("report: {}", path.display());
}

/// Sends the batches through the native runtime's HTTP client, or refuses
/// when this `fz` was built without one.
#[cfg(feature = "auth-import")]
fn import_dispatch(options: &ImportOptions, users: &[Value]) -> Result<Outcome, String> {
    let (http, _clock) = native_stack();
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|err| format!("cannot start the async runtime this import needs: {err}"))?;
    runtime.block_on(import_all(&http, options, users))
}

/// The native runtime's own client — reqwest behind the outbound policy,
/// wrapped in the port's bounds — the same construction `fz push send`
/// uses (issue #184), so the import goes through the client the runtime
/// uses rather than one written for the occasion.
#[cfg(feature = "auth-import")]
fn native_stack() -> (Arc<dyn HttpClient>, Arc<dyn cratefield_core::Clock>) {
    let clock: Arc<dyn cratefield_core::Clock> = Arc::new(cratefield_runtime_native::TokioClock);
    let http: Arc<dyn HttpClient> = Arc::new(cratefield_core::BoundedHttpClient::new(
        Arc::new(cratefield_runtime_native::ReqwestClient::new()),
        Arc::clone(&clock),
    ));
    (http, clock)
}

/// The refusal an `fz` without the feature prints: one line saying exactly
/// what to rebuild. Mirrors `push::send_now`'s, and for the same reason —
/// `auth-import` pulls `cratefield-runtime-native`, which `compile_error!`s
/// on wasm32, so the feature belongs on a separately installed binary and
/// never on a venture's own `cratefield-cli` dependency.
#[cfg(not(feature = "auth-import"))]
fn import_dispatch(_options: &ImportOptions, _users: &[Value]) -> Result<Outcome, String> {
    Err(
        "this `fz` was built without the `auth-import` feature, so it has no HTTP client and \
         cannot import. Install one that has it — `cargo install cratefield-cli --features \
         auth-import` — and run that binary (it needs no compiled-in harness); do not add the \
         feature to the venture's own `cratefield-cli` dependency, which would pull the native \
         runtime into its wasm build."
            .to_owned(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use cratefield_core::HttpError;
    use cratefield_testing::{FakeHttpClient, TempDir};
    use http::Response;

    fn json_response(body: &str) -> Result<Response<bytes::Bytes>, HttpError> {
        Response::builder()
            .status(200)
            .body(bytes::Bytes::from(body.to_owned()))
            .map_err(|err| HttpError::Transport(err.to_string()))
    }

    fn result_body(pairs: &[(&str, &str)]) -> String {
        let results: Vec<Value> = pairs
            .iter()
            .map(|(provider, id)| {
                serde_json::json!({
                    "external_provider": provider,
                    "external_id": id,
                    "status": "created",
                    "sub": format!("sub-{id}"),
                    "reason": Value::Null,
                })
            })
            .collect();
        serde_json::json!({ "dry_run": true, "results": results }).to_string()
    }

    fn options(dir: &TempDir, rows: &[(&str, &str)], batch_size: usize) -> ImportOptions {
        let file = dir.join("users.jsonl");
        let mut text = String::new();
        for (provider, id) in rows {
            use std::fmt::Write as _;
            writeln!(
                text,
                "{{\"external_provider\":{provider:?},\"external_id\":{id:?},\
                 \"email\":\"u{id}@example.com\",\"email_verified\":true}}"
            )
            .expect("writes to a String");
        }
        std::fs::write(&file, text).expect("writes the fixture");
        ImportOptions {
            file,
            target: "https://venture.example/".to_owned(),
            admin_token: "test-admin-token-0123456789abcdef".to_owned(),
            apply: false,
            merge_by_email: false,
            report: None,
            batch_size,
        }
    }

    /// The only synchronous orchestrator tests drive: it runs the same
    /// `prepare` then `import_all` the command does, over `pollster`
    /// rather than a tokio runtime so a `FakeHttpClient` needs no reactor.
    #[cfg(test)]
    fn import_with(http: &Arc<dyn HttpClient>, options: &ImportOptions) -> Result<Outcome, String> {
        let users = prepare(options)?;
        pollster::block_on(import_all(http, options, &users))
    }

    #[test]
    fn batching_splits_into_the_requested_sizes() {
        let dir = TempDir::new("fz-auth-import-batch");
        let options = options(
            &dir,
            &[("p", "1"), ("p", "2"), ("p", "3"), ("p", "4"), ("p", "5")],
            2,
        );
        // 5 users at 2 per batch is 2 + 2 + 1.
        let fake = FakeHttpClient::scripted(vec![
            json_response(&result_body(&[("p", "1"), ("p", "2")])),
            json_response(&result_body(&[("p", "3"), ("p", "4")])),
            json_response(&result_body(&[("p", "5")])),
        ]);
        let http: Arc<dyn HttpClient> = Arc::new(fake.clone());

        let outcome = import_with(&http, &options).expect("imports");

        assert_eq!(outcome.results.len(), 5);
        let captured = fake.captured();
        assert_eq!(captured.len(), 3, "5 users at 2 per batch is 3 requests");
        for (method, uri, _) in &captured {
            assert_eq!(method, "POST");
            assert_eq!(
                uri,
                "https://venture.example/v1/auth-core/admin/users/import"
            );
        }
        let sizes: Vec<usize> = captured
            .iter()
            .map(|(_, _, body)| {
                serde_json::from_str::<Value>(body).expect("request is JSON")["users"]
                    .as_array()
                    .expect("users array")
                    .len()
            })
            .collect();
        assert_eq!(sizes, vec![2, 2, 1]);
    }

    #[test]
    fn the_report_never_carries_an_email_or_a_password_hash() {
        let dir = TempDir::new("fz-auth-import-report-privacy");
        let email = "alice@example.com";
        let hash = "argon2id$v=19$m=19456,t=2,p=1$c2FsdA$c2FsdA";
        let file = dir.join("users.jsonl");
        std::fs::write(
            &file,
            format!(
                "{{\"external_provider\":\"legacy\",\"external_id\":\"42\",\"email\":\"{email}\",\
                 \"email_verified\":true,\"password_hash\":\"{hash}\"}}\n"
            ),
        )
        .expect("writes the fixture");
        let options = ImportOptions {
            file,
            target: "https://venture.example".to_owned(),
            admin_token: "test-admin-token-0123456789abcdef".to_owned(),
            apply: false,
            merge_by_email: false,
            report: None,
            batch_size: DEFAULT_BATCH_SIZE,
        };
        let fake = FakeHttpClient::scripted(vec![json_response(&result_body(&[("legacy", "42")]))]);
        let http: Arc<dyn HttpClient> = Arc::new(fake.clone());

        let outcome = import_with(&http, &options).expect("imports");
        let report = options.report_path();
        write_report(&report, &outcome.results).expect("writes the report");

        let bytes = std::fs::read_to_string(&report).expect("reads the report");
        assert!(
            !bytes.contains(email),
            "the report carries no email: {bytes}"
        );
        assert!(!bytes.contains(hash), "the report carries no hash: {bytes}");
        // The request does carry them — that is the point of the import —
        // but it reaches the server and nowhere this command prints.
        let (_, _, request_body) = fake.captured().into_iter().next().expect("one request");
        assert!(
            request_body.contains(email),
            "the request carries the email"
        );
        assert!(request_body.contains(hash), "the request carries the hash");
    }

    #[test]
    fn a_missing_field_aborts_locally_before_any_request() {
        let dir = TempDir::new("fz-auth-import-missing-field");
        let file = dir.join("users.jsonl");
        std::fs::write(
            &file,
            "{\"external_provider\":\"p\",\"external_id\":\"1\",\"email_verified\":true}\n",
        )
        .expect("writes the fixture");
        let options = ImportOptions {
            file,
            target: "https://venture.example".to_owned(),
            admin_token: "test-admin-token-0123456789abcdef".to_owned(),
            apply: false,
            merge_by_email: false,
            report: None,
            batch_size: DEFAULT_BATCH_SIZE,
        };
        let fake = FakeHttpClient::ok_json("{}");
        let http: Arc<dyn HttpClient> = Arc::new(fake.clone());

        let error = import_with(&http, &options).expect_err("email is required");
        assert!(error.contains("line 1"), "{error}");
        assert!(error.contains("email"), "{error}");
        assert!(fake.captured().is_empty(), "nothing was sent");
    }

    #[test]
    fn a_duplicate_id_aborts_locally_before_any_request() {
        let dir = TempDir::new("fz-auth-import-duplicate");
        let options = options(&dir, &[("p", "7"), ("p", "7")], DEFAULT_BATCH_SIZE);
        let fake = FakeHttpClient::ok_json("{}");
        let http: Arc<dyn HttpClient> = Arc::new(fake.clone());

        let error = import_with(&http, &options).expect_err("the id is duplicated");
        assert!(error.contains("line 2"), "{error}");
        assert!(error.contains("duplicate"), "{error}");
        assert!(fake.captured().is_empty(), "nothing was sent");
    }

    #[test]
    fn a_line_that_is_not_an_object_is_a_local_error_with_its_line_number() {
        let dir = TempDir::new("fz-auth-import-not-object");
        let file = dir.join("users.jsonl");
        std::fs::write(&file, "\n[1, 2, 3]\n").expect("writes the fixture");
        let error = load_users(&file).expect_err("an array is not a user");
        assert!(error.contains("line 2"), "{error}");
        assert!(error.contains("JSON object"), "{error}");
    }

    #[test]
    fn dry_run_is_true_by_default_and_false_with_apply() {
        let dir = TempDir::new("fz-auth-import-dry-run");
        let dry = options(&dir, &[("p", "1")], DEFAULT_BATCH_SIZE);
        let fake = FakeHttpClient::scripted(vec![json_response(&result_body(&[("p", "1")]))]);
        let http: Arc<dyn HttpClient> = Arc::new(fake.clone());
        assert!(dry.dry_run());
        import_with(&http, &dry).expect("dry-runs");
        let body = fake.captured().into_iter().next().expect("one request").2;
        assert!(body.contains("\"dry_run\":true"), "{body}");

        let mut apply = options(&dir, &[("p", "1")], DEFAULT_BATCH_SIZE);
        apply.apply = true;
        apply.merge_by_email = true;
        let fake = FakeHttpClient::scripted(vec![json_response(&result_body(&[("p", "1")]))]);
        let http: Arc<dyn HttpClient> = Arc::new(fake.clone());
        assert!(!apply.dry_run());
        import_with(&http, &apply).expect("applies");
        let body = fake.captured().into_iter().next().expect("one request").2;
        assert!(body.contains("\"dry_run\":false"), "{body}");
        assert!(body.contains("\"merge_by_email\":true"), "{body}");
    }

    #[test]
    fn an_out_of_range_batch_size_is_a_local_error() {
        let dir = TempDir::new("fz-auth-import-batch-range");
        for batch_size in [0, MAX_BATCH_SIZE + 1] {
            let options = options(&dir, &[("p", "1")], batch_size);
            let error = prepare(&options).expect_err("out of range");
            assert!(error.contains("--batch-size"), "{error}");
        }
    }

    #[test]
    fn a_non_2xx_batch_fails_the_run_with_the_problem_detail() {
        let dir = TempDir::new("fz-auth-import-non-2xx");
        let options = options(&dir, &[("p", "1")], DEFAULT_BATCH_SIZE);
        let fake = FakeHttpClient::scripted(vec![
            Response::builder()
                .status(400)
                .body(bytes::Bytes::from(
                    r#"{"type":"about:blank","title":"Bad Request","detail":"too many users"}"#,
                ))
                .map_err(|err| HttpError::Transport(err.to_string())),
        ]);
        let http: Arc<dyn HttpClient> = Arc::new(fake.clone());

        let error = import_with(&http, &options).expect_err("a 400 fails the run");
        assert!(error.contains("400"), "{error}");
        assert!(error.contains("too many users"), "{error}");
    }

    #[test]
    #[cfg(not(feature = "auth-import"))]
    fn the_refusal_points_at_an_installed_binary() {
        let dir = TempDir::new("fz-auth-import-refusal");
        let options = options(&dir, &[("p", "1")], DEFAULT_BATCH_SIZE);
        let error = run(&options).expect_err("no client, no import");
        assert!(
            error.contains("cargo install cratefield-cli --features auth-import"),
            "{error}"
        );
        assert!(!error.contains("cratefield-cli = {"), "{error}");
    }
}
