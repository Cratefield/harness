//! The Logs screen, and the request recorder that feeds it.
//!
//! Nothing retained a log before this: `wrangler tail` streams and keeps
//! nothing, so a Logs screen over what existed would have had nothing
//! truthful to show. The half that had to be built first is
//! **retention for the control plane's own traffic**: one row per
//! request this dashboard's router served, written by the [`record`]
//! layer — when, method, path, status, duration, and the account the
//! session belonged to when there was one.
//!
//! What the table deliberately never holds: query strings, bodies,
//! headers. A path is a path; everything else is where personal data
//! and credentials live. The row's shape is the privacy posture, not a
//! redaction pass applied after the fact — there is nothing in the
//! schema that could have carried the rest.
//!
//! The recorder is a layer on **this module's own router**, not a
//! kernel change: request retention for the control plane's own traffic
//! is a leaf feature. The harness composes one shared middleware stack
//! in `crates/core/src/harness.rs` for every venture, and that is where
//! this moves the day every venture is to have request logs — moved,
//! not copied, so there is one recorder and one retention story.
//!
//! A venture's own logs are out of scope and the screen says so: they
//! need the venture reachable (#26) and a retention story of their own.

use std::sync::Arc;

use axum::extract::{Query, State};
use axum::http::HeaderMap;
use axum::middleware::Next;
use axum::response::{Html, IntoResponse, Response};
use cratefield_chrome::{Page, escape, render};
use cratefield_console::current_session;
use cratefield_core::{Database, DbError, Statement};
use sea_query::Value as SeaValue;
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

use crate::{DashboardState, account_nav, frame, guard, internal, text, ulid};

/// Where the screen sits under the dashboard.
const PATH: &str = "/v1/dashboard/logs";

/// One page of rows, the page size the data screen paginates with: small
/// enough to render inside a Worker, large enough to be worth scrolling.
const PAGE_SIZE: u64 = 25;

/// How long a request row lives. Fourteen days covers "what happened
/// around the incident" without becoming an archive of operator
/// behaviour — which is the one personal datum this table holds.
pub(super) const RETAIN_DAYS: i64 = 14;

/// The hard ceiling on rows, so a request loop cannot fill the database:
/// ten thousand rows is roughly a megabyte and still 400 pages at the
/// screen's page size, and beyond it the oldest rows go first.
pub(super) const MAX_ROWS: u64 = 10_000;

// ---------------------------------------------------------------------------
// The recorder
// ---------------------------------------------------------------------------

/// The layer wrapped around every route this module serves. Writes one
/// row per request, then serves the response whatever happened to the
/// write: request logs are an operator convenience about traffic that
/// already succeeded, and failing (or even delaying) a response because
/// its own telemetry could not be written would turn a leaf feature
/// into an outage source. A failed write is warned about and dropped;
/// the next request tries again, and the screen stays honest because it
/// renders rows, never promises completeness.
pub(super) async fn record(
    State(state): State<Arc<DashboardState>>,
    request: axum::extract::Request,
    next: Next,
) -> Response {
    let ctx = &state.ctx;
    let (Some(db), Some(clock)) = (ctx.ports.db.clone(), ctx.ports.clock.clone()) else {
        // The module requires both ports, so this is a degraded
        // deployment rather than a normal state — and even here the
        // request is served rather than recorded.
        tracing::warn!("request recorder: no db or clock port; request not recorded");
        return next.run(request).await;
    };

    // Read everything the row needs before the request is consumed.
    // The account is the session's when there was one; the empty string
    // is the row's own spelling of "nobody was signed in", not a gap.
    let account_id = current_session(ctx, request.headers())
        .map(|session| session.account_id)
        .unwrap_or_default();
    let method = request.method().as_str().to_owned();
    // This router is nested under `/v1/dashboard`, and axum hands a
    // nested service the stripped path — `/logs`, not
    // `/v1/dashboard/logs`. The recorded path is the one the caller
    // made, so it comes from `OriginalUri` when nesting put one there.
    let path = request
        .extensions()
        .get::<axum::extract::OriginalUri>()
        .map_or_else(
            || request.uri().path().to_owned(),
            |original| original.path().to_owned(),
        );
    let started = clock.now();

    let response = next.run(request).await;

    let at = started.format(&Rfc3339).unwrap_or_default();
    let elapsed = (clock.now() - started).whole_milliseconds().max(0);
    let duration_ms = i64::try_from(elapsed).unwrap_or(i64::MAX);
    let status = i32::from(response.status().as_u16());
    if let Err(err) = db
        .execute(&Statement::with_values(
            "INSERT INTO request_log (id, at, method, path, status, duration_ms, account_id) \
             VALUES (?, ?, ?, ?, ?, ?, ?)",
            vec![
                text(&ulid(ctx)),
                text(&at),
                text(&method),
                text(&path),
                SeaValue::Int(Some(status)),
                SeaValue::BigInt(Some(duration_ms)),
                text(&account_id),
            ],
        ))
        .await
    {
        tracing::warn!(error = %err, path = %path, "request could not be recorded; served anyway");
    }
    // Retention rides on the write rather than a schedule: the control
    // plane's own traffic is operator-sized, the window delete is
    // indexed and usually matches nothing, and tying cleanup to the
    // event means a stopped system stops accumulating too. The day this
    // moves to the kernel for every venture is the day it earns a
    // schedule of its own.
    if let Err(err) = enforce_retention(db.as_ref(), started).await {
        tracing::warn!(error = %err, "request log retention failed; retried on next write");
    }
    response
}

/// Deletes rows older than the window, then trims the table to the cap,
/// oldest first. Idempotent, cheap on an empty table, and the only code
/// that ever removes request rows.
async fn enforce_retention(db: &dyn Database, now: OffsetDateTime) -> Result<(), DbError> {
    let cutoff = (now - time::Duration::days(RETAIN_DAYS))
        .format(&Rfc3339)
        .unwrap_or_default();
    db.execute(&Statement::with_values(
        "DELETE FROM request_log WHERE at < ?",
        vec![text(&cutoff)],
    ))
    .await?;
    db.execute(&Statement::with_values(
        "DELETE FROM request_log WHERE id NOT IN \
         (SELECT id FROM request_log ORDER BY id DESC LIMIT ?)",
        vec![SeaValue::BigInt(Some(
            i64::try_from(MAX_ROWS).unwrap_or(i64::MAX),
        ))],
    ))
    .await?;
    Ok(())
}

// ---------------------------------------------------------------------------
// The screen
// ---------------------------------------------------------------------------

/// One recorded request.
struct LogRow {
    at: String,
    method: String,
    path: String,
    status: u16,
    duration_ms: i64,
    account_id: String,
}

/// The status classes the filter offers. Exactly the three the screen
/// promises (2xx, 4xx, 5xx): a class nobody filters by is a row nobody
/// can hide, and adding one is a one-line change here.
fn class_bounds(class: &str) -> Option<(i32, i32)> {
    match class {
        "2xx" => Some((200, 299)),
        "4xx" => Some((400, 499)),
        "5xx" => Some((500, 599)),
        _ => None,
    }
}

/// The screen's filters, parsed from the query string once: a status
/// class from the three offered, and a path prefix. Parsed, never
/// trusted — an unknown class or an empty prefix is no filter, and the
/// prefix is capped because it is operator input echoed back onto the
/// page.
struct Filters {
    class: Option<&'static str>,
    prefix: Option<String>,
}

impl Filters {
    fn parse(query: &[(String, String)]) -> Self {
        let class = query
            .iter()
            .find(|(key, _)| key == "class")
            .map(|(_, value)| value.as_str())
            .and_then(|value| match value {
                "2xx" => Some("2xx"),
                "4xx" => Some("4xx"),
                "5xx" => Some("5xx"),
                _ => None,
            });
        let prefix: String = query
            .iter()
            .find(|(key, _)| key == "prefix")
            .map(|(_, value)| value.trim().chars().take(200).collect())
            .unwrap_or_default();
        Self {
            class,
            prefix: (!prefix.is_empty()).then_some(prefix),
        }
    }

    fn any(&self) -> bool {
        self.class.is_some() || self.prefix.is_some()
    }
}

/// The WHERE clause the filters select with: fixed fragments, every
/// value bound — user text never becomes SQL, only a parameter.
fn filter_conditions(filters: &Filters) -> (String, Vec<SeaValue>) {
    let mut conditions: Vec<&'static str> = Vec::new();
    let mut params: Vec<SeaValue> = Vec::new();
    if let Some(bounds) = filters.class.and_then(class_bounds) {
        conditions.push("status >= ? AND status <= ?");
        params.push(SeaValue::Int(Some(bounds.0)));
        params.push(SeaValue::Int(Some(bounds.1)));
    }
    if let Some(prefix) = &filters.prefix {
        conditions.push("path LIKE ?");
        params.push(text(&format!("{prefix}%")));
    }
    if conditions.is_empty() {
        (String::new(), params)
    } else {
        (format!(" WHERE {}", conditions.join(" AND ")), params)
    }
}

/// One page of the log under `filters`: how many rows match, which page
/// this is, how many pages there are, and the rows themselves, newest
/// first.
async fn read_page(
    db: &dyn Database,
    filters: &Filters,
    requested_page: u64,
) -> Result<(u64, u64, Vec<LogRow>), cratefield_core::DbError> {
    let (where_clause, params) = filter_conditions(filters);
    let count: u64 = db
        .query(&Statement::with_values(
            format!("SELECT COUNT(*) AS n FROM request_log{where_clause}"),
            params.clone(),
        ))
        .await?
        .first()
        .and_then(|row| row.get("n"))
        .unwrap_or(0);
    let pages = count.div_ceil(PAGE_SIZE).max(1);
    let page_number = requested_page.max(1).min(pages);
    let mut page_params = params;
    page_params.push(SeaValue::BigInt(Some(
        i64::try_from(PAGE_SIZE).unwrap_or(i64::MAX),
    )));
    page_params.push(SeaValue::BigInt(Some(
        i64::try_from((page_number - 1) * PAGE_SIZE).unwrap_or(i64::MAX),
    )));
    let rows = db
        .query(&Statement::with_values(
            format!(
                "SELECT at, method, path, status, duration_ms, account_id \
                 FROM request_log{where_clause} ORDER BY id DESC LIMIT ? OFFSET ?"
            ),
            page_params,
        ))
        .await?
        .rows
        .iter()
        .map(|row| LogRow {
            at: row.get("at").unwrap_or_default(),
            method: row.get("method").unwrap_or_default(),
            path: row.get("path").unwrap_or_default(),
            status: row.get("status").unwrap_or_default(),
            duration_ms: row.get("duration_ms").unwrap_or_default(),
            account_id: row.get("account_id").unwrap_or_default(),
        })
        .collect();
    Ok((count, page_number, rows))
}

/// `/v1/dashboard/logs` — the retained requests, newest first,
/// filterable by status class and path prefix, paginated the way the
/// data screen paginates.
pub(super) async fn screen(
    state: State<Arc<DashboardState>>,
    headers: HeaderMap,
    Query(query): Query<Vec<(String, String)>>,
) -> Response {
    let ctx = &state.ctx;
    if let Err(redirect) = guard(ctx, &headers) {
        return redirect;
    }
    let session = current_session(ctx, &headers).expect("guard proved a session");
    let Some(db) = ctx.ports.db.clone() else {
        return internal("db port unavailable");
    };
    let filters = Filters::parse(&query);
    let requested_page = query
        .iter()
        .find(|(key, _)| key == "page")
        .and_then(|(_, value)| value.parse::<u64>().ok())
        .unwrap_or(1);
    let (count, page_number, rows) = match read_page(db.as_ref(), &filters, requested_page).await {
        Ok(page) => page,
        Err(err) => {
            tracing::error!(error = %err, "request log read failed");
            return internal("could not read the request log");
        }
    };
    let pages = count.div_ceil(PAGE_SIZE).max(1);

    let table = rows_table(&rows);
    let nav = if pages > 1 {
        format!(
            "<p class=\"dash__note\">Page {page_number} of {pages}. \
             <a href=\"{link_prev}\">Previous</a> · \
             <a href=\"{link_next}\">Next</a></p>",
            link_prev = page_link(
                filters.class,
                filters.prefix.as_deref(),
                page_number.saturating_sub(1).max(1)
            ),
            link_next = page_link(
                filters.class,
                filters.prefix.as_deref(),
                (page_number + 1).min(pages)
            ),
        )
    } else {
        String::new()
    };
    let (body, crumb) = render_body(&filters, count, &table, &nav);

    Html(render(&Page {
        title: "Logs",
        signed_in_as: Some(&session.account_id),
        body: &format!(
            "<div class=\"page-h\"><h1>Logs</h1></div>\
             <p class=\"lede\">What the control plane served, kept long enough to look \
             at after the fact.</p>{frame}",
            frame = frame(&account_nav("logs"), &crumb, &body),
        ),
    }))
    .into_response()
}

/// The page body and its crumb: the scope banner, the filter form, the
/// rows, and the notes that keep the screen honest about what it is
/// not.
#[allow(clippy::format_push_string)] // the house idiom for HTML building
fn render_body(filters: &Filters, count: u64, table: &str, nav: &str) -> (String, String) {
    let selected = |want: &str| {
        if filters.class == Some(want) {
            " selected"
        } else {
            ""
        }
    };
    let body = format!(
        "<p class=\"dash__banner\"><span class=\"chip\">Scope</span>\
         <strong>These are the control plane's own requests.</strong> Every request this \
         dashboard served: when it arrived, its method and path, the status and duration \
         it answered with, and the account the session belonged to when there was one. \
         A venture's own logs are a different thing — they need the venture reachable, \
         which needs <a href=\"{issue}\" rel=\"noopener\">#26</a>, and a retention story \
         of their own — and this screen does not pretend to have them.</p>\
         <div class=\"dash__card dash__card--wide\">\
         <p class=\"dash__card-h\">Requests <span class=\"dash__tag\">{count}</span></p>\
         <form class=\"dash__filter\" method=\"get\" action=\"{PATH}\">\
         <select name=\"class\">\
         <option value=\"\">all statuses</option>\
         <option value=\"2xx\"{sel2}>2xx</option>\
         <option value=\"4xx\"{sel4}>4xx</option>\
         <option value=\"5xx\"{sel5}>5xx</option></select> \
         <input name=\"prefix\" value=\"{prefix}\" maxlength=\"200\" \
         placeholder=\"path prefix, e.g. /v1/dashboard/data\"> \
         <button class=\"btn\" type=\"submit\">Filter</button> \
         <a class=\"btn\" href=\"{PATH}\">Clear</a></form>\
         {table}{nav}\
         <p class=\"dash__note\">No query string, request body or header is recorded, on \
         purpose: a path is a path, and everything else is where personal data and \
         credentials live. Retention is a {RETAIN_DAYS}-day window and a \
         {MAX_ROWS}-row cap, both enforced on write, so the log is a view of recent \
         traffic rather than an archive a loop can grow.</p>\
         <p class=\"dash__note\">The row for the request that rendered this page is \
         written after the page is built, so it appears on refresh — that is the \
         recorder's ordering, not a missing row. Newest first throughout.</p></div>",
        issue = "https://github.com/Cratefield/control-plane/issues/26",
        count = count,
        prefix = escape(filters.prefix.as_deref().unwrap_or("")),
        sel2 = selected("2xx"),
        sel4 = selected("4xx"),
        sel5 = selected("5xx"),
        table = table,
        nav = nav,
    );
    let crumb = format!(
        "{count} request{s}{filtered} · newest first",
        s = if count == 1 { "" } else { "s" },
        filtered = if filters.any() { " · filtered" } else { "" },
    );
    (body, crumb)
}

/// The rows as the read-only table the data screen uses: one row per
/// recorded request, the status coloured by the same three classes the
/// filter offers.
#[allow(clippy::format_push_string)] // the house idiom for HTML building
fn rows_table(rows: &[LogRow]) -> String {
    let mut table = String::new();
    if rows.is_empty() {
        table.push_str(
            "<p class=\"dash__empty\">No requests recorded for this filter. An empty \
             log with no filter also means no traffic yet — this page's own request is \
             written after the page is built, so reload and it will be here.</p>",
        );
        return table;
    }
    table.push_str("<div class=\"dash__scroll\"><table class=\"dash__rows\">");
    table.push_str(
        "<thead><tr><th>When</th><th>Method</th><th>Path</th>\
         <th>Status</th><th>Duration</th><th>Account</th></tr></thead><tbody>",
    );
    for row in rows {
        let status_class = if row.status >= 500 {
            "dash__st dash__st--bad"
        } else if row.status >= 400 {
            "dash__st dash__st--warn"
        } else {
            "dash__st"
        };
        table.push_str(&format!(
            "<tr><td>{at}</td><td>{method}</td><td>{path}</td> \
             <td><span class=\"{status_class}\">{status}</span></td> \
             <td>{duration_ms} ms</td><td>{account}</td></tr>",
            at = escape(&row.at),
            method = escape(&row.method),
            path = escape(&row.path),
            status = row.status,
            duration_ms = row.duration_ms,
            account = if row.account_id.is_empty() {
                String::from("<span class=\"dash__meta\">— no session</span>")
            } else {
                escape(&row.account_id)
            },
        ));
    }
    table.push_str("</tbody></table></div>");
    table
}

/// A pagination link that carries the active filters with it. Percent-
/// encoded by hand because the workspace keeps a strict dependency
/// budget and the values are short operator input, not arbitrary URLs.
#[allow(clippy::format_push_string)] // the house idiom for HTML building
fn page_link(class: Option<&str>, prefix: Option<&str>, page: u64) -> String {
    let mut query = String::new();
    if let Some(class) = class {
        query.push_str("class=");
        query.push_str(&query_encode(class));
        query.push('&');
    }
    if let Some(prefix) = prefix {
        query.push_str("prefix=");
        query.push_str(&query_encode(prefix));
        query.push('&');
    }
    query.push_str(&format!("page={page}"));
    format!("{PATH}?{query}")
}

/// Percent-encodes everything outside the URL-unreserved set.
#[allow(clippy::format_push_string)] // the house idiom for HTML building
fn query_encode(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for byte in value.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                out.push(byte as char);
            }
            _ => {
                out.push('%');
                out.push_str(&format!("{byte:02X}"));
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Dashboard;
    use cratefield_access::{DEFAULT_TTL_SECS, issue_session};
    use cratefield_accounts::Repository;
    use cratefield_core::{Clock, Statement};
    use cratefield_testing::TestHarness;
    use http::{Method, Request as HttpRequest, StatusCode, header};
    use tower::util::ServiceExt;

    const EMAIL: &str = "op@cratefield.com";
    const NOW: u64 = 1_800_000_000;

    fn kit() -> TestHarness {
        TestHarness::new(vec![
            Box::new(cratefield_console::Console),
            Box::new(Dashboard::new(None)),
        ])
    }

    fn cookie(kit: &TestHarness) -> String {
        let token = issue_session(kit.signer.as_ref(), EMAIL, NOW, DEFAULT_TTL_SECS);
        format!("cf_session={token}")
    }

    async fn get(kit: &TestHarness, uri: &str, cookie: Option<&str>) -> (StatusCode, String) {
        let mut builder = HttpRequest::builder().method(Method::GET).uri(uri);
        if let Some(cookie) = cookie {
            builder = builder.header(header::COOKIE, cookie);
        }
        let response = kit
            .router
            .clone()
            .oneshot(builder.body(axum::body::Body::empty()).expect("request"))
            .await
            .expect("router answers");
        let (parts, body) = response.into_parts();
        let bytes = axum::body::to_bytes(body, 4 * 1024 * 1024)
            .await
            .expect("body");
        (
            parts.status,
            String::from_utf8(bytes.to_vec()).expect("utf-8"),
        )
    }

    /// The account guard needs an account row to exist; the ventures
    /// page is enough traffic for the recorder to have something to do.
    async fn seed_account(kit: &TestHarness) {
        Repository::new(kit.db.clone())
            .account_for_login(EMAIL, "Op", "acc_1", "t0")
            .await
            .expect("account");
    }

    /// Plants a row exactly the recorder's shape, with an id the test
    /// controls so ordering is deterministic (ULIDs sort after any id
    /// starting with a digit, so planted rows read as the oldest).
    async fn plant(kit: &TestHarness, id: &str, at: &str, method: &str, path: &str, status: u16) {
        kit.db
            .execute(&Statement::with_values(
                "INSERT INTO request_log (id, at, method, path, status, duration_ms, account_id) \
                 VALUES (?, ?, ?, ?, ?, ?, ?)",
                vec![
                    text(id),
                    text(at),
                    text(method),
                    text(path),
                    SeaValue::Int(Some(i32::from(status))),
                    SeaValue::BigInt(Some(3)),
                    text(""),
                ],
            ))
            .await
            .expect("planted row");
    }

    #[pollster::test]
    async fn the_recorder_writes_a_row_per_request_and_the_page_shows_them() {
        let kit = kit();
        seed_account(&kit).await;

        let (status, _) = get(&kit, "/v1/dashboard", Some(&cookie(&kit))).await;
        assert_eq!(status, StatusCode::OK);

        let (status, body) = get(&kit, PATH, Some(&cookie(&kit))).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        // The earlier request is on the page, and the banner keeps the
        // scope honest.
        assert!(body.contains("<td>/v1/dashboard</td>"), "{body}");
        assert!(
            body.contains("These are the control plane's own requests"),
            "{body}"
        );
        assert!(body.contains("issues/26"), "{body}");

        // And the request that rendered the page appears on refresh.
        let (status, body) = get(&kit, PATH, Some(&cookie(&kit))).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert!(body.contains("<td>/v1/dashboard/logs</td>"), "{body}");
        // Newest first: the just-recorded /logs row sits above the
        // earlier /dashboard row.
        let newer = body.find("<td>/v1/dashboard/logs</td>").expect("newer row");
        let older = body.find("<td>/v1/dashboard</td>").expect("older row");
        assert!(newer < older, "rows must list newest first: {body}");
        // The planned page is gone.
        assert!(!body.contains("Not built."), "{body}");
    }

    #[pollster::test]
    async fn a_request_row_holds_the_path_and_status_and_never_the_query_or_body() {
        let kit = kit();
        seed_account(&kit).await;

        // A request whose query string carries exactly what a query
        // string always carries: a token nobody should retain.
        let (status, _) = get(
            &kit,
            "/v1/dashboard/logs?token=supersecret-abcdef&page=9",
            Some(&cookie(&kit)),
        )
        .await;
        assert_eq!(status, StatusCode::OK);

        // The paired positive assertion: the row is there, with its
        // path and its status — the thing that would have carried the
        // rest.
        let rows = kit
            .db
            .query(&Statement::with_values(
                "SELECT id, at, method, path, status, duration_ms, account_id \
                 FROM request_log WHERE path = ?",
                vec![text("/v1/dashboard/logs")],
            ))
            .await
            .expect("read the log");
        let row = rows.first().expect("the request was recorded");
        let whole_row = format!(
            "{}|{}|{}|{}|{}|{}|{}",
            row.get::<String>("id").unwrap_or_default(),
            row.get::<String>("at").unwrap_or_default(),
            row.get::<String>("method").unwrap_or_default(),
            row.get::<String>("path").unwrap_or_default(),
            row.get::<String>("status").unwrap_or_default(),
            row.get::<String>("duration_ms").unwrap_or_default(),
            row.get::<String>("account_id").unwrap_or_default(),
        );
        assert!(whole_row.contains("/v1/dashboard/logs"), "{whole_row}");
        assert_eq!(
            row.get::<u16>("status"),
            Some(200),
            "the row carries the status: {whole_row}"
        );
        assert_eq!(row.get::<String>("method").as_deref(), Some("GET"));
        // And the negative one, against every column the row has:
        assert!(
            !whole_row.contains("supersecret"),
            "a credential from the query reached the row: {whole_row}"
        );
        assert!(
            !whole_row.contains('?'),
            "no column of the row may hold a query string: {whole_row}"
        );
        assert!(!whole_row.contains("page=9"), "{whole_row}");
        // The session's account was recorded — the "when there was one"
        // half of the column's contract.
        assert_eq!(
            row.get::<String>("account_id").as_deref(),
            Some(EMAIL),
            "{whole_row}"
        );
    }

    #[pollster::test]
    async fn an_unauthenticated_request_is_recorded_without_an_account() {
        let kit = kit();
        seed_account(&kit).await;

        let (status, _) = get(&kit, PATH, None).await;
        assert_eq!(status, StatusCode::SEE_OTHER);

        let rows = kit
            .db
            .query(&Statement::with_values(
                "SELECT status, account_id FROM request_log WHERE path = ?",
                vec![text("/v1/dashboard/logs")],
            ))
            .await
            .expect("read the log");
        let row = rows.first().expect("the redirect was recorded");
        assert_eq!(row.get::<u16>("status"), Some(303));
        assert_eq!(
            row.get::<String>("account_id").as_deref(),
            Some(""),
            "no session means the empty account, not a guessed one"
        );
    }

    #[pollster::test]
    async fn a_recorder_that_cannot_write_does_not_fail_the_request() {
        let kit = kit();
        seed_account(&kit).await;
        // Take the table away: every recorder write and every retention
        // pass fails from here on.
        kit.db
            .execute(&Statement::new("DROP TABLE request_log".to_owned()))
            .await
            .expect("drop the log");

        // The request is served anyway — that is the whole decision.
        let (status, body) = get(&kit, "/v1/dashboard", Some(&cookie(&kit))).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert!(body.contains("Your ventures"), "{body}");
    }

    #[pollster::test]
    async fn retention_deletes_old_rows_and_caps_the_table() {
        let kit = kit();
        let now = kit.clock.now();
        // One row far outside the window, and a loop's worth past the
        // cap just inside it — planted relative to the kit's clock so
        // the window is exercised by the row, not by arithmetic luck.
        let old = (now - time::Duration::days(RETAIN_DAYS + 1))
            .format(&Rfc3339)
            .unwrap_or_default();
        let recent = (now - time::Duration::days(1))
            .format(&Rfc3339)
            .unwrap_or_default();
        plant(&kit, "a_old", &old, "GET", "/gone", 200).await;
        for n in 0..(MAX_ROWS + 5) {
            plant(&kit, &format!("r{n:05}"), &recent, "GET", "/loop", 200).await;
        }

        enforce_retention(kit.db.as_ref(), now)
            .await
            .expect("retention");

        let count = kit
            .db
            .query(&Statement::new(
                "SELECT COUNT(*) AS n FROM request_log".to_owned(),
            ))
            .await
            .expect("count")
            .first()
            .and_then(|row| row.get::<u64>("n"))
            .unwrap_or_default();
        assert_eq!(count, MAX_ROWS, "the cap holds");
        let oldest_gone = kit
            .db
            .query(&Statement::with_values(
                "SELECT id FROM request_log WHERE id IN (?, ?, ?, ?, ?)",
                vec![
                    text("a_old"),
                    text("r00000"),
                    text("r00001"),
                    text("r00002"),
                    text("r00003"),
                ],
            ))
            .await
            .expect("read");
        assert!(
            oldest_gone.is_empty(),
            "the out-of-window row and the five oldest are gone"
        );
        let newest_kept = kit
            .db
            .query(&Statement::with_values(
                "SELECT id FROM request_log WHERE id = ?",
                vec![text(&format!("r{:05}", MAX_ROWS + 4))],
            ))
            .await
            .expect("read");
        assert!(newest_kept.first().is_some(), "the newest rows survive");
    }

    #[pollster::test]
    async fn the_screen_filters_by_status_class_and_path_prefix_and_paginates() {
        let kit = kit();
        seed_account(&kit).await;
        // Fixtures must sit inside the retention window: the recorder
        // enforces it on every write, so a hardcoded date would be
        // deleted by the very request under test — the same reason the
        // session fixtures mint "now". Each row gets its own minute so
        // ordering is assertable through the page's own "when" column.
        let when = |n: i64| {
            (kit.clock.now() - time::Duration::days(1) - time::Duration::minutes(n))
                .format(&Rfc3339)
                .unwrap_or_default()
        };
        // Real ids are ULIDs — monotonic with time — so the fixture keeps
        // the same invariant: the highest id is the newest row.
        for n in 0..30 {
            let path = if n % 2 == 0 {
                "/v1/dashboard/data"
            } else {
                "/other/miss"
            };
            let status = if n % 2 == 0 { 200 } else { 404 };
            plant(
                &kit,
                &format!("p{n:05}"),
                &when(29 - n),
                "GET",
                path,
                status,
            )
            .await;
        }

        // Unfiltered, the data screen's pagination shape.
        let (status, body) = get(&kit, PATH, Some(&cookie(&kit))).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert!(body.contains("Page 1 of 2"), "{body}");
        assert!(body.contains(&when(0)), "{body}");
        assert!(!body.contains(&when(29)), "{body}");
        assert!(body.contains(">Previous</a>"), "{body}");
        let (status, page_two) = get(&kit, &format!("{PATH}?page=2"), Some(&cookie(&kit))).await;
        assert_eq!(status, StatusCode::OK, "{page_two}");
        assert!(page_two.contains("Page 2 of 2"), "{page_two}");
        assert!(page_two.contains(&when(29)), "{page_two}");

        // By status class: only the misses.
        let (status, body) = get(&kit, &format!("{PATH}?class=4xx"), Some(&cookie(&kit))).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert!(body.contains("<td>/other/miss</td>"), "{body}");
        assert!(!body.contains("<td>/v1/dashboard/data</td>"), "{body}");
        assert!(body.contains("15 requests"), "{body}");
        assert!(body.contains("value=\"4xx\" selected"), "{body}");

        // By path prefix: only the data screen's traffic.
        let (status, body) = get(
            &kit,
            &format!("{PATH}?prefix=/v1/dashboard/data"),
            Some(&cookie(&kit)),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert!(body.contains("<td>/v1/dashboard/data</td>"), "{body}");
        assert!(!body.contains("<td>/other/miss</td>"), "{body}");
        assert!(body.contains("15 requests"), "{body}");

        // An unknown class is no filter, not an error.
        let (status, body) = get(&kit, &format!("{PATH}?class=9xx"), Some(&cookie(&kit))).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert!(body.contains("/other/miss"), "{body}");
    }
}
