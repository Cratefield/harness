//! The changelog test kit (issue #16, on the module-linkedin pattern): a
//! scripted fake GitHub, a clock the test drives, and one kit per available
//! database dialect.
//!
//! CI has no GitHub credentials and never reaches the network. The fake
//! `HttpClient` is the enforcement: the module can only reach the outside
//! through the port it was handed, so a call the test did not script fails
//! the test rather than answering with something. The counter on the same
//! fake is what pins the read-path contract — after a refresh, a page load
//! must make **zero** upstream requests, and the test can prove it.

#![allow(dead_code)]
// A test-support module, included with `mod support;` into each test binary
// in this crate. `pub` is how a helper reads here, and the lint is right
// that nothing outside can reach it — the module is private to every binary
// that includes it. Saying so once beats `pub(crate)` on forty helpers.
#![allow(unreachable_pub)]

use async_trait::async_trait;
use bytes::Bytes;
use cratefield_core::{
    Clock, Config, Database, HttpClient, HttpError, KeyValue, MapConfig, Statement,
};
use cratefield_module_changelog::Changelog;
use cratefield_testing::{Dialect, MemoryKeyValue, TestHarness, TestResponse, request, request_as};
use http::{Method, Request, Response, StatusCode, header};
use serde_json::{Value, json};
use std::collections::{BTreeMap, HashMap};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, RwLock};
use time::OffsetDateTime;

/// The path the admin refresh lives at — the one spelling the surface
/// declares, under `/admin/` because core reserves admin-audience actions
/// for `/admin/*` paths.
pub const REFRESH_PATH: &str = "/v1/changelog/admin/refresh";
/// The venture's admin bearer, as `require_admin` expects to find it.
pub const ADMIN: &str = "test-admin-token-0123456789abcdef";
/// The repository every stock kit mirrors.
pub const REPO: &str = "acme/widgets";
/// Where every stock kit points `CHANGELOG_API_BASE`. The fake routes on
/// the path, so the host costs nothing — which is exactly why a test can
/// assert the module actually used the configured base.
pub const API_BASE: &str = "https://github.test.example/api";

// ---------------------------------------------------------------------------
// A clock the test drives
// ---------------------------------------------------------------------------

/// A clock a test can move, so `updated_at` / `refreshed_at` are
/// deterministic and a spurious write shows up against an advanced clock.
pub struct TestClock {
    unix: std::sync::atomic::AtomicI64,
}

impl TestClock {
    /// 2026-09-07T10:00:00Z, a fixed point so stored timestamps are readable
    /// in failure output.
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            unix: std::sync::atomic::AtomicI64::new(1_788_775_200),
        })
    }

    /// Moves the clock forward, past anything a refresh just stamped.
    pub fn advance_secs(&self, secs: i64) {
        self.unix.fetch_add(secs, Ordering::SeqCst);
    }

    /// The RFC 3339 stamp a refresh writes **right now** — what
    /// `store::now_iso` will produce from this clock — so tests assert
    /// against an expectation instead of against the previous row.
    pub fn now_iso(&self) -> String {
        OffsetDateTime::from_unix_timestamp(self.unix.load(Ordering::SeqCst))
            .expect("test clock stays in range")
            .replace_nanosecond(0)
            .expect("truncation stays in range")
            .format(&time::format_description::well_known::Rfc3339)
            .expect("a whole second always formats")
    }
}

impl Clock for TestClock {
    fn now(&self) -> OffsetDateTime {
        OffsetDateTime::from_unix_timestamp(self.unix.load(Ordering::SeqCst))
            .expect("test clock stays in range")
    }
}

// ---------------------------------------------------------------------------
// A scripted fake GitHub
// ---------------------------------------------------------------------------

/// One recorded upstream call.
#[derive(Debug, Clone)]
pub struct Call {
    pub method: String,
    pub url: String,
    /// The `If-None-Match` the module sent, when it sent one.
    pub if_none_match: Option<String>,
}

struct ScriptedPage {
    etag: String,
    entries: Vec<Value>,
}

#[derive(Clone)]
struct ScriptedFile {
    etag: String,
    text: String,
}

/// What a scripted failure answers, status and body.
#[derive(Debug, Clone)]
struct Failure {
    status: u16,
    body: Value,
}

impl Failure {
    fn respond(&self) -> Response<Bytes> {
        json_response(self.status, &self.body, None)
    }
}

#[derive(Default)]
struct Inner {
    requests: AtomicUsize,
    calls: RwLock<Vec<Call>>,
    /// Release pages by 1-based page number.
    pages: RwLock<HashMap<u64, ScriptedPage>>,
    /// The raw `CHANGELOG.md` a `changelog-md` source reads.
    file: RwLock<Option<ScriptedFile>>,
    /// Every call answers this, whatever else is scripted (GitHub is down).
    fail_every: RwLock<Option<Failure>>,
    /// One named page answers this (a fetch that fails partway).
    fail_page: RwLock<Option<(u64, Failure)>>,
    /// Bumped every time the test re-scripts, so the etag moves with the
    /// content the way a real upstream's does: a refresh holding the old
    /// etag gets a full fetch of the new script, and only a refresh whose
    /// etag still matches is answered `304`.
    script_generation: AtomicU64,
}

/// A GitHub that answers only what a test scripted and fails the test for
/// anything else. Conditional requests are modelled the way GitHub models
/// them: a call whose `If-None-Match` matches the currently scripted etag
/// is answered `304 Not Modified`, which is how the refresh path's etag
/// contract gets exercised end to end.
#[derive(Clone, Default)]
pub struct FakeGitHub {
    inner: Arc<Inner>,
}

impl FakeGitHub {
    pub fn new() -> Self {
        Self::default()
    }

    // --- scripting -------------------------------------------------------

    /// Scripts one page of releases (shorter than GitHub's 100, so the
    /// module's walk stops there) and a fresh etag to go with it.
    pub fn script_releases(&self, releases: &[Value]) {
        self.script_release_pages(&[releases]);
    }

    /// Scripts explicit release pages; a full page of 100 makes the module
    /// walk on to the next. Every re-script moves the etag, so the next
    /// refresh carrying the previously stored etag fetches in full.
    pub fn script_release_pages(&self, pages: &[&[Value]]) {
        let generation = self.inner.script_generation.fetch_add(1, Ordering::SeqCst) + 1;
        let scripted: HashMap<u64, ScriptedPage> = pages
            .iter()
            .enumerate()
            .map(|(index, entries)| {
                (
                    u64::try_from(index).expect("page index fits") + 1,
                    ScriptedPage {
                        etag: format!("\"releases-{generation}-{index}\""),
                        entries: entries.to_vec(),
                    },
                )
            })
            .collect();
        *self.inner.pages.write().expect("lock") = scripted;
    }

    /// Scripts release pages with **explicit, stable etags**: nothing moves
    /// behind the test's back, so a refresh presenting one of these etags is
    /// answered `304` for exactly that page. The multi-page etag contract
    /// needs the precision — an edit on page 2 leaves page 1, and page 1's
    /// etag, byte-identical, which is precisely the case a per-response etag
    /// must not be allowed to shortcut on.
    pub fn script_release_pages_with_etags(&self, pages: &[(&str, &[Value])]) {
        let scripted: HashMap<u64, ScriptedPage> = pages
            .iter()
            .enumerate()
            .map(|(index, (etag, entries))| {
                (
                    u64::try_from(index).expect("page index fits") + 1,
                    ScriptedPage {
                        etag: (*etag).to_owned(),
                        entries: entries.to_vec(),
                    },
                )
            })
            .collect();
        *self.inner.pages.write().expect("lock") = scripted;
    }

    /// The etag currently scripted for release `page` — what a refresh
    /// holding it gets answered `304` with.
    pub fn page_etag(&self, page: u64) -> String {
        self.inner
            .pages
            .read()
            .expect("lock")
            .get(&page)
            .unwrap_or_else(|| panic!("no release page {page} is scripted"))
            .etag
            .clone()
    }

    /// The etag currently scripted for release page 1 — what the next
    /// refresh sends back in `If-None-Match`.
    pub fn releases_etag(&self) -> String {
        self.page_etag(1)
    }

    /// Scripts the raw file a `changelog-md` source reads.
    pub fn script_changelog_md(&self, text: &str) {
        let generation = self.inner.script_generation.fetch_add(1, Ordering::SeqCst) + 1;
        *self.inner.file.write().expect("lock") = Some(ScriptedFile {
            etag: format!("\"changelog-md-{generation}\""),
            text: text.to_owned(),
        });
    }

    /// GitHub is down, forbidden or rate-limited: every call answers
    /// `status` with this JSON body, whatever else is scripted.
    pub fn fail_every_call(&self, status: u16, body: Value) {
        *self.inner.fail_every.write().expect("lock") = Some(Failure { status, body });
    }

    /// The named page answers `status` — a fetch that fails partway
    /// through, the only kind that must never prune a stored row.
    pub fn fail_page(&self, page: u64, status: u16, body: Value) {
        *self.inner.fail_page.write().expect("lock") = Some((page, Failure { status, body }));
    }

    // --- assertions ------------------------------------------------------

    /// How many upstream calls the module has made. The number that pins
    /// the read-path contract: after a refresh it must stay at zero.
    pub fn requests(&self) -> usize {
        self.inner.requests.load(Ordering::SeqCst)
    }

    /// Every recorded call, in order.
    pub fn calls(&self) -> Vec<Call> {
        self.inner.calls.read().expect("lock").clone()
    }

    /// Forgets the recorded calls and zeroes the counter. Scripts stay, so
    /// a test can refresh, then measure what a page load costs.
    pub fn forget_calls(&self) {
        self.inner.requests.store(0, Ordering::SeqCst);
        self.inner.calls.write().expect("lock").clear();
    }
}

/// The `page=` query parameter, which the module always sends on the
/// releases route.
fn page_of(url: &str) -> u64 {
    let raw = url
        .split(['?', '&'])
        .find_map(|pair| pair.strip_prefix("page="))
        .unwrap_or_else(|| panic!("no page= parameter in {url}"));
    raw.parse()
        .unwrap_or_else(|_| panic!("unreadable page= parameter in {url}"))
}

#[async_trait]
impl HttpClient for FakeGitHub {
    // One routing table, and it fails loudly: a route missing here is a
    // test bug or a module bug, and either way the test should stop.
    async fn send(&self, request: Request<Bytes>) -> Result<Response<Bytes>, HttpError> {
        let url = request.uri().to_string();
        let method = request.method().as_str().to_owned();
        let if_none_match = request
            .headers()
            .get(header::IF_NONE_MATCH)
            .and_then(|value| value.to_str().ok())
            .map(str::to_owned);
        self.inner.requests.fetch_add(1, Ordering::SeqCst);
        self.inner.calls.write().expect("lock").push(Call {
            method,
            url: url.clone(),
            if_none_match: if_none_match.clone(),
        });

        // GitHub is down: everything fails, whatever else is scripted.
        if let Some(failure) = self.inner.fail_every.read().expect("lock").clone() {
            return Ok(failure.respond());
        }

        if url.contains(&format!("/repos/{REPO}/releases")) {
            let page = page_of(&url);
            if let Some((only_page, failure)) = self.inner.fail_page.read().expect("lock").clone()
                && only_page == page
            {
                return Ok(failure.respond());
            }
            let pages = self.inner.pages.read().expect("lock");
            let scripted = pages.get(&page).unwrap_or_else(|| {
                panic!("the fake has no release page {page} scripted for {url}; script it before refreshing")
            });
            if if_none_match.as_deref() == Some(scripted.etag.as_str()) {
                return Ok(not_modified(&scripted.etag));
            }
            return Ok(json_response(
                200,
                &Value::Array(scripted.entries.clone()),
                Some(&scripted.etag),
            ));
        }

        if url.contains(&format!("/repos/{REPO}/contents/")) {
            let file = self.inner.file.read().expect("lock").as_ref().cloned();
            let Some(file) = file else {
                panic!(
                    "the fake has no file scripted for {url}; call script_changelog_md before refreshing"
                );
            };
            if if_none_match.as_deref() == Some(file.etag.as_str()) {
                return Ok(not_modified(&file.etag));
            }
            return Ok(raw_response(200, &file.etag, file.text.as_bytes()));
        }

        panic!(
            "the fake GitHub has no route for {} {url}; the module called something the test did not script",
            request.method(),
        );
    }
}

fn json_response(status: u16, body: &Value, etag: Option<&str>) -> Response<Bytes> {
    let mut builder = Response::builder()
        .status(StatusCode::from_u16(status).expect("a valid status"))
        .header(header::CONTENT_TYPE, "application/json");
    if let Some(etag) = etag {
        builder = builder.header(header::ETAG, etag);
    }
    builder
        .body(Bytes::from(
            serde_json::to_vec(body).expect("json serializes"),
        ))
        .expect("response builds")
}

fn raw_response(status: u16, etag: &str, body: &[u8]) -> Response<Bytes> {
    Response::builder()
        .status(StatusCode::from_u16(status).expect("a valid status"))
        .header(header::CONTENT_TYPE, "application/octet-stream")
        .header(header::ETAG, etag)
        .body(Bytes::copy_from_slice(body))
        .expect("response builds")
}

fn not_modified(etag: &str) -> Response<Bytes> {
    Response::builder()
        .status(StatusCode::NOT_MODIFIED)
        .header(header::ETAG, etag)
        .body(Bytes::new())
        .expect("response builds")
}

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

/// A stable GitHub release, with exactly the fields the module reads and a
/// body worth storing byte-for-byte.
pub fn release(tag: &str, published_at: &str, body: &str) -> Value {
    json!({
        "id": tag,
        "tag_name": tag,
        "name": format!("{tag} — release notes"),
        "body": body,
        "html_url": format!("https://github.com/{REPO}/releases/tag/{tag}"),
        "published_at": published_at,
        "created_at": published_at,
        "draft": false,
        "prerelease": false,
    })
}

/// A draft: GitHub sends no `published_at` for one, only `created_at`.
pub fn draft(tag: &str, created_at: &str) -> Value {
    let mut value = release(tag, created_at, &format!("working notes for {tag}"));
    value["published_at"] = Value::Null;
    value["name"] = json!(format!("{tag} — unreleased"));
    value["draft"] = json!(true);
    value
}

/// A published prerelease.
pub fn prerelease(tag: &str, published_at: &str) -> Value {
    let mut value = release(tag, published_at, &format!("the {tag} release candidate"));
    value["prerelease"] = json!(true);
    value
}

/// A body with markdown structure, whitespace and non-ASCII in it, so
/// byte-for-byte storage is provable rather than assumed.
pub const MARKDOWN_BODY: &str = "### Added\n\n- **bulk export**, em—dash and `inline code` intact\n\n```\nverbatim\n```\n\nSee the [docs](https://example.com/docs).";

/// A Keep-a-Changelog file: a preamble above the first heading, an
/// `Unreleased` section that is a draft and must never become a release,
/// and three releases in the three heading shapes the parser reads.
pub const CHANGELOG_MD: &str = "\
# Changelog

All notable changes to this project will be documented in this file.

## [Unreleased]

### Added

- everything currently on the workbench

## [1.2.0] - 2024-05-06

### Added

- the bulk export
- the retry knob

### Fixed

- the off-by-one in the paginator

## 1.1.0 - 2024-01-15

- the earlier thing

## v1.0.0

- where it started
";

/// The body the fixture's `## [1.2.0]` section stores: every line up to the
/// next heading, the markdown intact, trimmed at the edges.
pub const CHANGELOG_MD_120_BODY: &str = "### Added\n\n- the bulk export\n- the retry knob\n\n### Fixed\n\n- the off-by-one in the paginator";

/// `count` plain filler releases — page-filling for the tests that make the
/// module walk past a full page of 100.
pub fn filler_releases(count: usize) -> Vec<Value> {
    (0..count)
        .map(|index| {
            release(
                &format!("v0.0.{index}"),
                &format!("2025-01-01T00:{:02}:{:02}Z", index / 60, index % 60),
                "a filler release",
            )
        })
        .collect()
}

/// `count` filler releases tagged uniquely for `page` (`v{page}.0.{index}`),
/// so a multi-page script holds five hundred distinct versions and the
/// mirror's one-row-per-version key never fights itself.
pub fn filler_page(page: usize, count: usize) -> Vec<Value> {
    (0..count)
        .map(|index| {
            release(
                &format!("v{page}.0.{index}"),
                &format!("2025-01-01T00:{:02}:{:02}Z", index / 60, index % 60),
                &format!("a filler release from page {page}"),
            )
        })
        .collect()
}

// ---------------------------------------------------------------------------
// The kit
// ---------------------------------------------------------------------------

/// A built kit: the harness (one per available dialect), the fake GitHub
/// behind its `HttpClient` port, and the handles a test needs to drive
/// time, read the tables and assert on the traffic.
pub struct Kit {
    pub harness: TestHarness,
    pub fake: FakeGitHub,
    pub clock: Arc<TestClock>,
    /// The `KeyValue` behind the read cache, when the kit composed one.
    pub kv: Option<MemoryKeyValue>,
    /// The migrated database, for assertions the routes do not expose.
    pub db: Arc<dyn Database>,
    /// `"sqlite"` or `"postgres"` — for naming a failed leg in a message.
    pub dialect: &'static str,
}

/// What a kit is built with. The defaults are the no-wiring composition the
/// README promises: `Changelog::new()` composed bare, everything else in
/// configuration (`CHANGELOG_REPO`, `ADMIN_TOKEN`, a test
/// `CHANGELOG_API_BASE`), `KeyValue` present.
pub struct KitSpec {
    config: Vec<(String, String)>,
    kv: bool,
    make: fn() -> Changelog,
}

impl Default for KitSpec {
    fn default() -> Self {
        Self {
            config: vec![
                ("ADMIN_TOKEN".to_owned(), ADMIN.to_owned()),
                ("CHANGELOG_REPO".to_owned(), REPO.to_owned()),
                ("CHANGELOG_API_BASE".to_owned(), API_BASE.to_owned()),
            ],
            kv: true,
            make: Changelog::new,
        }
    }
}

impl KitSpec {
    /// Sets (or replaces) one configuration key.
    #[must_use]
    pub fn config(mut self, key: &str, value: &str) -> Self {
        self.set_key(key, Some(value));
        self
    }

    /// Drops a key entirely — how a test builds the unset-`ADMIN_TOKEN`
    /// case, where admin routes are disabled rather than merely wrong.
    #[must_use]
    pub fn without(mut self, key: &str) -> Self {
        self.set_key(key, None);
        self
    }

    /// Composes no `KeyValue` port at all: the read cache is absent, and
    /// nothing else may notice.
    #[must_use]
    pub fn without_kv(mut self) -> Self {
        self.kv = false;
        self
    }

    /// Composes the module differently in code — the other half of the
    /// "configuration wins" contract.
    #[must_use]
    pub fn module(mut self, make: fn() -> Changelog) -> Self {
        self.make = make;
        self
    }

    fn set_key(&mut self, key: &str, value: Option<&str>) {
        self.config.retain(|(existing, _)| existing != key);
        if let Some(value) = value {
            self.config.push((key.to_owned(), value.to_owned()));
        }
    }
}

/// One kit per available dialect ([`Dialect::available`]), each with its
/// **own** fake, clock and cache handles so the legs of the parity loop
/// cannot see each other's traffic: the recorded calls, the request count
/// and the advanced clock of the SQLite leg must not leak into the
/// Postgres leg's assertions.
pub fn kits_from(spec: &KitSpec) -> Vec<Kit> {
    Dialect::available()
        .into_iter()
        .map(|dialect| {
            let fake = FakeGitHub::new();
            let clock = TestClock::new();
            let kv = spec.kv.then(MemoryKeyValue::new);
            let config: Arc<dyn Config> = Arc::new(MapConfig::from_pairs(spec.config.clone()));

            let fake_for_ports = fake.clone();
            let clock_for_ports = clock.clone();
            let kv_for_ports = kv.clone();
            let config_for_ports = config.clone();
            let harness = TestHarness::with_database_and_ports(
                vec![Box::new((spec.make)())],
                dialect,
                move |ports| {
                    ports.http = Some(Arc::new(fake_for_ports.clone()));
                    ports.clock = Some(clock_for_ports.clone());
                    ports.kv = kv_for_ports
                        .as_ref()
                        .map(|kv| Arc::new(kv.clone()) as Arc<dyn KeyValue>);
                    ports.config = config_for_ports.clone();
                },
            );

            Kit {
                dialect: harness.dialect,
                db: harness.db.clone(),
                harness,
                fake,
                clock,
                kv,
            }
        })
        .collect()
}

/// The stock kits: `Changelog::new()` composed bare, configuration only,
/// `KeyValue` wired — one per available dialect.
pub fn kits() -> Vec<Kit> {
    kits_from(&KitSpec::default())
}

/// The stock kits with extra configuration set.
pub fn kits_with(extra: &[(&str, &str)]) -> Vec<Kit> {
    let mut spec = KitSpec::default();
    for (key, value) in extra {
        spec = spec.config(key, value);
    }
    kits_from(&spec)
}

// ---------------------------------------------------------------------------
// Requests
// ---------------------------------------------------------------------------

/// A GET against the kit's router. The public reads need no bearer.
pub async fn get(kit: &Kit, path: &str) -> TestResponse {
    request(&kit.harness.router, Method::GET, path, None).await
}

/// The admin refresh with an explicit bearer; `None` sends no
/// `Authorization` header at all.
pub async fn refresh_as(kit: &Kit, bearer: Option<&str>) -> TestResponse {
    match bearer {
        Some(token) => {
            request_as(&kit.harness.router, Method::POST, REFRESH_PATH, token, None).await
        }
        None => request(&kit.harness.router, Method::POST, REFRESH_PATH, None).await,
    }
}

/// The admin refresh as the operator's tooling sends it: the right bearer,
/// a 200, the report parsed. Panics otherwise, so every test can assert on
/// the report itself.
pub async fn refresh(kit: &Kit) -> Value {
    let response = refresh_as(kit, Some(ADMIN)).await;
    assert_eq!(
        response.status,
        StatusCode::OK,
        "refresh failed on the {} kit: {}",
        kit.dialect,
        body_of(&response),
    );
    response.json()
}

/// The buffered response body as text, for failure messages.
pub fn body_of(response: &TestResponse) -> String {
    String::from_utf8_lossy(response.body()).to_string()
}

// ---------------------------------------------------------------------------
// Reading the tables the routes do not expose
// ---------------------------------------------------------------------------

/// One column of one `changelog_release` row, by version — for
/// `first_seen_at` and friends, which the API deliberately hides.
pub fn release_field(kit: &Kit, version: &str, column: &str) -> Option<String> {
    let rows = pollster::block_on(kit.db.query(&Statement::with_values(
        format!("SELECT {column} AS value FROM changelog_release WHERE version = ?"),
        vec![text(version)],
    )))
    .expect("release query runs");
    rows.rows.first().and_then(|row| row.get::<String>("value"))
}

/// `updated_at` by version — exactly what an idempotent refresh must not
/// move, compared as a whole map so a spurious write on any row is caught.
pub fn updated_at_by_version(kit: &Kit) -> BTreeMap<String, String> {
    let rows = pollster::block_on(kit.db.query(&Statement::new(
        "SELECT version, updated_at FROM changelog_release ORDER BY version",
    )))
    .expect("updated_at query runs");
    rows.rows
        .iter()
        .filter_map(|row| {
            Some((
                row.get::<String>("version")?,
                row.get::<String>("updated_at")?,
            ))
        })
        .collect()
}

/// One column of the source's bookkeeping row: `etag`, `generation`,
/// `last_refreshed_at` or `last_status`.
pub fn source_field(kit: &Kit, column: &str) -> Option<String> {
    let rows = pollster::block_on(kit.db.query(&Statement::new(format!(
        "SELECT {column} AS value FROM changelog_source"
    ))))
    .expect("source query runs");
    rows.rows.first().and_then(|row| row.get::<String>("value"))
}

/// How many release rows are stored, whatever the source — the duplicate
/// detector of last resort.
pub fn release_count(kit: &Kit) -> i64 {
    let rows = pollster::block_on(kit.db.query(&Statement::new(
        "SELECT COUNT(*) AS n FROM changelog_release",
    )))
    .expect("count query runs");
    rows.rows
        .first()
        .and_then(|row| row.get::<i64>("n"))
        .unwrap_or_default()
}

fn text(value: &str) -> sea_query::Value {
    sea_query::Value::String(Some(Box::new(value.to_owned())))
}
