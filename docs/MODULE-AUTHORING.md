# Module authoring guide

How to write a Factory Zero module: a crate that implements one trait,
sees nothing but ports, and passes the shared conformance suite. This
guide builds a complete module — `cratefield-module-hello` — from an empty
directory to green CI, step by step. The finished crate lives at
[`examples/module-hello/`](../examples/module-hello/) in this repository,
and its conformance run is part of CI.

Everything below is real: every snippet is the actual content of that
crate, and every command was run from the repository root with its real
output. Expect the walk-through to take under an hour.

Read first if you want the why: [ARCHITECTURE.md](ARCHITECTURE.md)
sections 2, 4, 5 and 11; ADRs [0002](adr/0002-ports-and-adapters.md),
[0004](adr/0004-sea-query-and-portable-sql-migrations.md) and
[0007](adr/0007-request-scope-in-extensions.md). To read a real module
after this guide: [`crates/module-email-signup/`](../crates/module-email-signup/)
(simple), [`crates/module-waitlist/`](../crates/module-waitlist/) (events,
atomic positions, scheduled work).

## What a module is

A module is one crate implementing `cratefield_core::Module`. `Harness::build()`
nests its router under `/v1/<name>`, checks its declared ports against the
runtime, rejects table and route collisions with other modules, and mounts
its migrations, events and scheduled work. The trait:

```rust
pub trait Module: Send + Sync + 'static {
    fn name(&self) -> &'static str;               // kebab-case; mounted at /v1/<name>
    fn version(&self) -> &'static str;            // env!("CARGO_PKG_VERSION")
    fn harness_api(&self) -> u32 { HARNESS_API }  // contract version; mismatch = build error
    fn requires(&self) -> &'static [Port];        // missing port = build error
    fn optional(&self) -> &'static [Port] { &[] } // used when present
    fn tables(&self) -> &'static [&'static str] { &[] }
    fn emits(&self) -> &'static [&'static str] { &[] }
    fn public_writes(&self) -> bool { false }     // legacy gate fallback;
        // declare `.captcha()` / `.policy(..)` per route (issue #133)
    fn migrations(&self) -> Migrations;           // include_str! SQL, per dialect
    fn validate_config(&self, cfg: &dyn Config) -> Result<(), ConfigError>;
    fn router(&self, ctx: ModuleContext) -> axum::Router;
    fn well_known(&self) -> Option<axum::Router> { None } // root /.well-known, at most one module
    fn events(&self) -> Vec<(EventName, EventHandler)> { Vec::new() }
    fn scheduled<'a>(&'a self, ctx: &'a ModuleContext, cron: &'a str) -> BoxFuture<'a, Result<(), AnyError>> { /* default: nothing */ }
}
```

The `ModuleContext` your router receives carries only what the module
declared:

```rust
pub struct ModuleContext {
    pub ports: Ports,            // only what requires()/optional() declared
    pub config: Arc<dyn Config>, // module keys prefixed: HELLO_MAX_NAME_LEN
    pub events: EventBus,
    pub templates: Arc<TemplateRegistry>,
    pub venture: Arc<Venture>,   // name, domain, public_url, cors_origins, env
}
```

### The rules

These are enforced by CI, by `fz doctor`, or by the conformance suite —
not by convention alone:

| Rule | Enforced by |
|---|---|
| `#![forbid(unsafe_code)]` in the crate | workspace lints (`unsafe_code = "forbid"`) |
| No `worker`, `wasm-bindgen`, `tokio`, `reqwest` in the normal dependency tree | `assert_wasm_safe_deps` (see step 7) and the wasm build of `examples/venture` |
| No `std::fs`, `std::net`, no `static mut`, no `thread_local!` request state | review; ADR 0001/0007 — anything native-only cannot enter a module |
| Queries through sea-query, never raw SQL strings | review; rendered by `Statement::render` |
| Migrations in the portable SQL subset (below) | `fz doctor` lints |
| Config keys `SCREAMING_SNAKE`, prefixed with the module name | `validate_config` + review |
| Passes `cratefield_testing::conformance` | the conformance CI job |
| Kebab-case `name()`, unique tables, unique route prefix | `Harness::build()` fails otherwise |

A module never touches a Cloudflare binding, `std::env`, or a vendor
client. It asks for a `Database`, a `Mailer`, a `Captcha`; adapters
answer. That one rule is what makes the self-hosted move (see
[PORTABILITY.md](PORTABILITY.md)) a change of one runtime crate.

## The module we will build

`hello` records names and counts them:

- `POST /v1/hello` `{ "name": "..." }` → `202 {"ok":true,"name":"..."}` —
  writes a row, emits `hello.recorded`;
- `GET /v1/hello/count` → `200 {"visits": N}`;
- one table `hello_visits`, one migration, one config key
  (`HELLO_MAX_NAME_LEN`), one optional port (`IdGen`).

Small — but it exercises the trait, ports, migrations, sea-query, config,
events, and the conformance suite. Everything a real module needs beyond
this (mailer, signer, templates, captcha) is the same machinery with a
different port; step 9 points at the real modules for those.

## Step 1 — Scaffold the crate

Module crates live in `crates/module-<name>/` inside this workspace. A
private one is named `fz-<name>` and carries `publish = false`; it sits in
the same directory as the public ones (ADR
[0013](adr/0013-one-repository.md)). The guide's crate is
`examples/module-hello/` because it ships as an example. Either way, the
scaffold is identical. `examples/module-hello/Cargo.toml`:

```toml
[package]
name = "cratefield-module-hello"
description = "Example Factory Zero module: one table, one write, one read, one event (built by docs/MODULE-AUTHORING.md)"
readme = "README.md"
publish = false
version.workspace = true
edition.workspace = true
rust-version.workspace = true
license.workspace = true
repository.workspace = true

[lints]
workspace = true

[dependencies]
cratefield-core = { workspace = true }
axum = { workspace = true }
serde = { workspace = true }
serde_json = { workspace = true }
sea-query = { workspace = true }
tracing = { workspace = true }

[dev-dependencies]
cratefield-testing = { workspace = true }
pollster = { workspace = true }
tower = { workspace = true }
http = { workspace = true }
```

Notes:

- `cratefield-core` is the only harness dependency a module needs. It is
  wasm-safe by construction (ADR 0001) and the CI job on this repository
  fails if it ever pulls `worker`, `wasm-bindgen`, `tokio`, `reqwest`,
  `sqlx` or `rusqlite`.
- `[lints] workspace = true` brings in `unsafe_code = "forbid"` and the
  clippy `pedantic` set the whole workspace uses.
- In this workspace the dependencies are `workspace = true`; in a private
  `fz-*` module outside it, they are ordinary version requirements.

`examples/module-hello/src/lib.rs` starts like this:

```rust
#![forbid(unsafe_code)]

mod handlers;
```

`handlers.rs` comes in step 4. Keep modules split (`lib.rs` for the
trait impl and builder, `handlers.rs` for HTTP, `store.rs` once query
code outgrows handlers) — both real modules follow that shape.

## Step 2 — Implement the trait

The whole `Module` impl for `hello` (this is
`examples/module-hello/src/lib.rs`, minus the doc comment):

```rust
use cratefield_core::{
    Config, ConfigError, DataKind, Disposition, Migrations, Module, ModuleConfig, ModuleContext,
    PersonalDataSet, Port, SqlMigration,
};
use std::sync::Arc;

/// The module's only migration: the `hello_visits` table in the portable
/// SQL subset (ADR 0004).
const MIGRATION_INIT: SqlMigration = SqlMigration {
    id: "0001",
    name: "init",
    sql: include_str!("../migrations/sqlite/0001_init.sql"),
    transactional: true,
};

/// Says hello, and counts how many times it was said.
pub struct Hello {
    settings: handlers::Settings,
}

impl Hello {
    /// A 64-character name limit; override at runtime with
    /// `HELLO_MAX_NAME_LEN`.
    pub fn new() -> Self {
        Self {
            settings: handlers::Settings { max_name_len: 64 },
        }
    }

    /// Compile-time default for the longest accepted name.
    #[must_use]
    pub fn max_name_len(mut self, len: u32) -> Self {
        self.settings.max_name_len = len;
        self
    }
}

impl Module for Hello {
    fn name(&self) -> &'static str {
        "hello"
    }

    fn version(&self) -> &'static str {
        env!("CARGO_PKG_VERSION")
    }

    fn requires(&self) -> &'static [Port] {
        &[Port::Db]
    }

    fn optional(&self) -> &'static [Port] {
        &[Port::IdGen]
    }

    fn tables(&self) -> &'static [&'static str] {
        &["hello_visits"]
    }

    fn personal_data(&self) -> &'static [PersonalDataSet] {
        const SETS: &[PersonalDataSet] = &[PersonalDataSet {
            table: "hello_visits",
            subject: "name",
            kind: DataKind::Contact,
            disposition: Disposition::Erase,
            description: "The name you said hello with, and nothing else.",
            redacted: &[],
        }];
        SETS
    }

    fn emits(&self) -> &'static [&'static str] {
        &[handlers::EVENT_RECORDED]
    }

    fn public_writes(&self) -> bool {
        true
    }

    fn migrations(&self) -> Migrations {
        const MIGRATIONS: [SqlMigration; 1] = [MIGRATION_INIT];
        Migrations {
            sqlite: &MIGRATIONS,
            postgres: &[],
        }
    }

    fn validate_config(&self, cfg: &dyn Config) -> Result<(), ConfigError> {
        let module = ModuleConfig::new("hello", cfg);
        let mut errors = ConfigError::default();
        if let Some(raw) = cfg
            .get(&module.key("MAX_NAME_LEN"))
            .map(|raw| raw.parse::<u32>())
            && matches!(raw, Ok(0) | Err(_))
        {
            errors.push(format!(
                "hello: {} must be a positive integer",
                module.key("MAX_NAME_LEN")
            ));
        }
        errors.into_result()
    }

    fn router(&self, ctx: ModuleContext) -> axum::Router {
        handlers::router(Arc::new(ctx), self.settings.clone())
    }
}
```

Decisions, one per method:

- **`name()`** `"hello"` — kebab-case, enforced; it is the route prefix
  `/v1/hello` and never changes after release (clients depend on it).
- **`version()`** — always `env!("CARGO_PKG_VERSION")`; `/__health`
  reports it.
- **`harness_api()`** — inherited default (`HARNESS_API`). You only
  mention it when a new core bumps it and you rebuild; `Harness::build`
  names your module and both versions in the error.
- **`requires()`** — `hello` cannot run without a `Database`. If the
  runtime does not provide one, `build()` fails with
  `module 'hello' requires port Database which the runtime does not provide`.
- **`optional()`** — `hello` uses `IdGen` when present (the runtime
  provides it) and falls back to `UlidIdGen` otherwise. Optional ports
  must always have a fallback path.
- **`tables()`** — every table the migrations create. Two modules claiming
  one table is a build error; this is how the harness prevents silent
  collisions. It is also what a whole-database `fz data export`/`import`
  carries, so adding a table here changes what a move of the venture takes
  with it. **Leaving one out is not a smaller decision than that**: a table
  in neither this list nor `personal_data()` is outside the export, outside
  erasure and outside the rule that compares them, all at once, which is
  where `auth-core` kept `deletion_jobs` and a person's identifier at their
  identity provider with it. Conformance now scans your migrations for
  `CREATE TABLE` and fails the module on anything missing here (issue #272).
- **`personal_data()`** — what each of those tables holds about a person.
  `cratefield-module-privacy` plans a subject access export and an erasure
  from this list and never from `tables()`, so a table missing here is
  never exported and never erased, and the erasure still reports success.
  **Every table you own needs an entry**: conformance fails otherwise
  (issue #244), and a table that holds nobody says so with
  `PersonalDataSet::none(table, reason)` — "no declaration" and "nothing
  personal here" must not look the same. Three fields are worth stopping
  on. `subject` is the *column* export and erasure match on, so a table
  whose only account id is inside a JSON payload cannot be declared with
  one. `disposition` is a decision per table, not a reflex: `Erase` for
  most, `Anonymise(&[..])` when deleting rows would break an aggregate
  somebody else can see, `Retain("why")` when the law says keep it — and
  the reason is published. `redacted` names columns an export must not
  copy, which is how a credential (a push token, a Web Push endpoint) can
  be declared for erasure without the export handing it out; the column is
  still listed, with `[redacted]` for a value. The sentence in
  `description` is published verbatim by `GET /v1/privacy/manifest`, so
  write it for the person reading that page.
- **`emits()`** — event names this module puts on the bus,
  `"<module>.<event>"`. Listed by `/__health` so operators can see what
  fires.
- **`public_writes()`** — `true` because `POST /v1/hello` is a public
  write. Since issue #133 this is the *legacy fallback* of the
  production-captcha rule; the primary declaration is per route in
  `surface()` (below). The rule is no longer a `fz doctor` advisory —
  `Harness::builder().build()` REFUSES to produce a production venture
  whose modules guard public writes (by route policy or by
  `public_writes()`) unless the runtime reports an *effective* `Captcha`
  port. Set it honestly; better yet, declare policies on the routes.
- **`migrations()`** — see step 3.
- **`depends_on()`** — the modules whose tables yours references, by
  name. It orders **migrations**, not routes: declare it when a foreign
  key of yours points at a table another module owns, so that table
  exists by the time your migration runs. Most modules own their schema
  outright and declare nothing, which is the default and costs nothing —
  the ordering is stable, so a venture that declares no dependencies
  keeps exactly the order it composed. Naming a module the venture did
  not compose fails the build, and so does a cycle; both at
  `Harness::builder().build()`, never at boot.
- **`validate_config()`** — see step 5. Always collect every problem into
  one `ConfigError` instead of failing on the first.
- **`router()`** — receives the `ModuleContext`; wrap it in an `Arc`,
  combine with your builder settings, hand both to `handlers::router`.

A builder (`Hello::new().max_name_len(..)`) is the composition surface a
venture sees in `src/harness.rs`. Settings that a venture must be able to
change without recompiling belong in config keys (step 5) with the builder
value as the default — the real modules do exactly that.

## Step 3 — Write the migration

`examples/module-hello/migrations/sqlite/0001_init.sql`:

```sql
CREATE TABLE IF NOT EXISTS hello_visits (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL
);
```

The portable SQL subset (ADR
[0004](adr/0004-sea-query-and-portable-sql-migrations.md); `fz doctor`
lints it):

- `TEXT` ids (ULIDs) and ISO-8601 `TEXT` timestamps, `INTEGER` counters;
- no `AUTOINCREMENT`, no `SERIAL`, no `NOW()`/`datetime(`, no
  `json_extract`, no backtick quoting — D1 is SQLite and the phase-3
  target is Postgres; the subset is what both accept;
- file names `NNNN_<slug>.sql`, zero-padded: lexical order is apply order;
- `include_str!` embeds the SQL in the crate, so a module ships its own
  schema and the venture never copies SQL around.

When Postgres genuinely needs different SQL you add
`migrations/postgres/NNNN_<slug>.sql` and fill `Migrations.postgres`.
Until then leave it empty — `hello` has none.

`fz migrations collect` in the venture repo collects every module's
sqlite set into `migrations/<GGGG>_<module>_<NNNN>_<name>.sql` for
`wrangler d1 migrations apply`, pinned by `migrations/.harness-lock.json`
so a module added later appends and never renumbers. It writes the files
and exits 0 silently. Real run against the acceptance fixture venture
(two modules, nothing collected yet), then a listing:

```
$ cargo run --manifest-path crates/cli-acceptance/fixture/Cargo.toml --bin fz -- \
      migrations collect --out /tmp/fixture-migrations
$ ls /tmp/fixture-migrations
0001_email-signup_0001_init.sql
0002_waitlist_0001_init.sql
.harness-lock.json
```

The lockfile records `email-signup/0001` → file `0001_...` plus a sha256
of its content; editing a collected file later fails the doctor and
`collect` with a content-hash mismatch — restore the file or add a new
migration.

In CI, the conformance kit applies your migrations **twice** to fresh
in-memory databases — write them idempotent (`IF NOT EXISTS`, or add-only
`ALTER TABLE`s).

**Never edit an applied migration.** Both engines record the sha256 of
each migration's SQL in `harness_migrations`, so a changed migration is
refused with an error naming it rather than silently skipped. `fz doctor`
catches the same edit inside the repository through
`.harness-lock.json`; the hash in the database is what catches it on a
deployment that already ran the old SQL. Write a new migration instead.

**A `no-transaction` migration must be idempotent.** You mark one with
`transactional: false` on its `SqlMigration`; `true` is the ordinary case,
and what every migration above uses. The ones Postgres refuses to run
inside a transaction — `CREATE INDEX CONCURRENTLY` is the one that comes
up — cannot be atomic with their tracking row, so the sequence is: run
the statement, then record it. A process that dies between the two leaves
the work done and unrecorded, and the next reconcile runs it again.

So write them so the second run is a no-op — `CREATE INDEX CONCURRENTLY
IF NOT EXISTS` — and never `CREATE INDEX CONCURRENTLY` bare. A
non-idempotent one fails on its second run, which is the run that
happens after a crash: a new error at the worst possible moment.
[ROLLBACK.md](ROLLBACK.md) §2 is the runbook for when it happens anyway.

CI refuses it earlier still (issue #34). `tools/migration-guard.sh` runs
on every pull request and fails it when a migration under any
`migrations/` directory is edited, deleted or renamed relative to the base
branch, when a sequence skips or repeats a number, when a
`migrations/postgres/` override names an id or name the canonical SQLite
set does not have, or when a migration mentions card data (#44) or carries
a connection string. A boot-time checksum mismatch is the last line of
defence and it fires in production; this is the first, where it is still a
diff someone can revert.

## Step 4 — Router and handlers

`examples/module-hello/src/handlers.rs`:

```rust
//! Handlers for `/v1/hello` (built in docs/MODULE-AUTHORING.md): one
//! public write, one public read. The write emits `hello.recorded` on the
//! shared bus.

use axum::extract::State;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::routing::{get, post};
use cratefield_core::{IdGen, Json, ModuleConfig, ModuleContext, Problem, Scope, Statement, UlidIdGen};
use serde::Deserialize;
use serde_json::{Value, json};
use std::sync::Arc;

/// Event emitted after a name is recorded; payload `{ "name": <str> }`.
pub(crate) const EVENT_RECORDED: &str = "hello.recorded";

/// The builder's compile-time settings, cloned into the router state.
#[derive(Clone)]
pub(crate) struct Settings {
    pub max_name_len: u32,
}

pub(crate) struct ModuleState {
    pub ctx: Arc<ModuleContext>,
    pub settings: Settings,
}

pub(crate) fn router(ctx: Arc<ModuleContext>, settings: Settings) -> axum::Router {
    let state = Arc::new(ModuleState { ctx, settings });
    axum::Router::new()
        .route("/", post(record))
        .route("/count", get(count))
        .with_state(state)
}

#[derive(Deserialize)]
struct RecordBody {
    name: String,
}

/// `POST /v1/hello` `{ "name": str }` -> `202 {"ok":true,"name":..}`;
/// records the visit and emits [`EVENT_RECORDED`] in this request's scope.
async fn record(
    scope: Scope,
    State(state): State<Arc<ModuleState>>,
    Json(body): Json<RecordBody>,
) -> Result<axum::response::Response, Problem> {
    let Some(db) = state.ctx.ports.db.clone() else {
        return Err(internal(&scope));
    };
    let cfg = ModuleConfig::new("hello", &*state.ctx.config);
    let max = cfg.get_u32("MAX_NAME_LEN", state.settings.max_name_len) as usize;

    let name = body.name.trim().to_owned();
    if name.is_empty() || name.chars().count() > max {
        return Err(Problem::validation_failed(format!(
            "name must be 1..={max} characters"
        ))
        .instance(&scope.request_id));
    }

    let id = state
        .ctx
        .ports
        .id_gen
        .as_ref()
        .map_or_else(|| UlidIdGen.ulid(), |id_gen| id_gen.ulid());
    let query = sea_query::Query::insert()
        .into_table(sea_query::Alias::new("hello_visits"))
        .columns([sea_query::Alias::new("id"), sea_query::Alias::new("name")])
        .values_panic([id.into(), name.clone().into()])
        .to_owned();
    db.execute(&Statement::render(&query)).await.map_err(|err| {
        tracing::error!(error = %err, "hello insert failed");
        internal(&scope)
    })?;

    state
        .ctx
        .events
        .emit_in(&scope, EVENT_RECORDED, json!({ "name": name }));
    Ok((StatusCode::ACCEPTED, Json(json!({ "ok": true, "name": name }))).into_response())
}

/// `GET /v1/hello/count` -> `200 {"visits": n}`.
async fn count(
    scope: Scope,
    State(state): State<Arc<ModuleState>>,
) -> Result<Json<Value>, Problem> {
    let Some(db) = state.ctx.ports.db.clone() else {
        return Err(internal(&scope));
    };
    let query = sea_query::Query::select()
        .expr_as(
            sea_query::Expr::col(sea_query::Alias::new("id")).count(),
            sea_query::Alias::new("count"),
        )
        .from(sea_query::Alias::new("hello_visits"))
        .to_owned();
    let rows = db.query(&Statement::render(&query)).await.map_err(|err| {
        tracing::error!(error = %err, "hello count failed");
        internal(&scope)
    })?;
    let visits: i64 = rows.first().and_then(|row| row.get("count")).unwrap_or(0);
    Ok(Json(json!({ "visits": visits })))
}

fn internal(scope: &Scope) -> Problem {
    Problem::internal().instance(&scope.request_id)
}
```

The patterns that matter:

- **`Scope` is an extractor, and it comes first.** The request id,
  tracing span and `wait_until` live in the request's extensions (ADR
  [0007](adr/0007-request-scope-in-extensions.md)); there is no ambient
  "current request". `Problem::validation_failed(..).instance(&scope.request_id)`
  ties the error document to the request that caused it. Never store a
  `Scope` or pass it to another request's code.
- **Errors are `Problem`** — RFC 9457 `application/problem+json` with a
  stable type URI per slug (`https://factory0.ventures/problems/<slug>`)
  and `instance` = request id. Use the constructors
  (`Problem::validation_failed`, `Problem::internal()`, `Problem::not_ready`, …);
  the taxonomy is generated into [ERRORS.md](ERRORS.md) and drift-checked
  in CI, so never invent a slug by hand.
- **Queries are sea-query, executed through the `Database` port.**
  `Statement::render(&query)` renders with the SQLite builder; on the
  Postgres adapter the same query tree renders for Postgres. Never
  concatenate SQL strings.
- **`db` is cloned out of the context per handler** (`Arc` clone), and a
  missing required port is treated as an internal error — the harness
  should have refused the build, so hitting that branch is a bug.
- **Bodies deserialize into validating types.** Trim, check length, then
  act. Public write endpoints answer `202` with an identical body shape
  whatever the row state — that is the no-enumeration rule (section 11);
  `hello` has no state to hide, the real modules show the full pattern.
- **JSON in, JSON out**; `cratefield_core::Json` re-exports the axum
  `Json` extractor/responder.

Captcha, rate limiting, and admin auth: public writes declare their
protection per route in `surface()` — `.captcha()` for a human form,
`.policy(RoutePolicy::Signature)` for a platform-signed webhook. The
`Captcha` bool on a route and the module-level `public_writes()` are
legacy mirrors, kept honest by `Route::validate()` (issue #133).
Handlers verify through `cratefield_core::verify_human_form`, which
fails closed in production for a missing port, a missing token, or a
provider/transport error. Rate limiting goes through `check_rate_limit`,
keyed by IP and, for writes, by normalized email, with an EXPLICIT
failure posture at every call site: `RateLimitFailure::FailClosed` for
abuse-critical paths (password reset, login), `FailOpen` where blocking
real users is worse than a throttle gap and something else carries the
load. Anything that sends mail to an address must additionally hold a
`SendCooldown` claim (`crates/core/src/cooldown.rs`, one table per
module) so a downed limiter can never become a mail flood. Admin
endpoints under `/v1/<module>/admin/*` require `Authorization: Bearer
<ADMIN_TOKEN>` via `cratefield_core::require_admin` and are disabled
when the token is unset. `Harness::build` refuses to produce a
production binary for a venture whose guards lack an effective `Captcha`
port; `fz doctor` re-checks the same rule at deploy time. Copy the exact
patterns from `crates/module-waitlist/src/handlers.rs` —
`check_captcha`, `rate_limited`, `require_admin` are the reusable
pieces.

## Step 5 — Config keys

Keys are `SCREAMING_SNAKE`, prefixed with the module name:
`HELLO_MAX_NAME_LEN`. Ventures set them as Workers vars or secrets; tests
set them through the kit's fake config.

`ModuleConfig` adds the prefix for you and parses with a default:

```rust
let cfg = ModuleConfig::new("hello", &*state.ctx.config);
let max = cfg.get_u32("MAX_NAME_LEN", state.settings.max_name_len) as usize;
```

`validate_config` rejects bad values up front (`fz doctor` runs it against
the venture's real config); collect every problem, not just the first —
`ConfigError::push` + `into_result()`, as in step 2.

The naming rule keeps modules out of each other's keys, and makes a
venture's config readable at a glance: every key says which module owns
it.

## Step 6 — Emit events

```rust
state
    .ctx
    .events
    .emit_in(&scope, EVENT_RECORDED, json!({ "name": name }));
```

`emit_in` takes the request's `Scope` explicitly and runs handlers in
that request's `wait_until` — a failed handler can never poison another
request. Name events `"<module>.<event>"` and list them in `emits()`.
Deliver payloads as plain JSON values; handlers must not assume a module
type they cannot see (modules cannot depend on each other — see below).

The worked example of subscribing: `email-signup`'s
`.subscribe_on_waitlist_confirm(true)` registers a handler for
`waitlist.confirmed` inside its `events()` method, mirroring confirmed
waitlist addresses into the signup list — with **no crate dependency**
between the two modules. Read `crates/module-email-signup/src/lib.rs`
(`fn events`) for the pattern.

### Durable and idempotent work

The event bus and `Defer` are execution *opportunities*, not durable
delivery — a crash or deadline after the commit loses the work. When a
side effect must survive that (a confirmation mail, a paid entitlement),
reach for two core primitives:

- **`cratefield_core::Outbox`** — write `enqueue_statement(..)` into the
  **same `db.batch`** as your state change so the work is durable exactly
  when the change is, then use `Defer` only to *attempt* immediate
  delivery (`claim_due` → deliver → `complete`/`retry_later`); drain the
  rest from the venture's scheduled entry point. At-least-once.
- **`cratefield_core::Inbox`** — before applying an inbound effect (a
  Stripe webhook, a redelivered event), `claim(db, event_id, now)`; only
  the first caller gets `true`. Exactly-once for the consumer.

Each owns a table the module declares — ship `create_table_sql()` as a
migration (Step 3). Pair them: an outbox gives at-least-once delivery, an
inbox key makes the consumer idempotent.

### Send a notification

Reaching a user's phone or browser is `cratefield-module-notifications`,
not your module: it owns the device registry, the per-account per-category
preferences, and the delivery policy that prunes a dead token and retries a
throttled provider. Your module says *what* happened; it says *whether and
where*.

Take the handle when the venture composes the harness:

```rust,ignore
let notifications = Notifications::new()
    .category(Category::new("booking"))
    .category(Category::new("room_starting").badge(true));
let notifier = notifications.notifier();

Harness::builder()
    .module(notifications)
    .module(MyBookingModule::new(notifier))   // your module holds it
```

Then send from inside the write that caused it. `notify` **writes
nothing**: it hands back outbox `INSERT`s for your own batch, so the
notification is durable exactly when your state change is — the `Outbox`
rule above, applied.

```rust,ignore
let enqueued = self.notifier
    .notify(&*db, &account_id, "booking", Notification::new("Booked", "See you Tuesday"))
    .await?;

let mut statements = vec![booking_insert];
statements.extend(enqueued.into_statements());
db.batch(&statements).await?;        // both, or neither

self.notifier.deliver_now(&scope);   // only now: a drain before the
                                     // commit would find no row
```

The order is not interchangeable, and nothing is lost if the isolate dies
between the two lines: the venture's scheduled entry point drains the rows
on the next tick.

A module that cannot take a crate dependency on it emits
`notifications.requested` on the event bus instead, with `account_id`,
`category` and a `Notification` — the same trade the `waitlist.confirmed`
subscription makes above: no crate edge, no atomicity with your batch.

Two rules to know before you read the code:

- **`PushError::Unregistered` is a delete instruction** and the only error
  that prunes a subscription (ADR
  [0015](adr/0015-platform-neutral-push-recipients.md)).
- **The preference is read in the drain**, immediately before the send, so
  an opt-out that arrives after your commit still wins.

## Step 7 — Conformance

`examples/module-hello/tests/conformance.rs` — the whole file:

```rust
use cratefield_module_hello::Hello;
use cratefield_testing::{assert_wasm_safe_deps, conformance};

#[test]
fn hello_conforms() {
    conformance(Box::new(Hello::new()));
}

#[test]
fn hello_deps_are_wasm_safe() {
    assert_wasm_safe_deps(env!("CARGO_PKG_NAME"));
}
```

`conformance()` mounts the module in the kit's harness and asserts:

1. it is listed by `GET /__health` with its version;
2. a request under `/v1/<name>/` is answered without a harness-level crash;
3. its sqlite migrations apply from scratch **twice** on fresh databases
   (idempotence);
4. `Ports::view_for` hides every port the module did not declare — a
   module cannot use what it did not ask for;
5. two concurrent requests keep their own request ids (the ADR 0007
   regression test);
6. a `well_known()` router, when provided, serves at the root
   `/.well-known` and never under `/v1`;
7. every table in `tables()` has a `personal_data()` declaration (issue
   #244) — the converse of the rule the harness build already enforces,
   which refuses a declaration for a table the module does not own;
8. every table your **migrations** create is in `tables()` (issue #272).
   Check 7 can only compare the two lists it is handed, so a table that
   never reached `tables()` is invisible to it, to `fz data export` and
   to erasure at once — `auth-core` created `deletion_jobs` and listed it
   nowhere. The kit scans your migration SQL for `CREATE TABLE`, and the
   same check runs the other way round: every table `tables()` names has
   to be one the scan found, so it cannot pass by matching nothing;
9. **sidecar parity** (issue #64): the module answers identically
   whether it is linked in or reached over a service binding (ADR 0009).

The parity axis builds the module twice — once in-process, once behind a
fake dispatcher whose "Worker" is a second harness — and sends both the
same probes with the same client-supplied request id, so a problem
body's `instance` and the `x-request-id` header compare byte for byte.
The probes are ones the kit can build without knowing your routes: an
unknown path, the module root, a malformed body. It also asserts that a
body over the 64 KiB cap is refused by the host and never forwarded, and
that every probe actually crossed the hop, so the comparison can never
pass because the mount quietly stopped working.

If a module genuinely cannot be sidecar-mounted, use
`conformance_in_process_only(module, "why")`. The reason is required and
printed by the run: it is the only record of the exception.
[MOUNTING.md](MOUNTING.md) lists what a sidecar cannot do, and when to
choose one at all.

`assert_wasm_safe_deps` runs `cargo tree -p <crate> --edges normal` and
fails on `worker`, `wasm-bindgen`, `tokio` or `reqwest` — the
wasm-boundary check you can run locally before CI does.

Every module in this repo runs both tests, public and private alike, in
the same CI job — so a private module cannot drift either. The shared
conformance workflow stays exported for modules built out of tree.

## Step 8 — Route tests

The kit also gives you a full fake harness for behaviour tests —
`TestHarness::new(vec![Box::new(module)])` applies migrations to a fresh
in-memory SQLite database, fakes every port, and exposes the real axum
router; `request(&kit.router, method, path, body)` drives it with no
network. `examples/module-hello/tests/routes.rs`:

```rust
use cratefield_module_hello::Hello;
use cratefield_testing::{TestHarness, request};
use http::{Method, StatusCode};

fn kit() -> TestHarness {
    TestHarness::new(vec![Box::new(Hello::new())])
}

#[pollster::test]
async fn a_recorded_visit_is_counted() {
    let kit = kit();
    let res = request(
        &kit.router,
        Method::POST,
        "/v1/hello",
        Some(r#"{ "name": "factory zero" }"#),
    )
    .await;
    assert_eq!(res.status, StatusCode::ACCEPTED);
    assert_eq!(res.json()["name"], "factory zero");

    let res = request(&kit.router, Method::GET, "/v1/hello/count", None).await;
    assert_eq!(res.status, StatusCode::OK);
    assert_eq!(res.json()["visits"], 1);
}

#[pollster::test]
async fn an_over_long_name_is_a_validation_problem() {
    let kit = kit();
    let body = format!(r#"{{ "name": "{}" }}"#, "x".repeat(65));
    let res = request(&kit.router, Method::POST, "/v1/hello", Some(&body)).await;
    assert_eq!(res.status, StatusCode::BAD_REQUEST);
    assert!(
        res.json()["type"]
            .as_str()
            .is_some_and(|uri| uri.ends_with("/problems/validation-failed")),
        "got {}",
        res.json()
    );
}

#[pollster::test]
async fn config_overrides_the_builder_limit() {
    let kit = TestHarness::new(vec![Box::new(Hello::new().max_name_len(4))]);
    let ok = request(
        &kit.router,
        Method::POST,
        "/v1/hello",
        Some(r#"{ "name": "ventures" }"#),
    )
    .await;
    assert_eq!(ok.status, StatusCode::BAD_REQUEST);
}
```

`kit.mailer.sent()`, `kit.db`, `kit.clock`, `kit.defer` and friends let
you assert on what the module actually did — see the
[`cratefield-testing` README](../crates/testing/README.md).

## Step 9 — Declare a surface

A module gets a UI for free once it says what it offers (ADR
[0010](adr/0010-modules-declare-a-ui-surface.md)). An axum router is opaque,
so `Module::surface` lists the **actions** (routes, relative to
`/v1/<name>`) and the **views** that compose them. The input schema of an
action is derived from the handler's own body type, so it cannot drift from
the route: derive `JsonSchema` next to `Deserialize` and put the UI hints on
the fields as `x-cf-*` keywords (the full list is on
`cratefield_core::HINT_KEYWORDS`).

```rust
#[derive(Deserialize, JsonSchema)]
struct RecordBody {
    #[schemars(extend("x-cf-label" = "Your name", "x-cf-placeholder" = "Ada"))]
    name: String,
}

pub(crate) fn surface() -> Surface {
    Surface::new()
        .action(Action::post("record", "/").input::<RecordBody>().accepted("Recorded. Hello!"))
        .action(Action::get("count", "/count").audience(Audience::Public).outcome(Outcome::Json))
        .view(View::form("record"))
        .view(View::status("count"))
}
```

and in the trait impl, `fn surface(&self) -> Surface { handlers::surface() }`.

Rules `Harness::build` enforces: action names are kebab-case and unique,
paths start with `/`, an `Admin` action lives under `/admin/` (and nothing
else does), an input schema describes an object, and a view names an action
the module declares. Mark fields the visitor must never type
(`captchaToken`, a referral code, a locale) with `x-cf-hidden`; a hint that
only exists at runtime (a `select` over configured products) is set after
derivation with `cratefield_core::hint_field`, as the waitlist does.

`GET /__surface` on the venture then lists the module. Admin actions and the
views over them appear only when the request carries the admin bearer.

## Step 10 — Run everything

From the repository root:

```
$ cargo test -p cratefield-module-hello
    Finished `test` profile [unoptimized + debuginfo] target(s) in 0.11s
     Running unittests src/lib.rs (target/debug/deps/cratefield_module_hello-…)
running 0 tests
test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out

     Running tests/conformance.rs (target/debug/deps/conformance-…)
running 2 tests
test hello_conforms ... ok
test hello_deps_are_wasm_safe ... ok
test result: ok. 2 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out

     Running tests/routes.rs (target/debug/deps/routes-…)
running 3 tests
test an_over_long_name_is_a_validation_problem ... ok
test config_overrides_the_builder_limit ... ok
test a_recorded_visit_is_counted ... ok
test result: ok. 3 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out

   Doc-tests cratefield_module_hello
running 1 test
test examples/module-hello/src/lib.rs - (line 6) - compile ... ok
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out
```

And the format/lint gates CI runs:

```
$ cargo fmt --all --check
$ cargo clippy --workspace --all-targets -- -D warnings
```

In this repository the example's conformance runs in CI twice over: in
the `test` job (`cargo test --workspace`) and in the dedicated
`conformance` job, which iterates `crates/module-*` **and**
`examples/module-hello`, running `cargo test -p <pkg> --test conformance`
per crate.

## Beyond hello

Everything else a module can do, with the module that does it:

- **Mailer + Signer + signed links** (double opt-in, unsubscribe):
  `crates/module-email-signup/` — HMAC tokens with purpose and TTL
  through the `Signer` port (ADR
  [0006](adr/0006-signed-tokens-for-opt-in.md)).
- **Atomic multi-statement writes** (`Database::batch`) and **positions**:
  `crates/module-waitlist/src/store.rs`.
- **Mail templates**: `crates/module-email-signup/src/mail.rs` — askama
  templates shipped as `pub fn default_templates()`, registered by the
  venture with `Harness::builder().templates(..)`, overridable per
  venture with `.template("<module>/<id>", ..)`; the id's module part
  must name a registered module.
- **Scheduled work** (cron): `Module::scheduled` — see waitlist's pending
  purge in `crates/module-waitlist/src/lib.rs`. Use the `ModuleContext`
  the runtime hands in and nothing else. A scheduled invocation never
  calls `Module::router`, so a module that keeps a context from
  router-build time has **none** on a cold isolate and a stale one on a
  warm isolate — and a test fixture that hands `scheduled` a stripped-down
  context cannot notice either.
- **A token verifier** (`factory0_auth_client::AuthClient`): build it once
  and park it, not inside `router()`. `router()` runs per request on
  Workers, and a fresh `AuthClient` starts with an empty JWKS cache: one
  extra outbound round-trip per authenticated request, drivable by anyone
  with a junk bearer. `crates/module-notifications/src/lib.rs` parks it in
  a `OnceLock` beside its context.
- **Push notifications**: `crates/module-notifications/` — subscriptions,
  per-category preferences, fan-out in the caller's own batch, and a drain
  that prunes, retries and dead-letters (ADR
  [0016](adr/0016-notifications-module-dead-letters-and-the-account.md)).
- **A route that acts for a signed-in account**: the same module's
  `Account` extractor, which delegates to `factory0-auth-client`'s
  `Authenticated`. `Scope` carries no principal (ADR 0007), so this is
  where an account id comes from — never a body field.
- **`/.well-known` discovery routes**: `Module::well_known` (root-level
  only; at most one module per venture may provide one).
- **CSV admin export with formula-injection escaping**: `cratefield_core::csv_row`.
- **Private modules**: same guide, same repo — `fz-*` crates with
  `publish = false`, consumed by ventures as ordinary path dependencies
  (ADR [0013](adr/0013-one-repository.md)), passing the same conformance
  suite.

### Checklist

Before opening a PR that adds or changes a module:

- [ ] `#![forbid(unsafe_code)]` at the crate root
- [ ] `cargo tree -p <crate> --edges normal` shows no `worker` /
      `wasm-bindgen` / `tokio` / `reqwest`
- [ ] migrations portable (subset above), idempotent, `include_str!`'d
- [ ] `surface()` declares every route a visitor or admin should see, and
      `JsonSchema` is derived on the same types the handlers deserialize
- [ ] `tables()` names every table your migrations `CREATE`, including one
      a later migration adds (issue #272)
- [ ] `personal_data()` covers every table in `tables()`, with the
      disposition decided per table and the description written for the
      person it is published to
- [ ] `name()`, `tables()`, `emits()` complete and honest; every public
      write declares `.captcha()` and every provider webhook
      `.policy(RoutePolicy::Signature)` (issue #133); `public_writes()`
      reflects reality as the legacy fallback
- [ ] config keys prefixed, `validate_config` collects all problems
- [ ] `tests/conformance.rs` passes locally
- [ ] route tests cover the happy path and every problem response
- [ ] `cargo fmt --all --check` and
      `cargo clippy --workspace --all-targets -- -D warnings` clean
- [ ] examples/venture still builds to wasm (`worker-build --release`)
