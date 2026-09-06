# Factory Zero backend harness — architecture

Status: v2 (Rust), adopted 2026-09-05, ADR 0008 added 2026-09-06, ADR 0009 added 2026-09-06. Owner: Factory Zero. Decisions are
recorded in [docs/adr](adr). Supersedes the TypeScript v1 design entirely.

## 1. What this is

One reusable, open-source backend harness, written in **Rust**, that every
Factory Zero venture compiles its own backend from. A venture's backend is a
small Cargo project that depends on the harness crates it wants, wires
adapters, and builds **one stateless Cloudflare Worker** (Rust compiled to
WebAssembly via `workers-rs`). Nothing is shared at runtime between ventures:
each venture has its own Worker, its own database, its own secrets.

Modules are Rust crates resolved at compile time. The kernel and most modules
are public; some modules are private. Cloudflare D1 is the database today; the
design keeps compute and storage swappable so everything can move to a
self-hosted native binary later without rewriting modules.

First deliverables: an **email signup** module (double opt-in via Resend) and
a **waitlist** module, deployed for factory0.ventures.

## 2. Principles

1. **Modules only see ports.** A module never touches a Cloudflare binding,
   `std::env`, or a vendor client. It receives trait objects: `Database`,
   `Mailer`, `Captcha`, `RateLimiter`, `Signer`, `KeyValue`, `Clock`, `IdGen`.
   Adapters implement the traits. This is what makes the self-hosted move a
   change of one runtime crate, not a rewrite.
2. **Compile-time composition.** A venture backend lists module crates in
   `Cargo.toml` and composes them in `src/harness.rs`. The wasm binary contains
   exactly those modules it serves in-process. No runtime plugin loading, no
   registry service. Cargo features select adapters. One narrowing, ADR 0009: a
   module whose source must stay with its owner may run as a **sidecar**, its
   own Worker reached over a service binding and mounted at the same
   `/v1/<name>`. It is still composed, just not into the same binary.
3. **Stateless by construction.** No `static mut`, no `thread_local!` state
   that outlives a request, no per-isolate caches of request data. Anything
   that must persist goes through `Database` or `KeyValue`. Confirmation and
   unsubscribe links are HMAC-signed tokens, so they need no server-side
   session. Request scope (request id, tracing span, `wait_until`) travels in
   axum request extensions, never in shared mutable state.
4. **Runtime-agnostic kernel.** `factory0-core` depends on `http`, `axum`
   (default features off), `serde`, `tracing`, and pure-Rust crypto. It has no
   `wasm-bindgen`, `worker`, `tokio` or `std::fs` dependency. Runtime-specific
   code lives in `factory0-runtime-cloudflare` (wasm) and, later,
   `factory0-runtime-native` (tokio).
5. **Portable SQL.** Migrations are hand-written SQL in a subset that both
   SQLite (D1) and Postgres accept, with per-dialect overrides only when
   unavoidable. Queries are built with `sea-query`, which renders the same
   query for either backend; execution goes through the `Database` trait.
6. **Small surface, boring crates.** axum, serde, sea-query, tracing, hmac,
   sha2, base64, subtle, ulid, askama, clap. No framework of our own beyond the
   `Module` trait.

## 3. Crate map

Crate names encode visibility and distribution. There are no scopes on
crates.io, so the prefix does the job.

| Prefix | Distribution | Visibility | Lives in |
|---|---|---|---|
| `factory0-*` | crates.io | public, MIT | `Cratefield/harness` |
| `fz-*` | git dependency (`git = "ssh://git@github.com/Factory-Zero/harness-private"`, pinned `tag`) | private | `Factory-Zero/harness-private` |

### `Cratefield/harness` (public Cargo workspace)

| Crate | Role |
|---|---|
| `factory0-core` | `Module` trait, `Harness` builder, axum router assembly, port traits, typed config, problem+json errors, request scope, tracing setup, in-process event bus, template registry. |
| `factory0-runtime-cloudflare` | `#[event(fetch)]` and `#[event(scheduled)]` entry points on `workers-rs`. Maps bindings to ports: D1 -> `Database` (sea-query -> `D1PreparedStatement`), KV -> `KeyValue`, Rate Limiting binding -> `RateLimiter`, `HARNESS_SECRET` -> `Signer`, `Context::wait_until` -> `Defer`. |
| `factory0-adapter-resend` | `Mailer` over the Resend REST API using the runtime's `HttpClient` port (no vendor SDK). Idempotency keys, error mapping, `NotConfigured` mode when the key is absent. |
| `factory0-adapter-turnstile` | `Captcha` over Cloudflare Turnstile siteverify. |
| `factory0-adapter-sqlite` | `Database` over `rusqlite` (bundled). Used by every test, and viable for a single-node self-hosted deployment. |
| `factory0-module-email-signup` | Collect an email, double opt-in, unsubscribe, admin export. |
| `factory0-module-waitlist` | Join a per-product waitlist, confirm, position, referral codes, admin export. |
| `factory0-cli` | Binary `fz`: `fz migrations collect`, `fz doctor`, `fz modules`. Run from the venture repo with `cargo run -p` or installed. |
| `factory0-testing` | Conformance kit for modules: fake mailer, fake captcha, fake rate limiter, fixed clock, in-memory `Database`, request helpers over the axum router (no network). Used by public and private modules alike. |
| `factory0-adapter-postgres` | (phase 3) `Database` over `sqlx` Postgres, for the native runtime. |
| `factory0-runtime-native` | (phase 3) The same harness served by axum on tokio as a single binary, for the self-hosted move. |

### `Factory-Zero/harness-private` (private Cargo workspace)

Same layout and tooling as `harness`. Crates are `fz-*` and are consumed as
pinned git dependencies; they are never published. Modules here pass the same
`factory0-testing` conformance kit. Candidate first module: `fz-module-admin`
(cross-module ops endpoints: stats, exports, deletion requests) because it
encodes internal process and needs no public API stability.

### `Factory-Zero/venture-backend-template` (public, GitHub template)

What a new venture clicks "Use this template" on. A Cargo project with
`src/harness.rs` (composition), `src/lib.rs` (Worker entry via the runtime
crate), `wrangler.toml` with `staging`/`production` envs, D1 and rate-limit
bindings, a `migrations/` dir maintained by `fz migrations collect`, a `tests/`
dir with a `harness_builds` test, CI (fmt, clippy, test, `fz doctor`,
`worker-build` dry run) and a deploy workflow (staging on `main`, production on
tag with a GitHub Environment approval gate).

### `Factory-Zero/factory0-backend` (private, first consumer)

Built from the template. Modules: `email-signup`, `waitlist`. Serves
`api.factory0.ventures`. The website's "enter" form and the ventures' waitlist
forms post here.

## 4. The module contract

```rust
// factory0-core
pub trait Module: Send + Sync + 'static {
    fn name(&self) -> &'static str;              // "email-signup" -> mounted at /v1/email-signup
    fn version(&self) -> &'static str;           // env!("CARGO_PKG_VERSION"), for /__health
    fn harness_api(&self) -> u32 { HARNESS_API } // contract version, checked by Harness::build
    fn requires(&self) -> &'static [Port];       // [Port::Db, Port::Mailer]; missing = build error
    fn optional(&self) -> &'static [Port] { &[] }
    fn tables(&self) -> &'static [&'static str] { &[] }
    fn emits(&self) -> &'static [&'static str] { &[] }
    fn public_writes(&self) -> bool { false }    // drives the production-captcha rule
    fn migrations(&self) -> Migrations;          // include_str! SQL per dialect
    fn validate_config(&self, cfg: &dyn Config) -> Result<(), ConfigError>;
    fn router(&self, ctx: ModuleContext) -> axum::Router;
    fn events(&self) -> Vec<(EventName, EventHandler)> { Vec::new() }
    fn scheduled<'a>(&'a self, ctx: &'a ModuleContext, cron: &'a str) -> BoxFuture<'a, Result<()>> {
        Box::pin(async { Ok(()) })
    }
}

pub struct ModuleContext {
    pub ports: Ports,            // Arc<dyn Database>, Option<Arc<dyn Mailer>>, ... only what was declared
    pub config: Arc<dyn Config>, // module keys are prefixed: EMAIL_SIGNUP_CONFIRM_TTL_DAYS
    pub events: EventBus,
    pub templates: Arc<TemplateRegistry>,
    pub venture: Arc<Venture>,   // name, domain, public_url, cors_origins, env
}

/// Per-request scope, inserted by core middleware into axum extensions.
pub struct Scope { pub request_id: String, pub defer: Defer, pub span: tracing::Span }
```

Handlers get the request scope as an axum extractor: `Scope` implements
`FromRequestParts`, so `async fn join(scope: Scope, State(ctx): State<Arc<ModuleContext>>, Json(body): Json<JoinBody>)`.
`ctx.events.emit_in(&scope, "waitlist.confirmed", payload)` runs handlers in
that request's `wait_until`. There is no ambient "current request".

A venture composes:

```rust
// src/harness.rs in a venture repo
use factory0_core::{Harness, Venture};
use factory0_runtime_cloudflare::Cloudflare;
use factory0_adapter_resend::Resend;
use factory0_adapter_turnstile::Turnstile;
use factory0_module_email_signup::EmailSignup;
use factory0_module_waitlist::Waitlist;

pub fn harness() -> Harness {
    Harness::builder()
        .venture(Venture::new("factory0", "factory0.ventures")
            .public_url("https://factory0.ventures")
            .cors_origins(["https://factory0.ventures"]))
        .module(EmailSignup::new().double_opt_in(true))
        .module(Waitlist::new().products(["kontinuum", "undercover-rockstars"]))
        .runtime(Cloudflare::new().db("DB").mailer(Resend::from_env()).captcha(Turnstile::from_env()))
        .build()
        .expect("harness configuration is invalid")
}
```

`Harness::build()` fails when a module requires a port the runtime does not
provide, when two modules claim the same route prefix or table, when a module's
`harness_api` differs from core's, or when a template override names an unknown
module. The template ships `tests/harness_builds.rs` asserting `build()` is
`Ok`, so `cargo test` fails before `wrangler deploy` can run.

## 5. Ports

| Port | Trait (sketch) | Cloudflare adapter | Self-hosted adapter |
|---|---|---|---|
| `Database` | `execute(&Statement) -> Result<u64>`, `query(&Statement) -> Result<Rows>`, `batch(&[Statement])` (atomic where the engine supports it); `Statement` = sea-query `(sql, values)` | D1 via `worker::D1Database` | Postgres via `sqlx`; SQLite via `rusqlite` |
| `Mailer` | `send(Message) -> Result<SendOutcome>` where `SendOutcome::{Sent{id}, NotConfigured}` | Resend over `HttpClient` | Resend (unchanged) |
| `Captcha` | `verify(token, remote_ip) -> Result<Verdict>` | Turnstile over `HttpClient` | Turnstile |
| `RateLimiter` | `limit(key) -> Result<Decision{ok, retry_after}>` | Workers Rate Limiting binding | Redis |
| `Signer` | `sign(Payload) -> String`, `verify(token, purpose) -> Option<Payload>` | HMAC-SHA256 (`hmac` + `sha2`) with `HARNESS_SECRET`; in core | same |
| `KeyValue` | `get/put/delete` with TTL | KV | Redis |
| `HttpClient` | `send(http::Request<Bytes>) -> http::Response<Bytes>` | `worker::Fetch` | `reqwest` |
| `Clock`, `IdGen` | `now() -> OffsetDateTime`, `ulid() -> String` | in core | in core |
| `Defer` | `wait_until(BoxFuture)` | `worker::Context::wait_until` | `tokio::spawn` |

All port traits are `Send + Sync`. On Workers the JS handles are `!Send`; the
Cloudflare adapters wrap them in `worker::send::SendWrapper`, which is sound
because a Workers isolate is single-threaded (ADR 0002). Async methods use
`async_trait` until native `async fn` in traits with `Send` bounds is
ergonomic for trait objects.

## 6. HTTP conventions

- Prefix `/v1/<module>`; `GET /__health` lists modules and versions; `GET /__ready` runs `SELECT 1` through `Database`.
- JSON in, JSON out. Bodies deserialize with serde into types whose constructors validate. Errors are RFC 9457 `application/problem+json` with a stable `type` URI per error (`https://factory0.ventures/problems/<slug>`), `instance` = request id.
- CORS allowlist from `venture.cors_origins` via `tower-http`. No wildcard in production.
- Every response carries `x-request-id` (accepted from the client if it matches `^[A-Za-z0-9_-]{8,128}$`, else a fresh ULID). Tracing spans carry it; logs are JSON keyed by it.
- Public write endpoints require a Turnstile token when the `Captcha` port is configured, and are rate limited per IP and per email.
- Admin endpoints (`/v1/<module>/admin/*`) require `Authorization: Bearer <ADMIN_TOKEN>` and are disabled when the token is unset.

### Email signup module

| Route | Behaviour |
|---|---|
| `POST /v1/email-signup` `{ email, source?, locale?, captchaToken? }` | Always `202` with an identical body. Creates or refreshes a `subscribers` row in `pending`; sends the confirmation mail with a signed link. Does not reveal whether the email already existed. |
| `GET /v1/email-signup/confirm?token=` | Verifies signature and TTL, flips to `confirmed`, `303` to the configured confirmed URL. |
| `POST /v1/email-signup/unsubscribe` `{ token }` and `GET .../unsubscribe?token=` | Flips to `unsubscribed`. Link is in every mail. |
| `GET /v1/email-signup/admin/export.csv` | Admin. |
| `DELETE /v1/email-signup/admin/subscribers/:email` | Admin. Hard delete for deletion requests. |

Table `subscribers(id, email, email_normalized unique, status, source, locale, confirmed_at, unsubscribed_at, created_at, updated_at)`.

### Waitlist module

| Route | Behaviour |
|---|---|
| `POST /v1/waitlist` `{ email, product, ref?, answers?, captchaToken? }` | `202`. Row in `waitlist_entries` as `pending`, confirmation mail. `product` must be in the configured list. |
| `GET /v1/waitlist/confirm?token=` | Confirms, assigns `position` (max+1 per product) inside a `batch`, credits the referrer, `303` to the status page with the entry's own referral code. |
| `GET /v1/waitlist/status?token=` | `{ product, position, referrals, referralCode, shareUrl }`. |
| `GET /v1/waitlist/admin/export.csv?product=` | Admin. |

Table `waitlist_entries(id, email, email_normalized, product, status, position, referral_code unique, referred_by, referrals, answers, created_at, confirmed_at)`, unique on `(email_normalized, product)`.

Emits `waitlist.confirmed`; a venture can subscribe that event to also add the address to the signup list.

## 7. Migrations

- Each module ships `migrations/sqlite/NNNN_<name>.sql` (and `migrations/postgres/` when the SQL differs), embedded with `include_str!` so the crate carries its own SQL.
- `fz migrations collect` in the venture repo writes `migrations/<GGGG>_<module>_<NNNN>_<name>.sql` for `wrangler d1 migrations apply`. A lockfile `migrations/.harness-lock.json` pins module migration -> global file so adding a module later appends and never renumbers, and detects edits to already-applied SQL by content hash.
- Portable subset: `TEXT` ids (ULID), ISO-8601 `TEXT` timestamps, `INTEGER` counters, no `AUTOINCREMENT`, no dialect-specific functions in DDL. `fz doctor` lints it.
- Postgres later: same files run through the `factory0-adapter-postgres` migrator.

## 8. Tooling and release

- Cargo workspace, `rust-toolchain.toml` pinning stable, `rustfmt` + `clippy -D warnings`, `cargo test` for core and modules against `factory0-adapter-sqlite`, `cargo deny` for licenses and advisories.
- Target `wasm32-unknown-unknown` built with `worker-build`; CI runs `worker-build --release` on the example venture to catch wasm-incompatible dependencies (anything pulling `tokio`, `mio`, `std::fs` at runtime).
- Release with `release-plz`: it opens a release PR with per-crate version bumps and changelogs from conventional commits; merging publishes `factory0-*` to crates.io using **trusted publishing** (OIDC from GitHub Actions, no long-lived token). Private crates are tagged, never published.
- Ventures pin exact crate versions; Renovate (cargo manager) opens bumps.
- `HARNESS_API` is bumped only on breaking contract changes; `factory0-core`'s major follows it.

## 9. Deployment

- One Worker per venture per environment (`<venture>-api-staging`, `<venture>-api`), custom domain `api.<venture domain>`. `wrangler.toml` uses `main = "build/worker/shim.mjs"` and `[build] command = "cargo install -q worker-build && worker-build --release"`.
- Secrets: `HARNESS_SECRET`, `RESEND_API_KEY`, `TURNSTILE_SECRET`, `ADMIN_TOKEN`. Set with `wrangler secret put` by a human for production; staging via GitHub Environment secrets.
- Mail sends from a **verified sending subdomain** `send.<domain>` (never the apex, which carries inbound Email Routing MX). Until verified, the adapter reports `NotConfigured` and the endpoints return `503 problem type=mail-not-configured` so forms can show a direct address.
- Deploy workflow: `main` -> staging automatically; tag `v*` -> production behind a GitHub Environment approval.

## 10. Migration path to self-hosted

Phase 3 introduces `factory0-adapter-postgres` and `factory0-runtime-native`.
The move for a venture is:

1. Stand up Postgres, run the same module migrations (postgres set).
2. Copy D1 data with `fz data export` / `fz data import`.
3. Switch `src/harness.rs` to `.runtime(Native::new().db(Postgres::from_env()).rate_limiter(Redis::from_env()))`, keep `Resend` and `Turnstile`. Build a native binary; ship the Dockerfile from the template.
4. Point `api.<domain>` at the new host.

No module code changes. The parity suite in `factory0-testing` runs every
module's tests against SQLite and Postgres in CI from phase 3 onward.

## 11. Security and privacy rules

- **No enumeration.** Signup and waitlist always answer `202` with the same body whether the address is new, pending, confirmed or unsubscribed.
- **Tokens carry a purpose.** Signed payload is `{ purpose, subject, exp?, kid }`. Confirm tokens expire (default 7 days); unsubscribe tokens do not. A confirm token is single-use because the row state is checked before flipping.
- **Key rotation.** `Signer` accepts `HARNESS_SECRET` plus `HARNESS_SECRET_PREVIOUS`; tokens name their `kid`, so rotation never breaks links in flight. MAC comparison uses `subtle::ConstantTimeEq`.
- **Fixed redirects.** Confirm endpoints redirect only to URLs from `Venture` config. No `redirect` query parameter.
- **Admin auth** uses a constant-time compare and is disabled entirely when `ADMIN_TOKEN` is unset. CSV exports escape leading `= + - @ \t \r` to block formula injection.
- **Rate limits** apply to every public endpoint, including confirm and status, keyed by IP (`cf-connecting-ip`, never `x-forwarded-for` on Workers) and, for writes, by normalized email.
- **Captcha is mandatory in production** when any module has `public_writes() == true`; `fz doctor` fails the build if the `Captcha` port is missing and `venture.env == Production`.
- **PII minimalism.** Store the email, its normalized form, timestamps, source and locale. Do not store IP addresses or user agents. Admin delete is a hard delete. A `retention` option purges `pending` rows older than N days from the scheduled handler.
- **Secrets never reach logs.** The tracing layer redacts fields matching `(?i)secret|token|key|authorization|password`; emails are logged only as a truncated SHA-256 `subject_hash`.
- **No `unsafe`** outside the Cloudflare adapters' `SendWrapper` use, and `#![forbid(unsafe_code)]` in core and every module.

## 12. Non-goals for v1

- Authentication and user accounts (later module).
- Payments (later, and only through the ports pattern).
- Multi-tenant single deployment **on the Worker path**. One venture = one Worker by design. The phase-3 native runtime does serve many tenants, one database each, with a separate control database; see ADR 0008 and issues #23 to #44.
- Runtime plugin loading. Unchanged by ADR 0009: Cloudflare's
  `WebAssembly.instantiate()` accepts only pre-compiled modules, so nothing is
  loaded at request time. A sidecar is a separately deployed Worker, not a
  plugin.
