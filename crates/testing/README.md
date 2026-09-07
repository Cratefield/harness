# cratefield-testing

The conformance kit every Factory Zero module runs against — public and
private modules alike. Fake ports, an in-memory SQLite `Database`, and
request helpers over the axum router with **no network**.

## A 15-line module test

```rust,ignore
use cratefield_testing::{conformance, request, TestHarness};

#[test]
fn my_module_conforms() {
    conformance(Box::new(my_module::MyModule::new()));
}

#[pollster::test]
async fn join_accepts_an_email() {
    let kit = TestHarness::new(vec![Box::new(my_module::MyModule::new())]);
    let res = request(&kit.router, http::Method::POST, "/v1/my-module/join",
        Some(r#"{"email":"nick@example.com"}"#)).await;
    assert_eq!(res.status, http::StatusCode::ACCEPTED);
    assert_eq!(kit.mailer.sent().len(), 1); // the confirmation mail
}
```

## What you get

- `TestHarness::new(vec![Box<dyn Module>])` — builds the harness with
  every port faked, applies each module's sqlite migrations to a fresh
  in-memory database, assembles the router. Exposes `{ router, mailer,
  captcha, rate_limiter, db, clock, kv, http, defer, signer, events,
  modules, dialect }`.
- Parity (issue #20): `TestHarness::with_database(modules,
  Dialect::Sqlite | Dialect::Postgres { url })` runs the same harness on
  a throwaway Postgres 16 database (per-harness, dropped on drop; needs
  the crate's `postgres` feature and a server at
  `FZ_TEST_POSTGRES_URL`). `TestHarness::all_dialects(make_modules)` /
  `all_dialects_with_ports(make_modules, patch)` build one kit per
  dialect available in the environment so a module suite loops over
  them — one test definition, every engine. The module factory runs once
  per dialect: modules may carry per-build state, so kits never share
  instances.
- Fakes: `FakeMailer` (records `Message`s; `SendOk`/`NotConfigured`/`Fail`
  modes, switchable mid-test), `FakeCaptcha` (allow-all or token list),
  `FakeRateLimiter` (scripted `Decision`s + call count), `FixedClock`,
  `MemoryKeyValue`, `FakeHttpClient` (scripted responses + captured
  requests), `EmptyDatabase` (services `SELECT 1` only), `FakeDefer`
  (collects deferred futures; `drain().await` runs them), and a `Signer`
  with the fixed dummy `TEST_HARNESS_SECRET`.
- `request(&router, method, path, json?) -> TestResponse { status,
  headers, json() }` — `tower::ServiceExt::oneshot`, no network.
- `conformance(module)` — the shared suite, run once per available
  dialect: mounts + health listing, request under the prefix, migrations
  apply twice on fresh databases, `view_for` hides undeclared ports, the
  two-concurrent-requests request-id test (ADR 0007), and — for modules
  with a `well_known` router — that it serves at the root
  `/.well-known` and never under `/v1` (#46).
- `assert_wasm_safe_deps(env!("CARGO_PKG_NAME"))` — `cargo tree` check:
  no `worker`/`wasm-bindgen`/`tokio`/`reqwest` in the module's normal
  dependency tree.

The in-memory `Database` is `cratefield-adapter-sqlite`; assertions on
`kit.db` see exactly what the module wrote. On the Postgres leg `kit.db`
is a pool on the kit's own tokio runtime marshalled per call, so
pollster-driven tests, spawned threads and deferred handlers all reach
it.
