# factory0-runtime-cloudflare

Cloudflare Workers runtime for the [Cratefield harness](https://github.com/Cratefield/harness):
maps Workers bindings to the harness ports and serves a `Harness` on
`#[event(fetch)]` / `#[event(scheduled)]`.

## Usage

A venture's Worker is three lines:

```rust,ignore
use factory0_core::Harness;
use factory0_runtime_cloudflare::{serve, serve_scheduled, Cloudflare};
use std::sync::OnceLock;
use worker::{event, Context, Env, Request, Response};

static INSTANCE: OnceLock<(Harness, Cloudflare)> = OnceLock::new();

#[event(fetch)]
pub async fn fetch(req: Request, env: Env, ctx: Context) -> worker::Result<Response> {
    let (harness, runtime) = INSTANCE.get_or_init(build);
    serve(harness, runtime, req, env, ctx).await
}

#[event(scheduled)]
pub async fn scheduled(event: worker::ScheduledEvent, env: Env, ctx: worker::ScheduleContext) {
    let (harness, runtime) = INSTANCE.get_or_init(build);
    serve_scheduled(harness, runtime, event, env, ctx).await;
}
```

The runtime builder: `Cloudflare::new().db("DB").kv("KV").rate_limiter("RATE_LIMITER")`
plus `.mailer(...)`/`.captcha(...)` with adapter instances.

## wrangler.toml

```toml
name = "my-venture-api"
main = "build/worker/shim.mjs"
compatibility_date = "2026-09-01"

[build]
command = "cargo install -q worker-build && worker-build --release"

[observability]
enabled = true

[[d1_databases]]
binding = "DB"
database_name = "my-venture-db"
database_id = "<uuid>"
migrations_dir = "migrations"

# Optional bindings:
# [kv_namespaces] binding = "KV", id = "..."
# [unsafe.bindings] name = "RATE_LIMITER", type = "ratelimit"
```

Secrets (`wrangler secret put`, or `.dev.vars` locally — copy `.dev.vars.example`):
`HARNESS_SECRET` (required for the Signer port, ≥ 32 bytes),
`HARNESS_SECRET_PREVIOUS` (rotation), `ADMIN_TOKEN`, `ENV`.

## wasm notes (workerd/miniflare, wrangler 4.x)

These are empirical facts recorded while building this crate; see
`PROGRESS.md` issue #5 for the full debugging history:

- The `worker` crate's `http` feature stays **off**: with it enabled, D1
  writes hang the isolate. `serve()` therefore takes the native
  `worker::Request` (the fetch macro's `FromRequest` accepts it).
- Request bodies are buffered via `Request::bytes()` before entering the
  router; every streaming bridge between `worker::Body` and axum hangs.
- Installing a `tracing` dispatcher (`set_global_default`/`set_default`)
  hangs the isolate, so `install_tracing()` is a no-op on wasm and runtime
  logs go through `worker::console_log!`/`console_error!` directly
  (`rt_log!`). The JSON-lines subscriber with field redaction is used on
  native runs.
- The `time` crate needs its `wasm-bindgen` feature for `now_utc()` on
  wasm (pinned in the workspace `Cargo.toml`); without it every clock read
  panics (`time not implemented on this platform`).
