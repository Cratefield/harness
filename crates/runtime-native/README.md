# factory0-runtime-native

The native runtime for the [Factory Zero harness](https://github.com/Factory-Zero/harness):
the same `Harness` served by axum on tokio as a single binary, for the
self-hosted move (ADR 0001, architecture section 10, issue #19). Cloudflare
Workers today, one binary on your own Postgres and Redis tomorrow — same
modules, same adapters, no module rewrites.

**Native only.** tokio, reqwest and redis do not compile to wasm, so this
crate fails compilation on any wasm target with a clear message and its
native dependencies are target-gated in `Cargo.toml`. A Worker depends on
`factory0-runtime-cloudflare`, never on this crate; `cargo tree --target
wasm32-unknown-unknown` of the venture must stay free of it.

## Usage

```rust,ignore
use std::sync::Arc;
use factory0_core::Harness;
use factory0_runtime_native::{Native, serve};

#[tokio::main]
async fn main() {
    let db = factory0_adapter_postgres::Postgres::connect(&std::env::var("DATABASE_URL").unwrap())
        .await
        .expect("database reachable");
    let runtime = Native::new().db_arc(Arc::new(db));
    let harness = Arc::new(harness()); // your composition, as on Workers
    serve(harness, runtime).await.expect("serve");
}
```

The builder mirrors the Cloudflare one: `.db(..)` takes any `Database`
(`Postgres` from `factory0-adapter-postgres`, `SqliteDatabase` from
`factory0-adapter-sqlite`), `.rate_limiter(..)`/`.kv(..)` take the Redis
adapters below, `.mailer(..)`/`.captcha(..)` take the adapter instances —
`Resend::from_env(..)` and `Turnstile::from_env(..)` unchanged from the
Workers path. `serve(harness, runtime)` binds, sanitizes client IPs,
starts the cron scheduler and serves until SIGTERM/SIGINT.

A complete example binary — the example venture's modules on Postgres or
SQLite — is [`examples/venture-native`](../../examples/venture-native/),
with the multi-stage distroless `Dockerfile` and the repo-root
`docker-compose.example.yml` (app + Postgres + Redis).

## Configuration

All keys are read from `std::env` through the same `Config` trait the
Workers runtime uses, so module keys (`EMAIL_SIGNUP_CONFIRM_TTL_DAYS`, …)
behave identically.

| Key | Default | Meaning |
|---|---|---|
| `LISTEN_ADDR` | `127.0.0.1:8080` | Bind address. Loopback by default; say `0.0.0.0:8080` when you mean it (the compose example does). |
| `HARNESS_SECRET`, `HARNESS_SECRET_PREVIOUS`, `ADMIN_TOKEN`, `ENV` | — | Harness-level keys, parsed by `HarnessConfig` exactly as on Workers. `HARNESS_SECRET` missing/short leaves the Signer port unset (warned once). |
| `TRUSTED_PROXY_HEADERS` | *(empty)* | Header names allowed to carry the client IP (see below). **Default: trust no forwarding header.** |
| `CRONS` | *(empty)* | Comma-separated cron expressions (UTC), fanned out to every module's `scheduled(ctx, cron)` — wrangler's `[triggers] crons` in config form. Invalid entries fail startup. |
| `REDIS_URL` | *(unset)* | Redis for `RateLimiter` + `KeyValue`; unset disables both ports. |
| `RATE_LIMIT_MAX`, `RATE_LIMIT_PERIOD_SECS` | `100`, `60` | Sliding-window parameters for `RedisRateLimiter` (per key). |

## Client IP: the one place native must differ

On Workers the edge sets `cf-connecting-ip` and forwarding headers are
client-forgeable. A native deployment sits behind its **own** proxy, so
this runtime owns IP resolution:

- With `TRUSTED_PROXY_HEADERS` empty (the default) the client IP is the
  TCP peer address, and every forwarding header
  (`cf-connecting-ip`, `x-forwarded-for`, `x-real-ip`, `forwarded`) is
  **stripped** before the router sees the request. A spoofed header
  cannot pick its own rate-limit key.
- With `TRUSTED_PROXY_HEADERS=x-forwarded-for` (or whichever headers a
  proxy you control overwrites), the first configured header whose first
  comma-separated entry parses as an IP wins, else the peer address.
- The resolved address is written into `cf-connecting-ip` — the header
  `factory0_core::client_ip` reads first — after stripping, so modules
  (which only ever call core) see exactly the runtime's verdict.

## Redis is not the Workers bindings

`RedisRateLimiter` and `RedisKv` implement the ports as closely as Redis
allows; the differences are documented on each type, not papered over.
Headlines: the limiter is a true sliding window (sorted-set + Lua) and
reports `retry_after`; the Workers Rate Limiting binding is fixed-window
and reports none. Redis is strongly consistent and single-node; Workers
KV is eventually consistent (up to ~60 s propagation) and replicated
per-colo. See the rustdoc of each adapter for the full list.

## Observability

`install_tracing()` (called by `serve`) installs a `tracing-subscriber`
JSON formatter writing one line per event to stdout, with the same
field-redaction rules as the Workers runtime (rules live in
`factory0-core`; secret-ish field names become `[redacted]`, email-ish
values become truncated SHA-256 hashes). `RUST_LOG` sets the filter
(default `info`). On wasm the Cloudflare runtime's `install_tracing` is a
no-op; here the real subscriber runs.

## Docker

```sh
export HARNESS_SECRET=$(openssl rand -hex 32)     # never commit a real secret
export POSTGRES_PASSWORD=$(openssl rand -hex 16)
docker compose -f docker-compose.example.yml up --build
curl -fsS http://127.0.0.1:8080/__health
curl -fsS http://127.0.0.1:8080/__ready
```

The compose file uses `/__ready` (a `SELECT 1` through the `Database`
port) as the app container's health check, executed by the binary itself
(`venture-native --check-ready`) because distroless ships no curl.
