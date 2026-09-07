//! `cratefield-runtime-native` runs a Factory Zero `Harness` as a single
//! binary on tokio (ADR 0001, issue #19): axum on a `TcpListener`,
//! `reqwest` (rustls) behind the `HttpClient` port, Redis behind
//! `RateLimiter` and `KeyValue`, `tokio::spawn` behind `Defer`, the
//! system clock behind `Clock`, and an in-process cron scheduler fanning
//! out to every module's `scheduled(ctx, cron)`.
//!
//! The move for a venture (architecture section 10): keep the modules and
//! adapters, switch `.runtime(Cloudflare::new().db("DB"))` for
//! `.runtime(Native::new().db(Postgres::connect(url).await?))`, ship the
//! Dockerfile. No module code changes.
//!
//! # Native-only gate
//!
//! tokio, reqwest, redis and the JSON log subscriber do not compile to
//! wasm, so this crate is impossible to build for a wasm target:
//! `src/lib.rs` fails compilation with a clear message on `wasm32`/
//! `wasm64` (the same gate `cratefield-adapter-postgres` uses), and the
//! native dependencies are target-gated in `Cargo.toml`. The wasm graph
//! of `examples/venture` must stay free of this crate; CI asserts it
//! with `cargo tree --target wasm32-unknown-unknown`.
//!
//! # Client IP (the one behavioral difference from Workers)
//!
//! On Workers the edge sets `cf-connecting-ip` and forwarding headers are
//! client-forgeable. A native deployment sits behind its **own** proxy,
//! so this runtime owns IP resolution: [`trusted_proxy_headers`] lists
//! the header names the deployment is willing to believe (default
//! **empty** — an unconfigured deployment trusts no forwarding header),
//! [`client_ip`] resolves the address from those headers or the socket
//! peer, and the server middleware sanitizes every forwarding header
//! before the router sees the request. See [`client_ip`] for how the
//! resolved address is carried to the modules.
//!
//! # Redis is not the Workers bindings
//!
//! [`RedisRateLimiter`] and [`RedisKv`] implement the ports with
//! semantics as close to the Workers Rate Limiting binding and KV as
//! Redis allows; every difference is documented on the type, not papered
//! over. The headline ones: the limiter is a true sliding window that
//! can report `retry_after` (the binding is fixed-window and cannot),
//! and Redis is strongly consistent and single-node where KV is
//! eventually consistent and replicated per-colo.
//!
//! ```ignore
//! # async fn demo() -> Result<(), Box<dyn std::error::Error>> {
//! use std::sync::Arc;
//! use cratefield_core::Harness;
//! use cratefield_runtime_native::{Native, serve};
//!
//! let db = cratefield_adapter_postgres::Postgres::connect("postgres://user:pass@host:5432/venture").await?;
//! let harness = Arc::new(harness()); // your composition, as on Workers
//! let runtime = Native::new().db_arc(Arc::new(db));
//! serve(harness, runtime).await?;
//! # Ok(())
//! # }
//! # fn harness() -> Harness { unimplemented!() }
//! ```

#![doc = include_str!("../README.md")]
#![forbid(unsafe_code)]

// The whole crate is native-only (issue #19): fail a wasm build of this
// crate fast, with a clear message, before tokio/reqwest/redis are even
// attempted. Modules see ports, never runtimes, so no wasm graph can
// reach this crate through a module — the gate exists for the venture
// that wires the wrong runtime into a Worker.
#[cfg(any(target_arch = "wasm32", target_arch = "wasm64"))]
compile_error!(
    "cratefield-runtime-native is native-only: tokio, reqwest and redis do not \
     compile to wasm (issue #19, ADR 0001). A wasm target must not depend on \
     this crate — use cratefield-runtime-cloudflare on Workers, and check the \
     wasm dependency graph of the venture."
);

mod config;
mod cron;
mod ports;
mod runtime;
mod server;
mod tracing_setup;

pub use config::EnvConfig;
pub use cron::{CronError, fan_out, spawn_cron_scheduler};
pub use ports::{
    CLIENT_IP_HEADER, RedisBundle, RedisKv, RedisPortError, RedisRateLimiter, ReqwestClient,
    SpawnDefer, TokioClock, client_ip, redis_from_env, trusted_proxy_headers,
};
pub use runtime::Native;
pub use server::{ServeError, serve, serve_on, shutdown_signal};
pub use tracing_setup::install_tracing;
