//! The smallest complete Factory Zero venture — the wasm build canary.
//!
//! CI runs `worker-build --release` on this crate so any dependency that
//! cannot compile to `wasm32-unknown-unknown` fails the PR (issue #1).
//! Issue #5 rewires it onto `factory0-runtime-cloudflare` and the real
//! `Harness` router once the runtime crate exists.

#![forbid(unsafe_code)]

use axum::routing::get;
use worker::{event, Context, Env, HttpRequest, Result};

fn router() -> axum::Router {
    axum::Router::new()
        .route("/", get(|| async { "venture ok" }))
        .route("/__health", get(|| async { "ok" }))
}

#[event(fetch)]
async fn fetch(
    req: HttpRequest,
    _env: Env,
    _ctx: Context,
) -> Result<http::Response<axum::body::Body>> {
    use tower::Service;
    let req = req.map(axum::body::Body::new);
    Ok(router().call(req).await?)
}
