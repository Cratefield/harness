//! Port adapters over Workers bindings (ADR 0002).

mod clock;
mod d1;
mod defer;
mod dispatcher;
mod http;
mod kv;
mod rate_limit;

pub use clock::WorkersClock;
pub use d1::D1Database;
pub use defer::{ContextDefer, ScheduleDefer};
pub use dispatcher::ServiceDispatcher;
pub use http::FetchClient;
pub use kv::KvStorePort;
pub use rate_limit::RateLimitPort;

use axum::http::HeaderMap;

/// The caller's IP from `cf-connecting-ip`. Never `x-forwarded-for` on
/// Workers (architecture section 11): that header is client-controlled.
pub fn client_ip(headers: &HeaderMap) -> Option<String> {
    headers
        .get("cf-connecting-ip")
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned)
}
