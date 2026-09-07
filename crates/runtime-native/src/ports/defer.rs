//! `Defer` over `tokio::spawn` (architecture section 5): work that
//! outlives the response, the native counterpart of
//! `worker::Context::wait_until`.

use cratefield_core::Defer;
use futures_core::future::BoxFuture;

/// Spawns deferred work on the tokio runtime. Request-scoped through the
/// [`Scope`](cratefield_core::Scope) like every defer — the runtime holds
/// no state of its own.
///
/// The spawned task is detached: a panic inside it is tokio's default
/// panic-and-drop (the join handle is not awaited, exactly like a
/// fire-and-forget `wait_until` on Workers). Handlers that need errors
/// observed do the observing themselves before deferring.
#[derive(Debug, Clone, Copy, Default)]
pub struct SpawnDefer;

impl Defer for SpawnDefer {
    fn wait_until(&self, fut: BoxFuture<'static, ()>) {
        tokio::spawn(fut);
    }
}
