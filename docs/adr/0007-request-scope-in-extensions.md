# ADR 0007: Request scope travels in axum extensions, never in shared state

Status: accepted, 2026-09-05

## Context
The discarded TypeScript v1 kept "the current request" in a closure variable
that was saved and restored around each request. A review test proved that
two concurrent requests in one isolate swapped request ids in their logs and
one lost its `waitUntil`. Rust makes the same mistake possible with a
`thread_local!` or a `static` `RefCell`.

## Decision
Core middleware creates a `Scope { request_id, defer, span }` per request and
stores it in the request's extensions. Handlers receive it through the `Scope`
extractor. `EventBus::emit_in(&scope, ..)` and `Defer` take the scope
explicitly. `factory0-core` and every module carry `#![forbid(unsafe_code)]`
and a clippy lint deny on `thread_local!` and `static mut`.

## Consequences
- No ambient request context; a handler that needs the request id asks for it.
- The conformance kit includes a two-concurrent-requests test that asserts each request logs its own id.
