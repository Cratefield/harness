# ADR 0002: Modules depend on port traits; adapters are separate crates

Status: accepted, 2026-09-05

## Context
The database (D1 now, Postgres later), mailer, captcha and rate limiter are all
vendor services that will change. Modules must not.

## Decision
`cratefield-core` defines the port traits: `Database`, `Mailer`, `Captcha`,
`RateLimiter`, `Signer`, `KeyValue`, `HttpClient`, `Clock`, `IdGen`, `Defer`.
All are `Send + Sync` and object-safe (`Arc<dyn Trait>`). Modules declare which
ports they `requires()` and which are `optional()`; `Harness::build()` fails
when a required port is not provided.

Each adapter is its own crate. On Workers the JS handles (`D1Database`,
`KvStore`, `Fetch`) are `!Send`; the Cloudflare adapters wrap them in
`worker::send::SendWrapper`. This is sound because a Workers isolate executes
on a single thread; it is the one place `unsafe`-adjacent code is allowed.

## Consequences
- A venture compiles only the adapters it lists (Cargo features on the runtime crate).
- Tests run modules against fakes from `cratefield-testing` and the `rusqlite` adapter; no Cloudflare needed.
- Every new vendor integration is an adapter crate, never an `if let Some(binding)` inside a module.
