# Factory Zero auth service — architecture

Status: v1, adopted 2026-09-06. Built on the [harness](https://github.com/Factory-Zero/harness); its ADRs 0001 to 0008 apply here unchanged. Decisions specific to this service go in [docs/adr](adr).

## What this is

One authentication service, `auth.factory0.ventures`, that every venture backend delegates to. Six login methods resolve to one session: passkeys, Google, Apple, Meta, email and password, magic links. Consuming apps are registered clients with their own id, secret and exact redirect URIs. They receive tokens they can verify locally with a thin client crate.

## How it fits the harness

The service is a *consumer* of the harness, not a change to it. It is a venture-shaped backend in the sense of ADR 0003: one Worker, one D1 database, its own secrets, its own domain. Its features are harness modules (`auth-core`, `auth-passkeys`, `auth-oidc`, `auth-apple`, `auth-meta`, `auth-password`, `auth-magic-link`) that see only ports. Every port it needs already exists: `Database` for users, sessions and single-use tokens; `KeyValue` for nothing that must be single-use (see below); `HttpClient` for provider token exchanges and the Graph API; `Mailer` for magic links; `RateLimiter` and `Captcha` for the password and magic-link endpoints; `Signer` for short-lived HMAC state; `Clock` and `IdGen`. Multi-app support is the `clients` table and an OAuth 2.1 authorization-code flow with PKCE, because consuming apps live on other domains (undercoverrockstars.com, kontinuum.audio) and a cookie on `auth.factory0.ventures` cannot reach them. The venture backends then verify tokens with `factory0-auth-client`.

## What the harness must gain first

Two small things, filed in the harness repo as one issue: modules can currently only mount under `/v1/<name>`, and this service must publish `/.well-known/jwks.json` and `/.well-known/openid-configuration` at the root; and axum's form extractor is not enabled in the core, which Apple's `form_post` callback requires.

## Validated before writing this

`webauthn-rs` 0.5.5 has OpenSSL as a hard dependency through `webauthn-rs-core` and `webauthn-attestation-ca`, with no feature to turn it off, so it does not compile for `wasm32-unknown-unknown`. `openidconnect` 4, `oauth2` 5 and `argon2` 0.6 all build to wasm32 with default features off and no OpenSSL or reqwest in the tree. The passkey spike therefore starts from a known failure and evaluates the alternatives. Two more facts shape the schema: Cloudflare KV is eventually consistent, so anything that must be single-use (magic-link tokens, WebAuthn challenges, authorization codes) lives in D1 with delete-on-use, never in KV; and argon2 on Workers is CPU-bound in wasm, so its parameters are measured, not assumed.

## Deferred

Enterprise SAML SSO is out of scope for this epic and has no issues. When a venture needs it, it becomes a separate epic on top of the same session and client model.

## Order

Spikes first; then schema, client registration, sessions, tokens and the authorization flow; then the client crate and rate limiting; then each login method; account linking last because it depends on every provider's identity shape.
