# The auth service — architecture

Status: v1, adopted 2026-09-06; deployment model revised 2026-10-05 (issue #777: one branded instance per app). Built on the [harness](https://github.com/Cratefield/harness); its ADRs 0001 to 0008 apply here unchanged. Decisions specific to this service are the 0200 block in [docs/adr](../adr).

## What this is

One authentication service, deployed **once per app** on the app's own domain (`auth.<app-domain>`), that the app's backends delegate to. An instance is either self-hosted by the app's team or operated by Cratefield on the app's domain; the code, the Worker and the deploy are the same, and everything that makes an instance somebody's (origin, issuer, passkey RP ID, cookies, sender, branding, D1, secrets) is configuration in `instances/<app>/wrangler.toml`. Six login methods resolve to one session: passkeys, Google, Apple, Meta, email and password, magic links. Consuming apps are registered clients of their instance with their own id, secret and exact redirect URIs. They receive tokens they can verify locally with a thin client crate.

The service was first designed as one shared instance for every venture. It was never deployed in that shape; the per-instance model replaced it before any user, passkey or client existed, so there was nothing to migrate. One instance per app means a passkey, a session cookie and an issuer each belong to exactly one app, a login page never shows another app's name, and an outage or a compromised secret stays inside one app.

## How it fits the harness

The service is a *consumer* of the harness, not a change to it. It is a venture-shaped backend in the sense of ADR 0003: one Worker, one D1 database, its own secrets, its own domain. Its features are harness modules (`auth-core`, `auth-passkeys`, `auth-oidc` for Google and Apple, `auth-meta`, `auth-password`, `auth-magic-link`) that see only ports. Every port it needs already exists: `Database` for users, sessions and single-use tokens; `KeyValue` for nothing that must be single-use (see below); `HttpClient` for provider token exchanges and the Graph API; `Mailer` for magic-link and password mail (Owlpost by default, Resend as an option); `RateLimiter` and `Captcha` for the password and magic-link endpoints; `Signer` for short-lived HMAC state; `Clock` and `IdGen`. Within one instance, client support is the `clients` table and an OAuth 2.1 authorization-code flow with PKCE, because an app's frontends and backends live on other hosts than `auth.<app-domain>` and a host-locked cookie there cannot reach them. The app's backends then verify tokens with `cratefield-auth-client` against their instance's issuer.

## What the harness had to gain first

Historical (both landed). Two small things, filed in the harness repo as one issue: modules can currently only mount under `/v1/<name>`, and this service must publish `/.well-known/jwks.json` and `/.well-known/openid-configuration` at the root; and axum's form extractor is not enabled in the core, which Apple's `form_post` callback requires.

## Validated before writing this

`webauthn-rs` 0.5.5 has OpenSSL as a hard dependency through `webauthn-rs-core` and `webauthn-attestation-ca`, with no feature to turn it off, so it does not compile for `wasm32-unknown-unknown`. `openidconnect` 4, `oauth2` 5 and `argon2` 0.6 all build to wasm32 with default features off and no OpenSSL or reqwest in the tree. The passkey spike therefore starts from a known failure and evaluates the alternatives. Two more facts shape the schema: Cloudflare KV is eventually consistent, so anything that must be single-use (magic-link tokens, WebAuthn challenges, authorization codes) lives in D1 with delete-on-use, never in KV; and argon2 on Workers is CPU-bound in wasm, so its parameters are measured, not assumed.

## Deferred

Enterprise SAML SSO is out of scope for this epic and has no issues. When a venture needs it, it becomes a separate epic on top of the same session and client model. Per-organization enterprise SSO over OpenID Connect is implemented (issue #627): a connection is one organization's `IdP`, owned by a client, and a sign-in through it marks the session and the access token. See [SSO.md](SSO.md).

## Order

Historical, the order the work was done in: spikes first; then schema, client registration, sessions, tokens and the authorization flow; then the client crate and rate limiting; then each login method; account linking last because it depends on every provider's identity shape.
