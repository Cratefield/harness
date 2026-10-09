<p align="center">
  <a href="https://github.com/Cratefield/harness">
    <img src="https://raw.githubusercontent.com/Cratefield/harness/main/assets/banners/cratefield.png" alt="cratefield — One dependency." width="100%">
  </a>
</p>

<p align="center">
  <a href="https://crates.io/crates/cratefield"><img src="https://img.shields.io/crates/v/cratefield.svg?style=flat-square&labelColor=0A0A0B&color=4C6FFF" alt="cratefield on crates.io"></a>
  <a href="https://docs.rs/cratefield"><img src="https://img.shields.io/docsrs/cratefield?style=flat-square&labelColor=0A0A0B&color=EDEBE6" alt="cratefield documentation"></a>
  <a href="https://github.com/Cratefield/harness/blob/main/LICENSE"><img src="https://img.shields.io/badge/LICENSE-MIT-4C6FFF?style=flat-square&labelColor=0A0A0B" alt="MIT"></a>
</p>

# `cratefield`

The Cratefield harness as one dependency.

A venture needs a core, a runtime, one or more adapters and its modules —
six crates for the smallest useful backend, each with a version that has to
agree with the others. This crate is that set behind one name and one
version.

```toml
[dependencies]
cratefield = { version = "0.1", features = ["cloudflare", "resend", "waitlist"] }
```

It adds no code of its own. Everything here is a re-export, so
`cratefield::Harness` and `cratefield_core::Harness` are the same type, and
a venture can drop down to the individual crates at any point without
rewriting anything.

## What you get

`cratefield-core` is re-exported at the root, so the builder, the `Module`
trait and the port traits are simply `cratefield::*`. Everything else is a
feature. Each feature enables one crate; `push-wiring` and `notifications`
also switch on the extra features noted in their rows:

| Feature | Crate | Reached as | What it is |
|---|---|---|---|
| `cloudflare` | `cratefield-runtime-cloudflare` | `cratefield::cloudflare` | Workers entry points; D1, KV and rate limiting as ports |
| `native` | `cratefield-runtime-native` | `cratefield::native` | The same harness as one tokio binary |
| `sqlite` | `cratefield-adapter-sqlite` | `cratefield::sqlite` | `Database` over rusqlite |
| `postgres` | `cratefield-adapter-postgres` | `cratefield::postgres` | `Database` over sqlx |
| `resend` | `cratefield-adapter-resend` | `cratefield::resend` | `Mailer` over the Resend API |
| `owlpost` | `cratefield-adapter-owlpost` | `cratefield::owlpost` | `Mailer` over the Resend-compatible Owlpost API |
| `telegram` | `cratefield-adapter-telegram` | `cratefield::telegram` | `TelegramBot` over the Bot API: verified webhook updates, sends under global and per-chat rate budgets, a token that never rides a log line |
| `colonizer` | `cratefield-adapter-colonizer` | `cratefield::colonizer` | An HTTP client for the Colonizer mothership: open a colony, ask, answer, stop and resume, via the `HttpClient` port |
| `turnstile` | `cratefield-adapter-turnstile` | `cratefield::turnstile` | `Captcha` over Cloudflare Turnstile |
| `anthropic` | `cratefield-adapter-anthropic` | `cratefield::anthropic` | `TextModel` over the Anthropic Messages API, via the `HttpClient` port |
| `openai-compatible` | `cratefield-adapter-openai-compatible` | `cratefield::openai_compatible` | `TextModel` over the `OpenAI` chat-completions wire at any base URL, via the `HttpClient` port |
| `cloudflare-saas` | `cratefield-adapter-cloudflare-saas` | `cratefield::cloudflare_saas` | `CustomHostnames` over Cloudflare for `SaaS` custom hostnames, via the `HttpClient` port |
| `stripe` | `cratefield-adapter-stripe` | `cratefield::stripe` | `Payments` over the Stripe API |
| `polar` | `cratefield-adapter-polar` | `cratefield::polar` | `Payments` over Polar, a Merchant of Record: checkout, usage meters, portal, refunds and disputes |
| `apns` | `cratefield-adapter-apns` | `cratefield::apns` | `Push` over Apple Push Notification service |
| `fcm` | `cratefield-adapter-fcm` | `cratefield::fcm` | `Push` over Firebase Cloud Messaging (HTTP v1) |
| `webpush` | `cratefield-adapter-webpush` | `cratefield::webpush` | `Push` over Web Push (RFC 8030), browsers and UnifiedPush |
| `push-auth` | `cratefield-push-auth` | `cratefield::push_auth` | Provider-JWT signing for the push adapters (ES256 for APNs and VAPID, RS256 for Google service accounts) with a keyed token cache. Pulled in by `apns`, `fcm` and `webpush` already; a feature of its own for using it directly |
| `github-app` | `cratefield-adapter-github-app` | `cratefield::github_app` | GitHub App auth: the RS256 app JWT, installation tokens (cached, single-flight, one re-mint on `401`) and the user-to-server OAuth code exchange, over the `HttpClient` and `Clock` ports. Builds on `push-auth`'s signer and token cache |
| `push-wiring` | `cratefield-push-wiring` | `cratefield::push_wiring` | Assembles the `Push` port from the environment, with the one table of variable names that `serve()`, `fz push` and `fz doctor` share. Pulls all three push adapters, and also turns on `push` in whichever runtime is enabled, for `push_from_env()` |
| `github-issues` | `cratefield-adapter-github-issues` | `cratefield::github_issues` | `Tracker` over the GitHub Issues REST API |
| `webhook-tracker` | `cratefield-adapter-webhook-tracker` | `cratefield::webhook_tracker` | `Tracker` over an HMAC-signed webhook the tenant configures |
| `jira` | `cratefield-adapter-jira` | `cratefield::jira` | `Tracker` over the Jira Cloud REST API v3 (Basic auth over `email:api_token`, ADF bodies, and the inbound status webhook) |
| `linear` | `cratefield-adapter-linear` | `cratefield::linear` | `Tracker` over the Linear GraphQL API (a personal API key or an OAuth token, Markdown bodies, and the inbound status webhook) |
| `typesafe` | `cratefield-adapter-typesafe` | `cratefield::typesafe` | `Classifier` over the operator's own `TypeSafe` API key, via the `HttpClient` port |
| `classifier-llm` | `cratefield-adapter-classifier-llm` | `cratefield::classifier_llm` | `Classifier` over the `TextModel` port, JSON-schema output, no new vendor |
| `ui` | `cratefield-ui` | `cratefield::ui` | Renders the module surface as HTML |
| `i18n` | `cratefield-i18n` | `cratefield::i18n` | Server-side localisation: Fluent catalogs, BCP 47 negotiation and text direction. Pulled in by `notifications` already; a feature of its own for localising a venture's own strings |
| `text-guard` | `cratefield-text-guard` | `cratefield::text_guard` | Keeps the facts across a model rewrite: finds the names, numbers, quotes, code, links and hashtags (plus caller-supplied spans) a rewrite must not change, and lists every one it dropped or altered |
| `text-diff` | `cratefield-text-diff` | `cratefield::text_diff` | Word-level diff in which protected ranges stay whole and come back as locked |
| `secrets` | `cratefield-secrets` | `cratefield::secrets` | Envelope-encrypted secrets |
| `kms` | `cratefield-kms` | `cratefield::kms` | The KMS port and its local-file provider |
| `manifest` | `cratefield-manifest` | `cratefield::manifest` | The venture manifest and its composition generator; `fz` reads it, a running venture does not need it |
| `client-ts` | `cratefield-client-ts` | `cratefield::client_ts` | The TypeScript client generator behind `fz client-ts`: a `/__surface` document in, a typed client package out |
| `introspect` | `cratefield-introspect` | `cratefield::introspect` | Reads a live database's catalog over the Database port, in `cratefield-tables`' schema vocabulary |
| `import-supabase` | `cratefield-import-supabase` | `cratefield::import_supabase` | Inspects a Supabase project read-only and writes the migration report (ADR 0026); native only |
| `tables-api` | `cratefield-tables-api` | `cratefield::tables_api` | The HTTP API over a venture's declared tables; `fz build` turns it on for a manifest with a `[tables]` section |
| `auth-client` | `cratefield-auth-client` | `cratefield::auth_client` | Verifies auth-service tokens: JWKS fetch and cache, ES256 verification and an axum extractor |
| `oauth-client` | `cratefield-oauth-client` | `cratefield::oauth_client` | OAuth 2.0 over the `HttpClient` port: authorize URLs, code exchange, refresh, revocation, PKCE, and token sealing |
| `mail-templates` | `cratefield-mail-templates` | `cratefield::mail_templates` | Branded, email-client-safe HTML and text mail in the venture's `MailTheme`; turned on by every module that sends mail |
| `email-signup` | `cratefield-module-email-signup` | `cratefield::email_signup` | Double opt-in email signup |
| `privacy` | `cratefield-module-privacy` | `cratefield::privacy` | Subject access and erasure, over what every other module declares it holds |
| `waitlist` | `cratefield-module-waitlist` | `cratefield::waitlist` | Per-product waitlist |
| `cms` | `cratefield-module-cms` | `cratefield::cms` | Small content store |
| `crm` | `cratefield-module-crm` | `cratefield::crm` | Contacts, organisations and tags, filed idempotently by natural key |
| `changelog` | `cratefield-module-changelog` | `cratefield::changelog` | A project's releases, mirrored into your own database |
| `notifications` | `cratefield-module-notifications` | `cratefield::notifications` | Push subscriptions, per-account per-category preferences, fan-out, prune and retry. Also turns on `i18n` |
| `telemetry` | `cratefield-module-telemetry` | `cratefield::telemetry` | Aggregate usage counts from clients, consent-first, in the venture's own database |
| `webhooks` | `cratefield-module-webhooks` | `cratefield::webhooks` | Outbound webhooks: per-subject signed POSTs over the core outbox, with dead letters and replay |
| `device-auth` | `cratefield-module-device-auth` | `cratefield::device_auth` | The OAuth 2.0 device authorization grant (RFC 8628): a client with no browser shows a code, a signed-in person approves it, and the venture's issuer mints the credential |
| `orgs` | `cratefield-module-orgs` | `cratefield::orgs` | Organizations, memberships, roles and email invitations: a person creates an organization and is its owner, invites people by address, and everyone who belongs holds a role the venture configured |
| `connections` | `cratefield-module-connections` | `cratefield::connections` | Per-subject third-party OAuth connections: authorize, sealed access and refresh tokens, guarded refresh, revoke, over the `HttpClient` port |
| `wallets` | `cratefield-module-wallets` | `cratefield::wallets` | Links a person's own crypto wallet (EVM or Solana) to an account they have already signed in to, by verifying an EIP-4361 (SIWE) or SIWS signature over a single-use nonce bound to their account. Reads an address and proves ownership of it; never asks a wallet to move funds |
| `guardrails` | `cratefield-module-guardrails` | `cratefield::guardrails` | The policy engine every automated value-moving action must pass: hard denies, allowlists, required simulation, micro-USD caps, a kill switch and audit. Default deny, fail closed |
| `owlpost-events` | `cratefield-module-owlpost` | `cratefield::owlpost_events` | Owlpost's signed inbound webhooks as harness events: verified `POST /v1/owlpost/events`, deduplicated per delivery, with a venture hook per inbound mail. The plain `owlpost` feature is the sending adapter |
| `telegram-events` | `cratefield-module-telegram` | `cratefield::telegram_events` | Telegram in the harness: the secret-token webhook, account linking and consent buttons that never move value without a passkey. The plain `telegram` feature is the sending adapter |
| `testing` | `cratefield-testing` | `cratefield::testing` | The conformance kit; belongs under `[dev-dependencies]` |

The third classifier adapter, `cratefield-adapter-workers-ai`, has no
feature here on purpose: it needs the Workers `env.AI` binding (and the
`worker` crate), so a venture on Workers depends on it directly — the same
way it depends on the `cloudflare` runtime — and no native venture pulls
`worker` through this crate.

There is no default feature. A runtime is a decision, not a default, and an
empty default is what keeps `tokio` and `sqlx` out of a Workers build
(ADR 0001).

The `fz` binary is not here. Install it separately with
`cargo install cratefield-cli`.

## On Workers

Three features cannot go to `wasm32-unknown-unknown`, because of what they
depend on rather than anything this crate does: `native` (tokio), `postgres`
(sqlx) and `sqlite` (rusqlite compiles C). On Workers the database is D1,
which arrives through `cloudflare`, so none of the three is what you want
there anyway.

Everything else builds for wasm — but **your** crate has to turn on
`getrandom`'s wasm backend, because only the final artifact can pick it.
Without this, the build fails inside `getrandom` with nothing in the error
mentioning Cratefield:

```toml
[target.'cfg(target_arch = "wasm32")'.dependencies]
getrandom = { version = "0.4", features = ["wasm_js"] }
```

`examples/venture` in the repository is a working Workers venture built on
this crate, and CI boots it under `wrangler dev` on every push.

## Versions

The point of depending on this crate rather than the parts is that the set
is chosen for you: one `cratefield` version pins a combination that is built
and tested together. `docs/COMPATIBILITY.md` in the repository lists what
each release resolves to.

---

MIT. Built in the open for [Cratefield](https://cratefield.com), a [Factory Zero](https://factory0.ventures) venture.
