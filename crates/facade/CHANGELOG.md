# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.2.2](https://github.com/Cratefield/harness/compare/cratefield-v0.2.1...cratefield-v0.2.2) - 2026-10-19

### Other

- updated the following local packages: cratefield-core, cratefield-testing, cratefield-runtime-native, cratefield-runtime-cloudflare, cratefield-adapter-anthropic, cratefield-adapter-sqlite, cratefield-adapter-postgres, cratefield-mail-templates, cratefield-module-email-signup, cratefield-module-privacy, cratefield-module-waitlist, cratefield-push-auth, cratefield-adapter-apns, cratefield-adapter-classifier-llm, cratefield-adapter-cloudflare-saas, cratefield-adapter-colonizer, cratefield-adapter-fcm, cratefield-adapter-github-app, cratefield-adapter-github-issues, cratefield-adapter-jira, cratefield-adapter-linear, cratefield-adapter-openai-compatible, cratefield-adapter-owlpost, cratefield-adapter-polar, cratefield-adapter-stripe, cratefield-adapter-resend, cratefield-adapter-telegram, cratefield-secrets, cratefield-adapter-turnkey, cratefield-adapter-turnstile, cratefield-adapter-typesafe, cratefield-adapter-webhook-tracker, cratefield-adapter-webpush, cratefield-auth-client, cratefield-push-wiring, cratefield-oauth-client, cratefield-module-device-auth, cratefield-client-ts, cratefield-import-supabase, cratefield-introspect, cratefield-ui, cratefield-module-changelog, cratefield-module-cms, cratefield-module-crm, cratefield-module-notifications, cratefield-module-orgs, cratefield-module-telemetry, cratefield-module-connections, cratefield-module-guardrails, cratefield-module-owlpost, cratefield-module-sealed, cratefield-module-telegram, cratefield-module-wallets, cratefield-module-webhooks, cratefield-tables-api

## [0.2.1](https://github.com/Cratefield/harness/compare/cratefield-v0.2.0...cratefield-v0.2.1) - 2026-10-15

### Added

- *(module-owlpost)* verified Owlpost event receiver with typed inbound mail and delivery events ([#673](https://github.com/Cratefield/harness/pull/673)) ([#853](https://github.com/Cratefield/harness/pull/853))
- *(text-guard)* protect links, hashtags and caller-supplied spans ([#836](https://github.com/Cratefield/harness/pull/836)) ([#851](https://github.com/Cratefield/harness/pull/851))
- *(text-guard)* keep names, numbers, quotes and code across a model rewrite, and a word diff that keeps them whole ([#836](https://github.com/Cratefield/harness/pull/836)) ([#837](https://github.com/Cratefield/harness/pull/837))

### Other

- module-sealed + @cratefield/sealed: zero-knowledge sealed blobs (passkey PRF + recovery-code wraps, server outer wrap, no server recovery) ([#757](https://github.com/Cratefield/harness/pull/757)) ([#867](https://github.com/Cratefield/harness/pull/867))
- Signer port: sign by key reference via Turnkey delegated access or Secrets-held session keys, guarded and audit-chained ([#761](https://github.com/Cratefield/harness/pull/761)) ([#865](https://github.com/Cratefield/harness/pull/865))
- adapter-telegram + module-telegram: verified bot webhook, account linking, rate-limited messages, signed action buttons and a notifications channel ([#764](https://github.com/Cratefield/harness/pull/764)) ([#864](https://github.com/Cratefield/harness/pull/864))
- allowlists, caps, required simulation, hard denies and a kill switch for value-moving actions ([#763](https://github.com/Cratefield/harness/pull/763)) ([#862](https://github.com/Cratefield/harness/pull/862))
- Linear adapter (`cratefield-adapter-linear`) with comment and inbound status webhook (#559, part 2) ([#850](https://github.com/Cratefield/harness/pull/850))
- link EVM and Solana wallets to a signed-in account via SIWE/SIWS (plus a push-protection fix) ([#838](https://github.com/Cratefield/harness/pull/838))

### Added

- *(telegram)* a `telegram` feature that re-exports `cratefield-adapter-telegram` as `cratefield::telegram`, and a `telegram-events` feature that re-exports `cratefield-module-telegram` as `cratefield::telegram_events`: the Telegram Bot API adapter and the webhook, account-linking and consent-button module ([#764](https://github.com/Cratefield/harness/issues/764))
- *(sealed)* a `sealed` feature that re-exports `cratefield-module-sealed` as `cratefield::sealed`: the server half of client-side sealed blobs, with opaque ciphertext at rest, crypto-shred erasure and no server-side recovery ([#757](https://github.com/Cratefield/harness/issues/757))
- *(guardrails)* a `guardrails` feature that re-exports `cratefield-module-guardrails` as `cratefield::guardrails`: the policy engine every automated value-moving action must pass ([#763](https://github.com/Cratefield/harness/issues/763))
- *(signer)* a `signer` feature that re-exports `cratefield-signer` as `cratefield::signer`: signing by key reference behind guardrails and an audit chain, with session keys held in the Secrets store ([#761](https://github.com/Cratefield/harness/issues/761))
- *(turnkey)* a `turnkey` feature that re-exports `cratefield-adapter-turnkey` as `cratefield::turnkey`: the signer port's Turnkey provider, delegated access under policy ([#761](https://github.com/Cratefield/harness/issues/761))

## [0.2.0](https://github.com/Cratefield/harness/compare/cratefield-v0.1.4...cratefield-v0.2.0) - 2026-10-03

### Added

- *(webhooks)* outbound webhook delivery module with per-endpoint secrets, retries, dead letters and replay ([#536](https://github.com/Cratefield/harness/pull/536)) ([#544](https://github.com/Cratefield/harness/pull/544))
- *(oauth-client)* reusable OAuth 2.0 client crate, with module-linkedin ported onto it ([#531](https://github.com/Cratefield/harness/pull/531)) ([#547](https://github.com/Cratefield/harness/pull/547))
- *(adapter-anthropic)* the first TextModel adapter, over the HttpClient port ([#430](https://github.com/Cratefield/harness/pull/430)) ([#481](https://github.com/Cratefield/harness/pull/481))
- *(changelog)* a module that mirrors a repository's releases and serves them ([#418](https://github.com/Cratefield/harness/pull/418))
- *(manifest)* a declared table becomes a module the venture composes ([#153](https://github.com/Cratefield/harness/pull/153)) ([#358](https://github.com/Cratefield/harness/pull/358))

### Other

- App JWTs, cached installation tokens, and a named GitHub webhook scheme ([#623](https://github.com/Cratefield/harness/pull/623)) ([#637](https://github.com/Cratefield/harness/pull/637))
- per-account third-party OAuth connections with sealed tokens, refresh and revoke ([#624](https://github.com/Cratefield/harness/pull/624)) ([#638](https://github.com/Cratefield/harness/pull/638))
- OAuth 2.0 device authorization grant (RFC 8628) issuing a venture-defined credential ([#587](https://github.com/Cratefield/harness/pull/587)) ([#633](https://github.com/Cratefield/harness/pull/633))
- CustomHostnames port in core, with a Cloudflare for SaaS adapter ([#590](https://github.com/Cratefield/harness/pull/590)) ([#630](https://github.com/Cratefield/harness/pull/630))
- a Mailer over the Owlpost API ([#591](https://github.com/Cratefield/harness/pull/591)) ([#629](https://github.com/Cratefield/harness/pull/629))
- comment op, inbound status webhooks, Freshdesk destination and the Jira Cloud adapter (#559, part 1) ([#582](https://github.com/Cratefield/harness/pull/582))
- OpenAI-compatible adapter, cached-token usage on every completion, shared TextModel conformance suite ([#560](https://github.com/Cratefield/harness/pull/560)) ([#567](https://github.com/Cratefield/harness/pull/567))
- cratefield-core 0.6.0 and every publishable dependent ([#558](https://github.com/Cratefield/harness/pull/558)) ([#565](https://github.com/Cratefield/harness/pull/565))
- Drop the Cargo.toml comments that still say published crates are `publish = false` ([#495](https://github.com/Cratefield/harness/pull/495)) ([#548](https://github.com/Cratefield/harness/pull/548))
- Remove the space runs from the Signer readiness message, and make the facade crate doc match NOT_LIBRARIES ([#527](https://github.com/Cratefield/harness/pull/527))
- Stop holding back cratefield-tables in release-plz.toml now that it is on crates.io ([#513](https://github.com/Cratefield/harness/pull/513))
- Docs accuracy: free-tier module copy, facade feature table, privacy erasure docs, cooldown declaration, removal consent flag ([#509](https://github.com/Cratefield/harness/pull/509))
- Classifier port, with your own TypeSafe key, Workers AI, or the LLM you already have ([#501](https://github.com/Cratefield/harness/pull/501))
- adapter-github-issues and adapter-webhook-tracker: the first two Tracker adapters ([#482](https://github.com/Cratefield/harness/pull/482))
- Release round: bump the 23 core dependents so their next publish requires core ^0.5 ([#496](https://github.com/Cratefield/harness/pull/496))
- anonymous usage telemetry any venture can compose, opt-out ([#471](https://github.com/Cratefield/harness/pull/471))
- The generated module serves the tables it declares ([#370](https://github.com/Cratefield/harness/pull/370))
