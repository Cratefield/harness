# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.2.1](https://github.com/Cratefield/harness/compare/cratefield-v0.2.0...cratefield-v0.2.1) - 2026-10-09

### Added

- *(module-owlpost)* verified Owlpost event receiver with typed inbound mail and delivery events ([#673](https://github.com/Cratefield/harness/pull/673)) ([#853](https://github.com/Cratefield/harness/pull/853))
- *(text-guard)* protect links, hashtags and caller-supplied spans ([#836](https://github.com/Cratefield/harness/pull/836)) ([#851](https://github.com/Cratefield/harness/pull/851))
- *(text-guard)* keep names, numbers, quotes and code across a model rewrite, and a word diff that keeps them whole ([#836](https://github.com/Cratefield/harness/pull/836)) ([#837](https://github.com/Cratefield/harness/pull/837))

### Other

- Linear adapter (`cratefield-adapter-linear`) with comment and inbound status webhook (#559, part 2) ([#850](https://github.com/Cratefield/harness/pull/850))
- link EVM and Solana wallets to a signed-in account via SIWE/SIWS (plus a push-protection fix) ([#838](https://github.com/Cratefield/harness/pull/838))

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
