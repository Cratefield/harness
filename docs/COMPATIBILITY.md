# Compatibility

Generated from the workspace manifests by `cargo run -p cratefield-cli --example
compatibility-doc` and checked in CI for drift. Do not edit by hand.

## The contract version

- `HARNESS_API` is 1. Every module and adapter is compiled
  against a `cratefield-core` whose `HARNESS_API` matches; `Harness::build`
  and `fz doctor` refuse a mismatch, naming the module, its version and
  the core crate.
- **The 1.0 rule:** `HARNESS_API` is bumped only for breaking changes to
  the module contract (the `Module` trait, `ModuleContext`, ports).
  `cratefield-core`'s major version follows `HARNESS_API`: a core 2.x is
  the first that accepts API 2, a core 1.x never does. Anything else —
  new optional trait methods, new ports, new error slugs — ships in a
  minor bump with the API unchanged.
- **Dependency ranges:** while pre-1.0, modules and adapters depend on
  `cratefield-core` with a caret on the current minor (`"0.1"` accepts
  0.1.x only), so a new core minor can never silently mix with older
  modules. From 1.0 the range is `"^1"`-style: compatible within the
  major. Ventures pin exact versions; the supported range per release
  is the table below.
- **Problem `type` URIs (cratefield-core 0.7.0):** every venture now
  names its problem types under its own base —
  `<public_url>/problems/<slug>`, `about:blank` when it has no public
  URL — instead of one fixed base. Clients must match on the slug,
  the part after `/problems/` (`auth/…` namespaces included), never
  on the full URI: the URI names whichever venture served the
  answer. docs/ERRORS.md is the slug list. Every other
  source-breaking change since 0.5.0, per minor, is in
  docs/UPGRADING.md.

## Supported core ranges

| Crate | Version | HARNESS_API | `cratefield-core` range |
|---|---|---|---|
| `cratefield` | 0.2.0 | 1 | `^0.8` — `>=0.8.0, <0.9.0` |
| `cratefield-access` *(not published)* | 0.1.1 | 1 | `^0.8` — `>=0.8.0, <0.9.0` |
| `cratefield-accounts` *(not published)* | 0.1.1 | 1 | `^0.8` — `>=0.8.0, <0.9.0` |
| `cratefield-adapter-anthropic` | 0.3.1 | 1 | `^0.8` — `>=0.8.0, <0.9.0` |
| `cratefield-adapter-apns` | 0.3.0 | 1 | `^0.8` — `>=0.8.0, <0.9.0` |
| `cratefield-adapter-classifier-llm` | 0.3.0 | 1 | `^0.8` — `>=0.8.0, <0.9.0` |
| `cratefield-adapter-cloudflare-saas` | 0.2.0 | 1 | `^0.8` — `>=0.8.0, <0.9.0` |
| `cratefield-adapter-colonizer` | 0.1.0 | 1 | `^0.8` — `>=0.8.0, <0.9.0` |
| `cratefield-adapter-fcm` | 0.3.0 | 1 | `^0.8` — `>=0.8.0, <0.9.0` |
| `cratefield-adapter-github-app` | 0.2.0 | 1 | `^0.8` — `>=0.8.0, <0.9.0` |
| `cratefield-adapter-github-issues` | 0.3.1 | 1 | `^0.8` — `>=0.8.0, <0.9.0` |
| `cratefield-adapter-jira` | 0.2.1 | 1 | `^0.8` — `>=0.8.0, <0.9.0` |
| `cratefield-adapter-linear` | 0.1.0 | 1 | `^0.8` — `>=0.8.0, <0.9.0` |
| `cratefield-adapter-openai-compatible` | 0.2.1 | 1 | `^0.8` — `>=0.8.0, <0.9.0` |
| `cratefield-adapter-owlpost` | 0.2.1 | 1 | `^0.8` — `>=0.8.0, <0.9.0` |
| `cratefield-adapter-polar` | 0.2.1 | 1 | `^0.8` — `>=0.8.0, <0.9.0` |
| `cratefield-adapter-postgres` | 0.3.1 | 1 | `^0.8` — `>=0.8.0, <0.9.0` |
| `cratefield-adapter-resend` | 0.4.1 | 1 | `^0.8` — `>=0.8.0, <0.9.0` |
| `cratefield-adapter-sqlite` | 0.3.0 | 1 | `^0.8` — `>=0.8.0, <0.9.0` |
| `cratefield-adapter-sqlite-wasm` *(not published)* | 0.1.1 | 1 | `^0.8` — `>=0.8.0, <0.9.0` |
| `cratefield-adapter-stripe` | 0.3.2 | 1 | `^0.8` — `>=0.8.0, <0.9.0` |
| `cratefield-adapter-telegram` | 0.1.0 | 1 | `^0.8` — `>=0.8.0, <0.9.0` |
| `cratefield-adapter-turnkey` | 0.1.0 | 1 | `^0.8` — `>=0.8.0, <0.9.0` |
| `cratefield-adapter-turnstile` | 0.3.1 | 1 | `^0.8` — `>=0.8.0, <0.9.0` |
| `cratefield-adapter-typesafe` | 0.3.0 | 1 | `^0.8` — `>=0.8.0, <0.9.0` |
| `cratefield-adapter-webhook-tracker` | 0.3.0 | 1 | `^0.8` — `>=0.8.0, <0.9.0` |
| `cratefield-adapter-webpush` | 0.3.0 | 1 | `^0.8` — `>=0.8.0, <0.9.0` |
| `cratefield-adapter-workers-ai` | 0.3.0 | 1 | `^0.8` — `>=0.8.0, <0.9.0` |
| `cratefield-auth-client` | 0.3.2 | 1 | `^0.8` — `>=0.8.0, <0.9.0` |
| `cratefield-auth-core` *(not published)* | 0.1.1 | 1 | `^0.8` — `>=0.8.0, <0.9.0` |
| `cratefield-auth-magic-link` *(not published)* | 0.1.1 | 1 | `^0.8` — `>=0.8.0, <0.9.0` |
| `cratefield-auth-meta` *(not published)* | 0.1.1 | 1 | `^0.8` — `>=0.8.0, <0.9.0` |
| `cratefield-auth-oidc` *(not published)* | 0.1.1 | 1 | `^0.8` — `>=0.8.0, <0.9.0` |
| `cratefield-auth-passkeys` *(not published)* | 0.1.1 | 1 | `^0.8` — `>=0.8.0, <0.9.0` |
| `cratefield-auth-password` *(not published)* | 0.1.1 | 1 | `^0.8` — `>=0.8.0, <0.9.0` |
| `cratefield-auth-worker` *(not published)* | 0.1.1 | 1 | `^0.8` — `>=0.8.0, <0.9.0` |
| `cratefield-bench-write-ceiling` *(not published)* | 0.1.1 | 1 | `^0.8` — `>=0.8.0, <0.9.0` |
| `cratefield-chrome` *(not published)* | 0.1.1 | 1 | `^0.8` — `>=0.8.0, <0.9.0` |
| `cratefield-cli` | 0.6.2 | 1 | `^0.8` — `>=0.8.0, <0.9.0` |
| `cratefield-client-ts` | 0.4.1 | 1 | `^0.8` — `>=0.8.0, <0.9.0` |
| `cratefield-connections` *(not published)* | 0.1.1 | 1 | `^0.8` — `>=0.8.0, <0.9.0` |
| `cratefield-console` *(not published)* | 0.1.1 | 1 | `^0.8` — `>=0.8.0, <0.9.0` |
| `cratefield-control-plane` *(not published)* | 0.1.1 | 1 | `^0.8` — `>=0.8.0, <0.9.0` |
| `cratefield-dashboard` *(not published)* | 0.1.1 | 1 | `^0.8` — `>=0.8.0, <0.9.0` |
| `cratefield-import-supabase` | 0.2.0 | 1 | `^0.8` — `>=0.8.0, <0.9.0` |
| `cratefield-introspect` | 0.3.0 | 1 | `^0.8` — `>=0.8.0, <0.9.0` |
| `cratefield-mail-previews` *(not published)* | 0.1.1 | 1 | `^0.8` — `>=0.8.0, <0.9.0` |
| `cratefield-mail-templates` | 0.1.1 | 1 | `^0.8` — `>=0.8.0, <0.9.0` |
| `cratefield-module-changelog` | 0.3.1 | 1 | `^0.8` — `>=0.8.0, <0.9.0` |
| `cratefield-module-cms` | 0.3.0 | 1 | `^0.8` — `>=0.8.0, <0.9.0` |
| `cratefield-module-connections` | 0.2.1 | 1 | `^0.8` — `>=0.8.0, <0.9.0` |
| `cratefield-module-crm` | 0.1.0 | 1 | `^0.8` — `>=0.8.0, <0.9.0` |
| `cratefield-module-device-auth` | 0.3.0 | 1 | `^0.8` — `>=0.8.0, <0.9.0` |
| `cratefield-module-email-signup` | 0.4.0 | 1 | `^0.8` — `>=0.8.0, <0.9.0` |
| `cratefield-module-guardrails` | 0.1.0 | 1 | `^0.8` — `>=0.8.0, <0.9.0` |
| `cratefield-module-hello` *(not published)* | 0.1.1 | 1 | `^0.8` — `>=0.8.0, <0.9.0` |
| `cratefield-module-notifications` | 0.3.1 | 1 | `^0.8` — `>=0.8.0, <0.9.0` |
| `cratefield-module-orgs` | 0.1.1 | 1 | `^0.8` — `>=0.8.0, <0.9.0` |
| `cratefield-module-owlpost` | 0.1.0 | 1 | `^0.8` — `>=0.8.0, <0.9.0` |
| `cratefield-module-privacy` | 0.3.1 | 1 | `^0.8` — `>=0.8.0, <0.9.0` |
| `cratefield-module-telegram` | 0.1.0 | 1 | `^0.8` — `>=0.8.0, <0.9.0` |
| `cratefield-module-telemetry` | 0.3.0 | 1 | `^0.8` — `>=0.8.0, <0.9.0` |
| `cratefield-module-waitlist` | 0.4.2 | 1 | `^0.8` — `>=0.8.0, <0.9.0` |
| `cratefield-module-wallets` | 0.1.0 | 1 | `^0.8` — `>=0.8.0, <0.9.0` |
| `cratefield-module-webhooks` | 0.4.0 | 1 | `^0.8` — `>=0.8.0, <0.9.0` |
| `cratefield-oauth-client` | 0.3.0 | 1 | `^0.8` — `>=0.8.0, <0.9.0` |
| `cratefield-provisioning` *(not published)* | 0.1.1 | 1 | `^0.8` — `>=0.8.0, <0.9.0` |
| `cratefield-push-auth` | 0.3.0 | 1 | `^0.8` — `>=0.8.0, <0.9.0` |
| `cratefield-push-wiring` | 0.3.0 | 1 | `^0.8` — `>=0.8.0, <0.9.0` |
| `cratefield-runtime-browser` *(not published)* | 0.1.1 | 1 | `^0.8` — `>=0.8.0, <0.9.0` |
| `cratefield-runtime-browser-demo` *(not published)* | 0.1.1 | 1 | `^0.8` — `>=0.8.0, <0.9.0` |
| `cratefield-runtime-cloudflare` | 0.4.2 | 1 | `^0.8` — `>=0.8.0, <0.9.0` |
| `cratefield-runtime-native` | 0.4.2 | 1 | `^0.8` — `>=0.8.0, <0.9.0` |
| `cratefield-secrets` | 0.4.0 | 1 | `^0.8` — `>=0.8.0, <0.9.0` |
| `cratefield-session-grants` *(not published)* | 0.1.0 | 1 | `^0.8` — `>=0.8.0, <0.9.0` |
| `cratefield-tables` | 0.4.0 | 1 | `^0.8` — `>=0.8.0, <0.9.0` |
| `cratefield-tables-api` | 0.1.0 | 1 | `^0.8` — `>=0.8.0, <0.9.0` |
| `cratefield-testing` | 0.5.1 | 1 | `^0.8` — `>=0.8.0, <0.9.0` |
| `cratefield-ui` | 0.4.0 | 1 | `^0.8` — `>=0.8.0, <0.9.0` |
| `cratefield-ui-generator` *(not published)* | 0.1.1 | 1 | `^0.8` — `>=0.8.0, <0.9.0` |
| `cratefield-waitlist` *(not published)* | 0.1.1 | 1 | `^0.8` — `>=0.8.0, <0.9.0` |
| `d1-blob-canary` *(not published)* | 0.1.0 | 1 | `^0.8` — `>=0.8.0, <0.9.0` |
| `fz-module-linkedin` *(not published)* | 0.1.1 | 1 | `^0.8` — `>=0.8.0, <0.9.0` |
| `sidecar-module-template` *(not published)* | 0.1.1 | 1 | `^0.8` — `>=0.8.0, <0.9.0` |
| `sidecar-slow-events` *(not published)* | 0.1.1 | 1 | `^0.8` — `>=0.8.0, <0.9.0` |
| `venture-native` *(not published)* | 0.1.1 | 1 | `^0.8` — `>=0.8.0, <0.9.0` |

A module row means: that module version was built and conformance-tested
against every `cratefield-core` its range accepts at the time of release
(the caret keeps it to one pre-1.0 minor). The conformance suite runs
per module crate via `.github/workflows/conformance.yml`, which is also
exported as a reusable workflow for modules built out of tree.
