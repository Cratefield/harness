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

## Supported core ranges

| Crate | Version | HARNESS_API | `cratefield-core` range |
|---|---|---|---|
| `cratefield` | 0.1.1 | 1 | `^0.4` — `>=0.4.0, <0.5.0` |
| `cratefield-access` | 0.1.1 | 1 | `^0.4` — `>=0.4.0, <0.5.0` |
| `cratefield-accounts` | 0.1.1 | 1 | `^0.4` — `>=0.4.0, <0.5.0` |
| `cratefield-adapter-apns` | 0.1.2 | 1 | `^0.4` — `>=0.4.0, <0.5.0` |
| `cratefield-adapter-fcm` | 0.1.1 | 1 | `^0.4` — `>=0.4.0, <0.5.0` |
| `cratefield-adapter-postgres` | 0.1.1 | 1 | `^0.4` — `>=0.4.0, <0.5.0` |
| `cratefield-adapter-resend` | 0.1.1 | 1 | `^0.4` — `>=0.4.0, <0.5.0` |
| `cratefield-adapter-sqlite` | 0.1.1 | 1 | `^0.4` — `>=0.4.0, <0.5.0` |
| `cratefield-adapter-sqlite-wasm` | 0.1.1 | 1 | `^0.4` — `>=0.4.0, <0.5.0` |
| `cratefield-adapter-stripe` | 0.1.1 | 1 | `^0.4` — `>=0.4.0, <0.5.0` |
| `cratefield-adapter-turnstile` | 0.1.1 | 1 | `^0.4` — `>=0.4.0, <0.5.0` |
| `cratefield-adapter-webpush` | 0.1.1 | 1 | `^0.4` — `>=0.4.0, <0.5.0` |
| `cratefield-chrome` | 0.1.1 | 1 | `^0.4` — `>=0.4.0, <0.5.0` |
| `cratefield-cli` | 0.1.1 | 1 | `^0.4` — `>=0.4.0, <0.5.0` |
| `cratefield-connections` | 0.1.1 | 1 | `^0.4` — `>=0.4.0, <0.5.0` |
| `cratefield-console` | 0.1.1 | 1 | `^0.4` — `>=0.4.0, <0.5.0` |
| `cratefield-control-plane` | 0.1.1 | 1 | `^0.4` — `>=0.4.0, <0.5.0` |
| `cratefield-dashboard` | 0.1.1 | 1 | `^0.4` — `>=0.4.0, <0.5.0` |
| `cratefield-introspect` | 0.1.1 | 1 | `^0.4` — `>=0.4.0, <0.5.0` |
| `cratefield-module-cms` | 0.1.1 | 1 | `^0.4` — `>=0.4.0, <0.5.0` |
| `cratefield-module-email-signup` | 0.1.1 | 1 | `^0.4` — `>=0.4.0, <0.5.0` |
| `cratefield-module-hello` | 0.1.1 | 1 | `^0.4` — `>=0.4.0, <0.5.0` |
| `cratefield-module-notifications` | 0.1.1 | 1 | `^0.4` — `>=0.4.0, <0.5.0` |
| `cratefield-module-privacy` | 0.1.1 | 1 | `^0.4` — `>=0.4.0, <0.5.0` |
| `cratefield-module-waitlist` | 0.1.1 | 1 | `^0.4` — `>=0.4.0, <0.5.0` |
| `cratefield-provisioning` | 0.1.1 | 1 | `^0.4` — `>=0.4.0, <0.5.0` |
| `cratefield-push-auth` | 0.1.2 | 1 | `^0.4` — `>=0.4.0, <0.5.0` |
| `cratefield-push-wiring` | 0.1.1 | 1 | `^0.4` — `>=0.4.0, <0.5.0` |
| `cratefield-runtime-browser` | 0.1.1 | 1 | `^0.4` — `>=0.4.0, <0.5.0` |
| `cratefield-runtime-browser-demo` | 0.1.1 | 1 | `^0.4` — `>=0.4.0, <0.5.0` |
| `cratefield-runtime-cloudflare` | 0.1.1 | 1 | `^0.4` — `>=0.4.0, <0.5.0` |
| `cratefield-runtime-native` | 0.1.1 | 1 | `^0.4` — `>=0.4.0, <0.5.0` |
| `cratefield-secrets` | 0.1.1 | 1 | `^0.4` — `>=0.4.0, <0.5.0` |
| `cratefield-tables` | 0.1.1 | 1 | `^0.4` — `>=0.4.0, <0.5.0` |
| `cratefield-testing` | 0.1.1 | 1 | `^0.4` — `>=0.4.0, <0.5.0` |
| `cratefield-ui` | 0.1.1 | 1 | `^0.4` — `>=0.4.0, <0.5.0` |
| `cratefield-ui-generator` | 0.1.1 | 1 | `^0.4` — `>=0.4.0, <0.5.0` |
| `cratefield-waitlist` | 0.1.1 | 1 | `^0.4` — `>=0.4.0, <0.5.0` |
| `factory0-auth-client` | 0.1.1 | 1 | `^0.4` — `>=0.4.0, <0.5.0` |
| `factory0-auth-core` | 0.1.1 | 1 | `^0.4` — `>=0.4.0, <0.5.0` |
| `factory0-auth-magic-link` | 0.1.1 | 1 | `^0.4` — `>=0.4.0, <0.5.0` |
| `factory0-auth-meta` | 0.1.1 | 1 | `^0.4` — `>=0.4.0, <0.5.0` |
| `factory0-auth-oidc` | 0.1.1 | 1 | `^0.4` — `>=0.4.0, <0.5.0` |
| `factory0-auth-passkeys` | 0.1.1 | 1 | `^0.4` — `>=0.4.0, <0.5.0` |
| `factory0-auth-password` | 0.1.1 | 1 | `^0.4` — `>=0.4.0, <0.5.0` |
| `factory0-auth-worker` | 0.1.1 | 1 | `^0.4` — `>=0.4.0, <0.5.0` |
| `fz-module-linkedin` | 0.1.1 | 1 | `^0.4` — `>=0.4.0, <0.5.0` |
| `sidecar-module-template` | 0.1.1 | 1 | `^0.4` — `>=0.4.0, <0.5.0` |
| `sidecar-slow-events` | 0.1.1 | 1 | `^0.4` — `>=0.4.0, <0.5.0` |
| `venture-native` | 0.1.1 | 1 | `^0.4` — `>=0.4.0, <0.5.0` |

A module row means: that module version was built and conformance-tested
against every `cratefield-core` its range accepts at the time of release
(the caret keeps it to one pre-1.0 minor). The conformance suite runs
per module crate via `.github/workflows/conformance.yml`, which is also
exported as a reusable workflow for modules built out of tree.
