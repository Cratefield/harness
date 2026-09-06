# Compatibility

Generated from the workspace manifests by `cargo run -p factory0-cli --example
compatibility-doc` and checked in CI for drift. Do not edit by hand.

## The contract version

- `HARNESS_API` is 1. Every module and adapter is compiled
  against a `factory0-core` whose `HARNESS_API` matches; `Harness::build`
  and `fz doctor` refuse a mismatch, naming the module, its version and
  the core crate.
- **The 1.0 rule:** `HARNESS_API` is bumped only for breaking changes to
  the module contract (the `Module` trait, `ModuleContext`, ports).
  `factory0-core`'s major version follows `HARNESS_API`: a core 2.x is
  the first that accepts API 2, a core 1.x never does. Anything else —
  new optional trait methods, new ports, new error slugs — ships in a
  minor bump with the API unchanged.
- **Dependency ranges:** while pre-1.0, modules and adapters depend on
  `factory0-core` with a caret on the current minor (`"0.1"` accepts
  0.1.x only), so a new core minor can never silently mix with older
  modules. From 1.0 the range is `"^1"`-style: compatible within the
  major. Ventures pin exact versions; the supported range per release
  is the table below.

## Supported core ranges

| Crate | Version | HARNESS_API | `factory0-core` range |
|---|---|---|---|
| `factory0-adapter-postgres` | 0.1.0 | 1 | `^0.3` — `>=0.3.0, <0.4.0` |
| `factory0-adapter-resend` | 0.1.0 | 1 | `^0.3` — `>=0.3.0, <0.4.0` |
| `factory0-adapter-sqlite` | 0.1.0 | 1 | `^0.3` — `>=0.3.0, <0.4.0` |
| `factory0-adapter-turnstile` | 0.1.0 | 1 | `^0.3` — `>=0.3.0, <0.4.0` |
| `factory0-cli` | 0.1.0 | 1 | `^0.3` — `>=0.3.0, <0.4.0` |
| `factory0-module-email-signup` | 0.1.0 | 1 | `^0.3` — `>=0.3.0, <0.4.0` |
| `factory0-module-hello` | 0.1.0 | 1 | `^0.3` — `>=0.3.0, <0.4.0` |
| `factory0-module-waitlist` | 0.1.0 | 1 | `^0.3` — `>=0.3.0, <0.4.0` |
| `factory0-runtime-cloudflare` | 0.1.0 | 1 | `^0.3` — `>=0.3.0, <0.4.0` |
| `factory0-runtime-native` | 0.1.0 | 1 | `^0.3` — `>=0.3.0, <0.4.0` |
| `factory0-testing` | 0.1.0 | 1 | `^0.3` — `>=0.3.0, <0.4.0` |
| `venture` | 0.1.0 | 1 | `^0.3` — `>=0.3.0, <0.4.0` |
| `venture-native` | 0.1.0 | 1 | `^0.3` — `>=0.3.0, <0.4.0` |

A module row means: that module version was built and conformance-tested
against every `factory0-core` its range accepts at the time of release
(the caret keeps it to one pre-1.0 minor). The conformance suite runs
per module crate via `.github/workflows/conformance.yml`, which is also
exported as a reusable workflow for `harness-private`.
