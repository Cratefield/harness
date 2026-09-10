<p align="center">
  <a href="https://github.com/Cratefield/harness">
    <img src="https://raw.githubusercontent.com/Cratefield/harness/main/assets/readme-banner.png" alt="Cratefield Harness. The open-source core. Modules are crates, compiled into one stateless Worker with its own database." width="100%">
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
feature, and each feature names exactly one crate:

| Feature | Crate | Reached as | What it is |
|---|---|---|---|
| `cloudflare` | `cratefield-runtime-cloudflare` | `cratefield::cloudflare` | Workers entry points; D1, KV and rate limiting as ports |
| `native` | `cratefield-runtime-native` | `cratefield::native` | The same harness as one tokio binary |
| `sqlite` | `cratefield-adapter-sqlite` | `cratefield::sqlite` | `Database` over rusqlite |
| `postgres` | `cratefield-adapter-postgres` | `cratefield::postgres` | `Database` over sqlx |
| `resend` | `cratefield-adapter-resend` | `cratefield::resend` | `Mailer` over the Resend API |
| `turnstile` | `cratefield-adapter-turnstile` | `cratefield::turnstile` | `Captcha` over Cloudflare Turnstile |
| `stripe` | `cratefield-adapter-stripe` | `cratefield::stripe` | `Payments` over the Stripe API |
| `apns` | `cratefield-adapter-apns` | `cratefield::apns` | `Push` over Apple Push Notification service |
| `webpush` | `cratefield-adapter-webpush` | `cratefield::webpush` | `Push` over Web Push (RFC 8030), browsers and UnifiedPush |
| `push-auth` | `cratefield-push-auth` | `cratefield::push_auth` | Provider-JWT signing for the push adapters (ES256 for APNs and VAPID, RS256 for Google service accounts) with a keyed token cache. Pulled in by `apns` and `webpush` already; a feature of its own for using it directly |
| `ui` | `cratefield-ui` | `cratefield::ui` | Renders the module surface as HTML |
| `secrets` | `cratefield-secrets` | `cratefield::secrets` | Envelope-encrypted secrets |
| `kms` | `cratefield-kms` | `cratefield::kms` | The KMS port and its local-file provider |
| `email-signup` | `cratefield-module-email-signup` | `cratefield::email_signup` | Double opt-in email signup |
| `waitlist` | `cratefield-module-waitlist` | `cratefield::waitlist` | Per-product waitlist |
| `cms` | `cratefield-module-cms` | `cratefield::cms` | Small content store |
| `testing` | `cratefield-testing` | `cratefield::testing` | The conformance kit; belongs under `[dev-dependencies]` |

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
