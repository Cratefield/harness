<p align="center">
  <img src="assets/readme-banner.png" alt="Factory Zero Harness. One Rust harness. Every venture compiles its own backend." width="100%">
</p>

<p align="center">
  <img src="https://img.shields.io/badge/STATUS-M0%20IN%20PROGRESS-FF5A36?style=flat-square&labelColor=0A0A0B" alt="Status: M0 in progress">
  <img src="https://img.shields.io/badge/LANGUAGE-RUST-EDEBE6?style=flat-square&labelColor=0A0A0B" alt="Language: Rust">
  <img src="https://img.shields.io/badge/TARGET-WASM32%20%C2%B7%20WORKERS-EDEBE6?style=flat-square&labelColor=0A0A0B" alt="Target: wasm32 on Cloudflare Workers">
  <img src="https://img.shields.io/badge/ROUTER-AXUM-EDEBE6?style=flat-square&labelColor=0A0A0B" alt="Router: axum">
  <img src="https://img.shields.io/badge/DATABASE-D1%20NOW%20%C2%B7%20POSTGRES%20LATER-EDEBE6?style=flat-square&labelColor=0A0A0B" alt="Database: D1 now, Postgres later">
  <img src="https://img.shields.io/badge/LICENSE-MIT-FF5A36?style=flat-square&labelColor=0A0A0B" alt="License: MIT">
</p>

<p align="center">
  <b>factory0.ventures</b> · HARNESS · <code>factory0-*</code> on crates.io
</p>

---

# The harness

Factory Zero builds companies that operate and grow themselves. Each of those
companies needs a backend, and none of them should build one from scratch.

This is that backend, once. A **Rust** harness that every venture compiles its
own backend from: pick module crates, wire adapters, ship **one stateless
Cloudflare Worker**. Cloudflare D1 today, a self-hosted native binary later,
with no module rewrites in between.

> **Modules only see ports.**
> A module never touches a Cloudflare binding, an environment variable, or a
> vendor client. It asks for a `Database`, a `Mailer`, a `Captcha`. Adapters
> answer. That one rule is what makes the later move off Cloudflare a change of
> a single runtime crate.

Read [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for the full design.
Decisions, including why the TypeScript attempt was thrown away, are in
[docs/adr](docs/adr). Security controls and reporting:
[docs/SECURITY.md](docs/SECURITY.md). What we store and for how long:
[docs/PRIVACY.md](docs/PRIVACY.md).

## How a venture uses it

```rust
// src/harness.rs in a venture repo
Harness::builder()
    .venture(Venture::new("factory0", "factory0.ventures")
        .public_url("https://factory0.ventures")
        .cors_origins(["https://factory0.ventures"]))
    .module(EmailSignup::new().double_opt_in(true))
    .module(Waitlist::new().products(["kontinuum", "undercover-rockstars"]))
    .runtime(Cloudflare::new()
        .db("DB")
        .mailer(Resend::from_env())
        .captcha(Turnstile::from_env()))
    .build()?
```

That is the whole composition. `build()` refuses a module that requires a port
the runtime does not provide, two modules claiming the same table or route, or
a module built against a different contract version. The venture template runs
it under `cargo test`, so a misconfiguration fails before `wrangler deploy` can.

## Shape

```mermaid
flowchart LR
  subgraph venture["one venture · one Worker · one database"]
    H["Harness<br/>axum router · /v1/&lt;module&gt;"]
    M1["module<br/>email-signup"]
    M2["module<br/>waitlist"]
    P["ports<br/>Database · Mailer · Captcha<br/>RateLimiter · Signer · KeyValue"]
    H --> M1 & M2 --> P
  end
  subgraph cf["runtime-cloudflare"]
    D1[(D1)]
    KV[(KV)]
    RL[Rate Limiting]
  end
  subgraph vendors["adapters"]
    RS[Resend]
    TS[Turnstile]
  end
  P --> D1 & KV & RL & RS & TS
  P -. "phase 3: runtime-native" .-> PG[(Postgres)]
```

## Crates

All public crates are `factory0-*`, MIT, published to crates.io.

| Crate | Role |
|---|---|
| `factory0-core` | `Module` trait, `Harness` builder, port traits, problem+json errors, request scope, event bus, templates |
| `factory0-runtime-cloudflare` | workers-rs entry points; D1, KV, Rate Limiting and `wait_until` mapped to ports |
| `factory0-adapter-resend` | `Mailer` over the Resend REST API, with a `NotConfigured` mode until a sending domain is verified |
| `factory0-adapter-turnstile` | `Captcha` over Cloudflare Turnstile, fail-closed |
| `factory0-adapter-sqlite` | `Database` over rusqlite: every test, and single-node self-hosting |
| `factory0-module-email-signup` | Email signup with double opt-in, unsubscribe, admin export |
| `factory0-module-waitlist` | Per-product waitlist with confirm, position, referral codes |
| `factory0-cli` | Binary `fz`: `migrations collect`, `doctor`, `modules` |
| `factory0-testing` | Conformance kit every module, public or private, must pass |
| `factory0-adapter-postgres` | Phase 3. `Database` over sqlx for the native runtime |
| `factory0-runtime-native` | Phase 3. The same harness as a single binary on tokio |

Private modules are `fz-*` crates in
[harness-private](https://github.com/Factory-Zero/harness-private), consumed as
pinned git dependencies. New ventures start from
[venture-backend-template](https://github.com/Factory-Zero/venture-backend-template).
The first consumer is
[factory0-backend](https://github.com/Factory-Zero/factory0-backend).

## What a module is

A crate implementing one trait.

```rust
pub trait Module: Send + Sync + 'static {
    fn name(&self) -> &'static str;              // mounted at /v1/<name>
    fn requires(&self) -> &'static [Port];       // build fails if one is missing
    fn migrations(&self) -> Migrations;          // include_str! SQL, portable subset
    fn router(&self, ctx: ModuleContext) -> axum::Router;
    // version, optional ports, tables, events, scheduled …
}
```

Migrations are plain SQL in a subset SQLite and Postgres both accept. Queries go
through sea-query, which renders for either. Confirmation and unsubscribe
links are HMAC-signed tokens with key rotation, so there is no session store.
Request scope travels in axum extensions, never in shared state; the
conformance kit includes the concurrent-request test that proves it.

## Roadmap

| Milestone | Contents | Issues |
|---|---|---|
| **M0 Foundation** | workspace tooling, `core`, Cloudflare runtime, Resend and Turnstile adapters, SQLite adapter, `fz`, testing kit | #1–#9 |
| **M1 First modules** | `email-signup`, `waitlist`, templates, security baseline, observability | #10–#14 |
| **M2 First venture live** | crates.io publishing, docs, contract versioning, `api.factory0.ventures` | #15–#17 |
| **M3 Self-hosted portability** | Postgres adapter, native runtime, parity suite, data move | #18–#21 |

Progress is visible in the [milestones](../../milestones).

## Observability

One structured span per request carries `request_id`, `method`, `route`
(the matched path), `module`, `status`, `duration_ms`, `ip_hash` and
`ua_family` — never an email address. Workers Logs is enabled in the
template `wrangler.toml` (`[observability] enabled = true`); every
response also echoes `x-request-id`. To pull one request's trail out of
the logs, filter on the id the API returned:

```sh
wrangler tail --format pretty --search <request-id>
```

The error taxonomy (every problem slug, status and meaning) is
`docs/ERRORS.md`, generated from `factory0-core`'s registry and checked
in CI for drift.

## Toolchain

Stable Rust pinned in `rust-toolchain.toml`, target `wasm32-unknown-unknown`,
[`worker-build`](https://crates.io/crates/worker-build), wrangler. CI runs
`fmt`, `clippy -D warnings`, `test`, `cargo deny`, and builds the example
venture to wasm so a native-only dependency cannot slip into a module.

```
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
(cd examples/venture && worker-build --release)
```

## Layout

```
crates/
  core/                    factory0-core
  runtime-cloudflare/      factory0-runtime-cloudflare
  adapter-resend/          factory0-adapter-resend
  adapter-turnstile/       factory0-adapter-turnstile
  adapter-sqlite/          factory0-adapter-sqlite
  module-email-signup/     factory0-module-email-signup
  module-waitlist/         factory0-module-waitlist
  cli/                     factory0-cli  →  fz
  testing/                 factory0-testing
examples/
  venture/                 smallest complete venture; CI builds it to wasm
docs/
  ARCHITECTURE.md
  adr/                     0000 … 0008
tools/
  banner-render.html       source of the README banner
  render-banner.sh         regenerates it with headless Chrome
```

## License

MIT. Built in the open by [Factory Zero](https://factory0.ventures).
