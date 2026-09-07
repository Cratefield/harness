<p align="center">
  <img src="assets/readme-banner.png" alt="Cratefield Harness. The open-source core. Modules are crates, compiled into one stateless Worker with its own database." width="100%">
</p>

<p align="center">
  <img src="https://img.shields.io/badge/STATUS-M2%20IN%20PROGRESS-4C6FFF?style=flat-square&labelColor=0A0A0B" alt="Status: M2 in progress">
  <img src="https://img.shields.io/badge/LANGUAGE-RUST-EDEBE6?style=flat-square&labelColor=0A0A0B" alt="Language: Rust">
  <img src="https://img.shields.io/badge/TARGET-WASM32%20%C2%B7%20WORKERS-EDEBE6?style=flat-square&labelColor=0A0A0B" alt="Target: wasm32 on Cloudflare Workers">
  <img src="https://img.shields.io/badge/ROUTER-AXUM-EDEBE6?style=flat-square&labelColor=0A0A0B" alt="Router: axum">
  <img src="https://img.shields.io/badge/DATABASE-D1%20NOW%20%C2%B7%20POSTGRES%20LATER-EDEBE6?style=flat-square&labelColor=0A0A0B" alt="Database: D1 now, Postgres later">
  <img src="https://img.shields.io/badge/LICENSE-MIT-4C6FFF?style=flat-square&labelColor=0A0A0B" alt="License: MIT">
</p>

<p align="center">
  <a href="https://github.com/Cratefield/harness/actions/workflows/parity.yml">
    <img src="https://github.com/Cratefield/harness/actions/workflows/parity.yml/badge.svg" alt="parity: module suites on SQLite and Postgres (matrix)">
  </a>
</p>

<p align="center">
  <b>cratefield.com</b> · HARNESS · the open-source core
</p>

---

# The harness

Every product needs a backend, and almost none of them should be built from
scratch. This is that backend, once.

A **Rust** harness you compile your own backend from: pick module crates, wire
adapters, ship **one stateless Worker with its own database**. Cloudflare D1
today, a self-hosted native binary later, with no module rewrites in between.

This repository is the open-source core, MIT, and it is complete enough to run
yourself today. [Cratefield](https://cratefield.com) is the managed service
being built on top of it: builds, migrations, secrets, domains and monitoring,
so you do not have to operate any of it. That service is not built yet, and the
site says so on every page.

> **Modules only see ports.**
> A module never touches a Cloudflare binding, an environment variable, or a
> vendor client. It asks for a `Database`, a `Mailer`, a `Captcha`. Adapters
> answer. That one rule is what makes the later move off Cloudflare a change of
> a single runtime crate.

Read [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for the full design.
Decisions, including why the TypeScript attempt was thrown away, are in
[docs/adr](docs/adr). Security controls and reporting:
[docs/SECURITY.md](docs/SECURITY.md). What we store and for how long:
[docs/PRIVACY.md](docs/PRIVACY.md). Which module version runs on which
core: [docs/COMPATIBILITY.md](docs/COMPATIBILITY.md), generated and
drift-checked in CI. How crates reach crates.io:
[docs/RELEASING.md](docs/RELEASING.md).

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
%%{init: {"theme":"base","themeVariables":{
  "background":"transparent",
  "fontFamily":"ui-monospace, SFMono-Regular, Menlo, monospace",
  "fontSize":"13px",
  "primaryColor":"#141416","primaryTextColor":"#EDEBE6","primaryBorderColor":"#3A3A3F",
  "lineColor":"#6E6E76","textColor":"#8A8A8E",
  "clusterBkg":"transparent","clusterBorder":"#3A3A3F",
  "edgeLabelBackground":"#0E0E10"
}} }%%
flowchart LR
  REQ(["HTTPS<br/>request"]):::req --> H

  subgraph V["ONE VENTURE · ONE BINARY · ONE DATABASE"]
    H["<b>Harness</b><br/>axum router<br/>/v1/&lt;module&gt;"]:::core
    M1["email-signup"]:::mod
    M2["waitlist"]:::mod
    MX["your module"]:::ghost
    P{{"<b>ports</b><br/>Database · Mailer<br/>Captcha · RateLimiter<br/>Signer · KeyValue"}}:::port
    H --> M1 & M2 & MX --> P
  end

  subgraph A["ADAPTERS · THE ONLY VENDOR-AWARE CODE"]
    DB[("D1")]:::vendor
    KV[("KV")]:::vendor
    RS["Resend"]:::vendor
    TS["Turnstile"]:::vendor
    PG[("Postgres<br/>phase 3")]:::future
  end

  P --> DB & KV & RS & TS
  P -. "runtime-native" .-> PG

  classDef req fill:#0E0E10,stroke:#4C6FFF,stroke-width:1.5px,color:#EDEBE6
  classDef core fill:#141416,stroke:#4C6FFF,stroke-width:1.5px,color:#EDEBE6
  classDef mod fill:#0E0E10,stroke:#3A3A3F,color:#EDEBE6
  classDef ghost fill:transparent,stroke:#55555A,stroke-dasharray:4 3,color:#8A8A8E
  classDef port fill:#141416,stroke:#EDEBE6,stroke-width:1.5px,color:#EDEBE6
  classDef vendor fill:#0E0E10,stroke:#3A3A3F,color:#A9A8A5
  classDef future fill:transparent,stroke:#55555A,stroke-dasharray:4 3,color:#8A8A8E
```

## Crates

All public crates are `factory0-*`, MIT. Nothing is published to crates.io yet;
depend on this repository by git.

> The `factory0-` prefix predates the move of this repository into the
> Cratefield organisation. Renaming published crate names is a breaking change
> for every consumer, so the prefix stays until there is a release worth
> breaking. It is a package namespace, not a statement about who maintains this.

| Crate | Role |
|---|---|
| `factory0-core` | `Module` trait, `Harness` builder, port traits, problem+json errors, request scope, event bus, templates |
| `factory0-runtime-cloudflare` | workers-rs entry points; D1, KV, Rate Limiting and `wait_until` mapped to ports |
| `factory0-adapter-resend` | `Mailer` over the Resend REST API, with a `NotConfigured` mode until a sending domain is verified |
| `factory0-adapter-turnstile` | `Captcha` over Cloudflare Turnstile, fail-closed |
| `factory0-adapter-sqlite` | `Database` over rusqlite: every test, and single-node self-hosting |
| `factory0-module-email-signup` | Email signup with double opt-in, unsubscribe, admin export |
| `factory0-module-waitlist` | Per-product waitlist with confirm, position, referral codes |
| `factory0-ui` | Renders the module surface as HTML at `/ui`: pages, fragments, in-process form dispatch, the `cf-*` styling contract (ADR 0010) |
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

A module is mounted one of two ways, and a caller cannot tell which. **Compiled
in** is the default this README describes: the crate is linked into the Worker.
**Sidecar** gives one module its own Worker, built and deployed separately and
mounted at the same `/v1/<name>` over a Cloudflare service binding, binding the
same database and secrets. It exists so a module whose source should not enter
the shared artifact can still run as a real module with real ports. Designed,
not built: [epic #56](../../issues/56).

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

Three epics sit outside the milestones because they are specified but not
scheduled: [#23](../../issues/23) multi-tenant schema, [#24](../../issues/24)
embedded secrets, and [#56](../../issues/56) custom modules without rebuilding
the shared bundle.

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
  ui/                      factory0-ui
  cli/                     factory0-cli  →  fz
  testing/                 factory0-testing
examples/
  venture/                 smallest complete venture; CI builds it to wasm
docs/
  ARCHITECTURE.md
  MIGRATION-STREAMS.md     two repositories applying migrations to one database
  MOUNTING.md              compile a module in, or run it as a sidecar
  UI.md                    the UI surface, its markup contract, UiSpec, admin
  ui-llms.txt              the same contract written for a generator
  adr/                     0000 … 0010
tools/
  banner-render.html       source of the README banner
  render-banner.sh         regenerates it with headless Chrome
```

## License

MIT. Built in the open for [Cratefield](https://cratefield.com), a
[Factory Zero](https://factory0.ventures) venture.
