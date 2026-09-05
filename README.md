# Factory Zero harness

A modular, open-source backend harness in **Rust**. Every Factory Zero venture
compiles its own backend from it: pick module crates, wire adapters, ship
**one stateless Cloudflare Worker** (Rust on wasm via workers-rs). Cloudflare
D1 today, a self-hosted native binary later, with no module rewrites in
between.

Read [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) first. Decisions live in
[docs/adr](docs/adr); ADR 0000 explains why the TypeScript attempt was
discarded.

## Crates (`factory0-*`, crates.io, MIT)

| Crate | Role |
|---|---|
| `factory0-core` | `Module` trait, `Harness` builder, port traits, errors, request scope |
| `factory0-runtime-cloudflare` | workers-rs entry points; maps bindings to ports |
| `factory0-adapter-resend` | `Mailer` over Resend |
| `factory0-adapter-turnstile` | `Captcha` over Turnstile |
| `factory0-adapter-sqlite` | `Database` over rusqlite, for tests and single-node hosting |
| `factory0-module-email-signup` | Email signup with double opt-in |
| `factory0-module-waitlist` | Per-product waitlist with referral codes |
| `factory0-cli` | Binary `fz`: `migrations collect`, `doctor`, `modules` |
| `factory0-testing` | Conformance kit every module runs against |

Private modules live in `Factory-Zero/harness-private` as `fz-*` git
dependencies. New ventures start from `Factory-Zero/venture-backend-template`.

## Status

Design v2 adopted 2026-09-05. Implementation tracked in the issues and
milestones of this repo:

- **M0 Foundation**: workspace tooling, `core`, `runtime-cloudflare`, adapters, CLI, testing kit
- **M1 First modules**: `module-email-signup`, `module-waitlist`
- **M2 First venture live**: publish to crates.io, template, `api.factory0.ventures`
- **M3 Self-hosted portability**: `adapter-postgres`, `runtime-native`, parity suite

## Layout (target)

```
crates/
  core/
  runtime-cloudflare/
  adapter-resend/
  adapter-turnstile/
  adapter-sqlite/
  module-email-signup/
  module-waitlist/
  cli/
  testing/
examples/
  venture/            # smallest complete venture; CI builds it to wasm
docs/
  ARCHITECTURE.md
  adr/
```

Toolchain: stable Rust (pinned in `rust-toolchain.toml`), target
`wasm32-unknown-unknown`, `worker-build`, wrangler.

## License

MIT.
