# Contributing to the Factory Zero harness

Read [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) first — the design is
decided and recorded in [`docs/adr`](docs/adr). If you disagree with a
decision, open an issue; do not silently deviate. Writing or changing a
module? [`docs/MODULE-AUTHORING.md`](docs/MODULE-AUTHORING.md) is the
guide and `examples/module-hello` is the worked example; taking a venture
to production? [`docs/VENTURE-GUIDE.md`](docs/VENTURE-GUIDE.md).

## Toolchain

- Rust stable, pinned in [`rust-toolchain.toml`](rust-toolchain.toml)
  (installs automatically via rustup; add the target with
  `rustup target add wasm32-unknown-unknown` if it is missing).
- `worker-build` for the wasm build (`cargo install --locked worker-build`).
- wrangler v4+ via bun: `bunx wrangler ...`.
- `cargo-deny` for license/advisory checks.

## Before every commit

```
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cargo deny check
(cd examples/venture && worker-build --release)
```

CI runs all of the above on every PR. `cargo test --workspace` includes
every module's conformance run and the generated-doc drift checks
(ERRORS.md, COMPATIBILITY.md); if a regeneration is needed, CI's
`--check` step names the command.

Real output of the wasm build on a clean tree:

```
$ (cd examples/venture && worker-build --release)
  index.js  27.3kb

⚡ Done in 19ms
```

If your change pulls a native-only dependency into core or a module,
this is where it explodes — which is the point of the example.

## Running the wasm example locally

`examples/venture` is the smallest complete venture: core + the
Cloudflare runtime + `email-signup` + `waitlist` + a sample row module.
`cargo test` exercises the same handlers without workerd, but only
`wrangler dev` proves the binding wiring — both the wasm panic and the
D1-write hang we once shipped were invisible to `cargo test`. If you
touch the runtime, the example, or anything that only shows up under
workerd, actually run it:

```
cd examples/venture

# local D1
bunx wrangler d1 migrations apply venture-example --local
# 🚣 2 commands executed successfully.
# 0001_sample_0001_init.sql ✅ 0002_email-signup_0001_init.sql ✅ 0003_waitlist_0001_init.sql ✅

# signed-link modules need HARNESS_SECRET locally (never a real secret)
printf 'HARNESS_SECRET=%s\n' "$(openssl rand -hex 32)" > .dev.vars

# compile to wasm + serve on local workerd, then probe it
bunx wrangler dev --local --port 8792 &
sleep 40   # first compile takes a while

curl -fsS http://127.0.0.1:8792/__health   # lists every module + version
curl -fsS http://127.0.0.1:8792/__ready    # {"ok":true} — SELECT 1 through D1
```

`.dev.vars` is git-ignored; `build/` and `.wrangler/` are build state —
never commit them.

## Writing a module

Follow [`docs/MODULE-AUTHORING.md`](docs/MODULE-AUTHORING.md). Short
version: one crate, one `Module` impl, ports only, sea-query queries,
`include_str!` migrations in the portable subset, conformance +
behaviour tests, `#![forbid(unsafe_code)]`. The guide's checklist is the
review checklist.

## Rules

- `crates/core` and module crates must stay wasm-safe: no `worker`,
  `wasm-bindgen`, `tokio`, `reqwest`, `sqlx`, `rusqlite`, no `std::fs` /
  `std::net` at runtime.
- `#![forbid(unsafe_code)]` everywhere except `cratefield-runtime-cloudflare`
  (ADR 0002).
- No `thread_local!`, no `static mut`, no ambient request state (ADR 0007).
- Never commit real secrets; test fixtures use obvious dummies.
- One commit per issue, conventional-commit format, issue number last:
  `feat(core): Module trait and Harness builder (#2)`.
- Architecture decisions change via a new ADR, never by editing existing
  ones; `docs/ARCHITECTURE.md` and `docs/adr/` are append-mostly.

## PR checklist

- [ ] conventional-commit subject with the issue number last
- [ ] `cargo fmt --all --check` clean
- [ ] `cargo clippy --workspace --all-targets -- -D warnings` clean
- [ ] `cargo test --workspace` green; new behaviour comes with tests,
      bug fixes with the test that failed first
- [ ] no wasm-incompatible dependencies (see Rules);
      `worker-build --release` on `examples/venture` still passes
- [ ] venture/runtime/example changes: `wrangler dev` was actually run
      and the endpoints answer
- [ ] module changes: conformance passes and `fz doctor`'s rules hold
      (portable SQL, honest `public_writes()`)
- [ ] no secrets, tokens or real addresses anywhere, including pasted
      output and examples

## Releases

Maintainers: [`docs/RELEASING.md`](docs/RELEASING.md) (release-plz PR,
trusted publishing to crates.io, tagging). Contributors need do nothing
— conventional commits do the work.
