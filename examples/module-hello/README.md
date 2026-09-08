# cratefield-module-hello

The example Factory Zero module, built step by step by
[docs/MODULE-AUTHORING.md](../../docs/MODULE-AUTHORING.md): one table
(`hello_visits`), one public write (`POST /v1/hello`), one public read
(`GET /v1/hello/count`), one event (`hello.recorded`). The smallest module
that still exercises every rule a real module must obey.

```rust
use cratefield_module_hello::Hello;

let module = Hello::new().max_name_len(64);
```

- `requires()` the `Database` port, `optional()` the `IdGen` port, and
  nothing else — modules see ports, never bindings (ADR 0002).
- `public_writes()` is `true`: a venture that mounts it in production must
  configure the `Captcha` port or `fz doctor` fails the build.
- Migrations in the portable SQL subset, queries via sea-query,
  `#![forbid(unsafe_code)]`, no `worker`/`tokio`/`std::fs`/`std::net`.
- Passes the `cratefield-testing` conformance suite.

This crate is an example (`publish = false`); real modules live in
`crates/module-*` here; private ones are `fz-*` crates in the same directory, kept off crates.io with `publish = false` (ADR 0013).
