# factory0-cli-acceptance

Acceptance tests for the `fz` CLI (`factory0-cli`): a fixture venture
(`fixture/`, a standalone crate with two modules), then real `fz`
subprocess runs against it — `migrations collect` (file names +
`.harness-lock.json` pinning, content-hash edit detection), `doctor`
(portable-SQL, captcha-in-production, contract checks) and `modules`.

A separate workspace crate rather than dev-dependencies of
`factory0-cli`, because `cargo publish` resolves dev-dependencies
against crates.io — a published `factory0-cli` could never verify
against an unpublished fixture (issue #15). `publish = false`, no
library target, so unlike the published crates it carries no rustdoc
README include.
